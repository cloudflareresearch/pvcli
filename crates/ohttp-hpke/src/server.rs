// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use crate::config::{AeadId, AeadImpl, KdfId, KdfImpl, KemId, KeyConfig};
use crate::decapsulated::{Decapsulated, OpenInPlace};
use crate::encapsulated::Encapsulated;
use crate::header::EncapHeader;
use crate::instance::{dispatch_triple, CallTriple};
use crate::invalid_data;
use crate::keys::{EncappedKey, KeyPair, PrivateKeyBytes};
use crate::response::{AeadContext, ResponseContext, ResponseNonce, ResponseSecret};
use aead::generic_array::typenum::Unsigned;
use aead::{AeadCore, KeySizeUser};
use bytes::Bytes;
use futures::Stream;
use hpke::aead::AeadCtxR;
use hpke::kem::Kem as KemTrait;
use hpke::{setup_receiver, Deserializable, HpkeError, OpModeR, Serializable};
use octets::OctetsMut;
use rand::RngCore;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{cmp, fmt, io};
use stream_buf::StreamBuf;

#[derive(Debug, Default)]
pub struct ServerConfig {
    key_configs: Vec<KeyConfig<KeyPair>>,
}

impl ServerConfig {
    pub fn add_key_config(
        &mut self,
        key_pair: KeyPair,
        symmetric_algorithms: Vec<(KdfId, AeadId)>,
    ) -> Result<(), HpkeError> {
        // TODO(nox): Proper error.
        let key_id = u8::try_from(self.key_configs.len()).expect("too many keys");

        // TODO(nox): Proper error.
        assert!(!symmetric_algorithms.is_empty(), "no symmetric algorithms");

        // TODO(nox): Proper error.
        assert!(
            symmetric_algorithms.len() * 4 <= u16::MAX as usize,
            "too many symmetric algorithms",
        );

        let key_config = KeyConfig {
            key_id,
            key: key_pair,
            symmetric_algorithms,
        };

        // TODO(nox): Proper error.
        assert!(
            key_config.encoded_len() + 2 <= u16::MAX as usize,
            "key config too large",
        );

        self.key_configs.push(key_config);

        Ok(())
    }

    pub(crate) fn get_key_pair(&self, encap_header: &EncapHeader) -> io::Result<&KeyPair> {
        let key_config = self
            .key_configs
            .get(encap_header.key_id as usize)
            .ok_or_else(|| invalid_data(format!("unknown key id {}", encap_header.key_id)))?;

        let expected_kem_id = key_config.key.public_key.kem_id;

        if encap_header.kem_id != expected_kem_id {
            return Err(invalid_data(format!(
                "wrong kem id for key id {} (expected {:?}, got {:?})",
                encap_header.key_id, key_config.key.public_key.kem_id, encap_header.kem_id,
            )));
        }

        let header_algo = (encap_header.kdf_id, encap_header.aead_id);

        if !key_config.symmetric_algorithms.contains(&header_algo) {
            return Err(invalid_data(format!(
                "invalid algo {:?} for key id {}",
                header_algo, encap_header.key_id,
            )));
        }

        Ok(&key_config.key)
    }

    fn put(&self, octets: &mut OctetsMut<'_>) -> octets::Result<()> {
        for key_config in &self.key_configs {
            octets.put_u16(key_config.encoded_len() as u16)?;
            key_config.put(octets)?;
        }

        Ok(())
    }

    fn encoded_len(&self) -> usize {
        self.key_configs
            .iter()
            .map(|key_config| {
                // Key Config Length
                2 +
                // Key Config
                key_config.encoded_len()
            })
            .sum()
    }
}

pub fn encode_config(config: &ServerConfig) -> Vec<u8> {
    let encoded_len = config.encoded_len();
    let mut buf = vec![0; encoded_len];
    let mut octets = OctetsMut::with_slice(&mut buf);

    config.put(&mut octets).unwrap();

    debug_assert_eq!(octets.off(), encoded_len);

    buf
}

impl KeyConfig<KeyPair> {
    fn encoded_len(&self) -> usize {
        // Key Identifier
        1 +
        // KEM ID
        2 +
        // Public Key
        self.key.public_key.bytes.len() +
        // Symmetric Algorithms Length
        2 +
        // Symmetric Algorithms
        self.symmetric_algorithms.len() * 4
    }

    fn put(&self, octets: &mut OctetsMut<'_>) -> octets::Result<()> {
        octets.put_u8(self.key_id)?;
        octets.put_u16(self.key.public_key.kem_id as u16)?;
        octets.put_bytes(&self.key.public_key.bytes)?;
        octets.put_u16(self.symmetric_algorithms.len() as u16 * 4)?;

        for (kdf_id, aead_id) in &self.symmetric_algorithms {
            octets.put_u16(*kdf_id as u16)?;
            octets.put_u16(*aead_id as u16)?;
        }

        Ok(())
    }
}

pub async fn decode_request_header<O, E>(
    hpke_config: &ServerConfig,
    request_info_str: &str,
    response_info_str: &str,
    stream_buf: &mut StreamBuf<impl Stream<Item = Result<O, E>> + Send + Unpin>,
) -> Result<(RequestReceivingContext, ResponseSendingContext), E>
where
    O: Into<Bytes>,
    E: From<io::Error>,
{
    struct RequestOpener<Kem, Kdf, Aead>(AeadCtxR<Aead, Kdf, Kem>)
    where
        Kem: KemTrait,
        Kdf: KdfImpl,
        Aead: AeadImpl;

    impl<Kem, Kdf, Aead> fmt::Debug for RequestOpener<Kem, Kdf, Aead>
    where
        Kem: KemTrait,
        Kdf: KdfImpl,
        Aead: AeadImpl,
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("RequestOpener")
                .field("kem_id", &KemId::try_from_u16(Kem::KEM_ID).unwrap())
                .field("kdf_id", &KdfId::try_from_u16(Kdf::KDF_ID).unwrap())
                .field("aead_id", &AeadId::try_from_u16(Aead::AEAD_ID).unwrap())
                .finish()
        }
    }

    impl<Kem, Kdf, Aead> OpenInPlace for RequestOpener<Kem, Kdf, Aead>
    where
        Kem: KemTrait + Send + Sync + 'static,
        Kdf: KdfImpl,
        Aead: AeadImpl,
        <Aead as hpke::aead::Aead>::AeadImpl: Send + Sync,
    {
        fn open_in_place<'a>(
            &mut self,
            buf: &'a mut [u8],
            aad: &[u8],
        ) -> Result<&'a mut [u8], HpkeError> {
            let ciphertext_len = buf
                .len()
                .checked_sub(hpke::aead::AeadTag::<Aead>::size())
                .ok_or(HpkeError::OpenError)?;

            let (ciphertext, tag) = buf.split_at_mut(ciphertext_len);

            // NOTE(nox): This `AeadTag::from_bytes` call cannot return an error
            // because the bytes we pass to it are exactly the right length.
            let tag = hpke::aead::AeadTag::from_bytes(tag)?;

            self.0.open_in_place_detached(ciphertext, aad, &tag)?;

            Ok(ciphertext)
        }
    }

    struct SetupRequestDecap;

    impl CallTriple<(&PrivateKeyBytes, &EncappedKey, &[u8], &str)> for SetupRequestDecap {
        type Output = Result<(Box<dyn OpenInPlace>, ResponseSecret), HpkeError>;

        fn call_triple<Kem, Kdf, Aead>(
            (sk_recip, encapped_key, request_info, response_info_str): (
                &PrivateKeyBytes,
                &EncappedKey,
                &[u8],
                &str,
            ),
        ) -> Self::Output
        where
            Kem: KemTrait + Send + Sync + 'static,
            Kdf: KdfImpl,
            Aead: AeadImpl,
            <Aead as hpke::aead::Aead>::AeadImpl: Send + Sync,
        {
            let aead_ctx = setup_receiver::<Aead, Kdf, Kem>(
                &OpModeR::Base,
                &sk_recip.try_lift::<Kem>()?,
                &encapped_key.try_lift::<Kem>()?,
                request_info,
            )?;

            let aead_key_len = <<Aead as AeadImpl>::Base as KeySizeUser>::KeySize::to_usize();
            let aead_nonce_len = <<Aead as AeadImpl>::Base as AeadCore>::NonceSize::to_usize();
            let response_secret_len = cmp::max(aead_key_len, aead_nonce_len);

            let response_secret = ResponseSecret({
                let mut buf = vec![0; response_secret_len];

                // NOTE(nox): This never panics because the secret length is never too big.
                aead_ctx
                    .export(response_info_str.as_bytes(), &mut buf)
                    .unwrap();

                buf
            });

            Ok((Box::new(RequestOpener(aead_ctx)), response_secret))
        }
    }

    let encap_header = EncapHeader::decode(&mut *stream_buf).await?;
    let key_pair = hpke_config.get_key_pair(&encap_header)?;
    let encapped_key_len = key_pair.public_key.kem_id.encapped_key_len();
    let encapped_key = EncappedKey(stream_buf.read_exact(encapped_key_len).await?);
    let request_info = encap_header.encode_info(request_info_str);

    let (opener, response_secret) = dispatch_triple::<_, SetupRequestDecap>(
        key_pair.public_key.kem_id,
        encap_header.kdf_id,
        encap_header.aead_id,
        (
            &key_pair.private_key,
            &encapped_key,
            &request_info,
            response_info_str,
        ),
    )
    .map_err(|e| invalid_data(format!("{e}")))?;

    let request_receiving_hpke_context = RequestReceivingContext { opener };

    let response_sending_hpke_context = ResponseSendingContext {
        inner: ResponseContext {
            kdf_id: encap_header.kdf_id,
            aead_id: encap_header.aead_id,
            encapped_key,
            response_secret,
        },
    };

    Ok((
        request_receiving_hpke_context,
        response_sending_hpke_context,
    ))
}

pub struct RequestReceivingContext {
    pub(crate) opener: Box<dyn OpenInPlace>,
}

impl fmt::Debug for RequestReceivingContext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("RequestReceivingContext")
    }
}

impl RequestReceivingContext {
    pub async fn decapsulate_non_chunked_content<S, O, E>(
        mut self,
        stream_buf: &mut StreamBuf<S>,
    ) -> Result<Bytes, E>
    where
        S: Stream<Item = Result<O, E>> + Send + Unpin,
        O: Into<Bytes>,
        E: From<io::Error>,
    {
        // NOTE(nox): In the future, we will be able to mutate Bytes directly.
        // https://github.com/tokio-rs/bytes/pull/710
        let mut buf = Vec::from(stream_buf.read_to_end().await?);

        let opened_len = self
            .opener
            .open_in_place(&mut buf, b"")
            .map_err(|e| invalid_data(format!("could not open non chunked content ({e})")))?
            .len();

        buf.truncate(opened_len);

        Ok(Bytes::from(buf))
    }

    pub fn decapsulate_chunked_content<S, O, E>(
        self,
        stream_buf: StreamBuf<S>,
    ) -> DecapsulatedRequestStream<S>
    where
        S: Stream<Item = Result<O, E>> + Send + Unpin,
        O: Into<Bytes>,
        E: From<io::Error>,
    {
        DecapsulatedRequestStream::new(self, stream_buf)
    }
}

pub struct DecapsulatedRequestStream<S> {
    inner: Decapsulated<Box<dyn OpenInPlace>, S>,
}

impl<S> fmt::Debug for DecapsulatedRequestStream<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.fmt(f, "DecapsulatedRequestStream")
    }
}

impl<S, O, E> DecapsulatedRequestStream<S>
where
    S: Stream<Item = Result<O, E>> + Send + Unpin,
    O: Into<Bytes>,
    E: From<io::Error>,
{
    pub(crate) fn new(
        request_receiving_hpke_context: RequestReceivingContext,
        stream_buf: StreamBuf<S>,
    ) -> Self {
        DecapsulatedRequestStream {
            inner: Decapsulated::new(request_receiving_hpke_context.opener, stream_buf),
        }
    }
}

impl<S, T, E> Stream for DecapsulatedRequestStream<S>
where
    S: Stream<Item = Result<T, E>> + Send + Unpin,
    T: Into<Bytes>,
    E: From<io::Error>,
{
    type Item = Result<Bytes, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

#[derive(Clone)]
pub struct ResponseSendingContext {
    pub(crate) inner: ResponseContext,
}

impl fmt::Debug for ResponseSendingContext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.fmt(f, "ResponseSendingContext")
    }
}

impl ResponseSendingContext {
    pub fn encapsulate_non_chunked_content<S, O, E>(
        self,
        stream_buf: StreamBuf<S>,
    ) -> EncapsulatedResponseStream<S>
    where
        S: Stream<Item = Result<O, E>> + Send + Unpin,
        O: Into<Bytes>,
        E: From<io::Error>,
    {
        let (response_nonce, aead_context) = self.derive_aead_state();

        EncapsulatedResponseStream {
            inner: Encapsulated::non_chunked(aead_context, response_nonce.0, stream_buf),
        }
    }

    pub fn encapsulate_chunked_content<S, O, E>(
        self,
        stream_buf: StreamBuf<S>,
    ) -> EncapsulatedResponseStream<S>
    where
        S: Stream<Item = Result<O, E>> + Send + Unpin,
        O: Into<Bytes>,
        E: From<io::Error>,
    {
        let (response_nonce, aead_context) = self.derive_aead_state();

        EncapsulatedResponseStream {
            inner: Encapsulated::chunked(aead_context, response_nonce.0, stream_buf),
        }
    }

    fn derive_aead_state(&self) -> (ResponseNonce, AeadContext) {
        let response_nonce = ResponseNonce({
            let mut buf = vec![0; self.inner.response_secret.0.len()];

            // NOTE(nox): Should the RNG be configurable?
            rand::rngs::OsRng.fill_bytes(&mut buf);

            buf.into()
        });

        let aead_context = self.inner.derive_aead_context(&response_nonce);

        (response_nonce, aead_context)
    }
}

pub struct EncapsulatedResponseStream<S> {
    inner: Encapsulated<AeadContext, S>,
}

impl<S> fmt::Debug for EncapsulatedResponseStream<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.fmt(f, "EncapsulatedResponseStream")
    }
}

impl<S, O, E> Stream for EncapsulatedResponseStream<S>
where
    S: Stream<Item = Result<O, E>> + Send + Unpin,
    O: Into<Bytes>,
    E: From<io::Error>,
{
    type Item = Result<Bytes, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}
