use crate::config::{AeadId, AeadImpl, KdfId, KdfImpl, KemId, KeyConfig};
use crate::decapsulated::{Decapsulated, OpenInPlace};
use crate::encapsulated::{Encapsulated, SealInPlace};
use crate::header::EncapHeader;
use crate::instance::{dispatch_triple, CallTriple};
use crate::invalid_data;
use crate::keys::{EncappedKey, PublicKey};
use crate::response::{AeadContext, AeadTag, ResponseContext, ResponseNonce, ResponseSecret};
use aead::generic_array::typenum::Unsigned;
use aead::{AeadCore, KeySizeUser};
use bytes::Bytes;
use futures::Stream;
use hpke::aead::AeadCtxS;
use hpke::{Deserializable, HpkeError, Kem as KemTrait, OpModeS, Serializable};
use octets::{Octets, OctetsMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{cmp, fmt, io};
use stream_buf::StreamBuf;
use stream_octets::StreamBufExt;

pub async fn decode_config<O, E>(
    stream_buf: &mut StreamBuf<impl Stream<Item = Result<O, E>> + Send + Unpin>,
) -> Result<ClientConfig, E>
where
    O: Into<Bytes>,
    E: From<io::Error>,
{
    let mut key_configs = vec![];

    while stream_buf.has_more_data().await? {
        let encoded_len = stream_buf.decode_u16().await?;
        let encoded = stream_buf.read_exact(encoded_len as usize).await?;

        // Skip key configs we can't decode (e.g. unsupported KEM ids such as
        // ML-KEM-768) instead of failing the entire config parse. As long as at
        // least one supported key config remains, we can still proceed.
        if let Ok(key_config) = KeyConfig::decode(&encoded) {
            key_configs.push(key_config);
        }
    }

    if key_configs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no key config found").into());
    }

    Ok(ClientConfig { key_configs })
}

impl KeyConfig<PublicKey> {
    pub(crate) fn decode(encoded: &[u8]) -> io::Result<Self> {
        let mut octets = Octets::with_slice(encoded);

        let key_id = octets.get_u8().map_err(invalid_data)?;

        let kem_id = KemId::try_from_u16(octets.get_u16().map_err(invalid_data)?)?;

        let public_key = PublicKey {
            kem_id,
            bytes: octets
                .get_bytes(kem_id.public_key_len())
                .map_err(invalid_data)?
                .to_vec()
                .into(),
        };

        let symmetric_algorithms_len = octets.get_u16().map_err(invalid_data)?;

        if symmetric_algorithms_len == 0
            || symmetric_algorithms_len % 4 != 0
            || octets.cap() < symmetric_algorithms_len as usize
        {
            return Err(invalid_data(format!(
                "invalid symmetric algorithms length ({symmetric_algorithms_len})"
            )));
        }

        let symmetric_algorithms = (0..(symmetric_algorithms_len / 4))
            .map(|_| {
                let kdf_id = KdfId::try_from_u16(octets.get_u16().map_err(invalid_data)?)?;

                let aead_id = AeadId::try_from_u16(octets.get_u16().map_err(invalid_data)?)?;

                Ok((kdf_id, aead_id))
            })
            .collect::<io::Result<Vec<_>>>()?;

        Ok(Self {
            key_id,
            key: public_key,
            symmetric_algorithms,
        })
    }
}

#[derive(Debug)]
pub struct ClientConfig {
    #[allow(dead_code)]
    key_configs: Vec<KeyConfig<PublicKey>>,
}

impl ClientConfig {
    pub fn first_encap_config(&self) -> EncapConfig {
        let key_config = &self.key_configs[0];
        let (kdf_id, aead_id) = key_config.symmetric_algorithms[0];

        EncapConfig {
            key_id: key_config.key_id,
            public_key: key_config.key.clone(),
            kdf_id,
            aead_id,
        }
    }
}

pub fn setup_request_encapsulation(
    config: EncapConfig,
    request_info_str: &str,
    response_info_str: &str,
) -> Result<(RequestSendingContext, ResponseReceivingContext), HpkeError> {
    struct RequestSealer<Kem, Kdf, Aead>(AeadCtxS<Aead, Kdf, Kem>)
    where
        Kem: KemTrait,
        Kdf: KdfImpl,
        Aead: AeadImpl;

    impl<Kem, Kdf, Aead> fmt::Debug for RequestSealer<Kem, Kdf, Aead>
    where
        Kem: KemTrait,
        Kdf: KdfImpl,
        Aead: AeadImpl,
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("RequestSealer")
                .field("kem_id", &KemId::try_from_u16(Kem::KEM_ID).unwrap())
                .field("kdf_id", &KdfId::try_from_u16(Kdf::KDF_ID).unwrap())
                .field("aead_id", &AeadId::try_from_u16(Aead::AEAD_ID).unwrap())
                .finish()
        }
    }

    impl<Kem, Kdf, Aead> SealInPlace for RequestSealer<Kem, Kdf, Aead>
    where
        Kem: KemTrait + Send + Sync + 'static,
        Kdf: KdfImpl,
        Aead: AeadImpl,
        <Aead as hpke::aead::Aead>::AeadImpl: Send + Sync,
    {
        fn seal_in_place(&mut self, buf: &mut [u8], aad: &[u8]) -> Result<AeadTag, HpkeError> {
            let tag = self.0.seal_in_place_detached(buf, aad)?;

            Ok(AeadTag(tag.to_bytes().to_vec()))
        }
    }

    struct SetupRequestEncap;

    impl CallTriple<(&[u8], &[u8], &str)> for SetupRequestEncap {
        type Output = Result<(Box<dyn SealInPlace>, EncappedKey, ResponseSecret), HpkeError>;

        fn call_triple<Kem, Kdf, Aead>(
            (pk_recip, request_info, response_info_str): (&[u8], &[u8], &str),
        ) -> Self::Output
        where
            Kem: KemTrait + Send + Sync + 'static,
            Kdf: KdfImpl,
            Aead: AeadImpl,
            <Aead as hpke::aead::Aead>::AeadImpl: Send + Sync,
        {
            let (encapped_key, aead_ctx) = hpke::setup_sender::<Aead, Kdf, Kem, _>(
                &OpModeS::Base,
                &Kem::PublicKey::from_bytes(pk_recip)?,
                request_info,
                &mut rand::thread_rng(),
            )?;

            let encapped_key = EncappedKey(encapped_key.to_bytes().to_vec().into());

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

            Ok((
                Box::new(RequestSealer(aead_ctx)),
                encapped_key,
                response_secret,
            ))
        }
    }

    let encap_header = EncapHeader {
        key_id: config.key_id,
        kem_id: config.public_key.kem_id,
        kdf_id: config.kdf_id,
        aead_id: config.aead_id,
    };

    let request_info = encap_header.encode_info(request_info_str);

    let (methods, encapped_key, response_secret) = dispatch_triple::<_, SetupRequestEncap>(
        config.public_key.kem_id,
        config.kdf_id,
        config.aead_id,
        (&config.public_key.bytes, &request_info, response_info_str),
    )?;

    let request_sending_hpke_context = RequestSendingContext {
        sealer: methods,
        encap_header,
        encapped_key: encapped_key.clone(),
    };

    let response_receiving_hpke_context = ResponseReceivingContext {
        inner: ResponseContext {
            kdf_id: config.kdf_id,
            aead_id: config.aead_id,
            encapped_key,
            response_secret,
        },
    };

    Ok((
        request_sending_hpke_context,
        response_receiving_hpke_context,
    ))
}

#[derive(Debug)]
pub struct EncapConfig {
    pub key_id: u8,
    pub public_key: PublicKey,
    pub kdf_id: KdfId,
    pub aead_id: AeadId,
}

#[derive(Debug)]
pub struct RequestSendingContext {
    pub(crate) sealer: Box<dyn SealInPlace>,
    pub(crate) encap_header: EncapHeader,
    pub(crate) encapped_key: EncappedKey,
}

impl RequestSendingContext {
    pub fn encapsulate_non_chunked_content<S, O, E>(
        self,
        stream_buf: StreamBuf<S>,
    ) -> EncapsulatedRequestStream<S>
    where
        S: Stream<Item = Result<O, E>> + Send + Unpin,
        O: Into<Bytes>,
        E: From<io::Error>,
    {
        let initial_chunk = self.encode_initial_chunk();

        EncapsulatedRequestStream {
            inner: Encapsulated::non_chunked(self.sealer, initial_chunk, stream_buf),
        }
    }

    pub fn encapsulate_chunked_content<S, O, E>(
        self,
        stream_buf: StreamBuf<S>,
    ) -> EncapsulatedRequestStream<S>
    where
        S: Stream<Item = Result<O, E>> + Send + Unpin,
        O: Into<Bytes>,
        E: From<io::Error>,
    {
        let initial_chunk = self.encode_initial_chunk();

        EncapsulatedRequestStream {
            inner: Encapsulated::chunked(self.sealer, initial_chunk, stream_buf),
        }
    }

    fn encode_initial_chunk(&self) -> Bytes {
        let mut buf = vec![0; EncapHeader::encoded_len() + self.encapped_key.0.len()];
        let mut octets = OctetsMut::with_slice(&mut buf);

        self.encap_header.put(&mut octets).unwrap();
        octets.put_bytes(&self.encapped_key.0).unwrap();

        buf.into()
    }
}

pub struct EncapsulatedRequestStream<S> {
    inner: Encapsulated<Box<dyn SealInPlace>, S>,
}

impl<S> fmt::Debug for EncapsulatedRequestStream<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f, "EncapsulatedRequestStream")
    }
}

impl<S, O, E> Stream for EncapsulatedRequestStream<S>
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

pub struct ResponseReceivingContext {
    pub(crate) inner: ResponseContext,
}

impl fmt::Debug for ResponseReceivingContext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.fmt(f, "ResponseReceivingContext")
    }
}

impl ResponseReceivingContext {
    pub async fn decapsulate_non_chunked_content<S, O, E>(
        self,
        stream_buf: &mut StreamBuf<S>,
    ) -> Result<Bytes, E>
    where
        S: Stream<Item = Result<O, E>> + Send + Unpin,
        O: Into<Bytes>,
        E: From<io::Error>,
    {
        let mut aead_context = self.derive_aead_context(stream_buf).await?;
        let mut content = Vec::from(stream_buf.read_to_end().await?);

        let opened_len = aead_context
            .open_in_place(&mut content, b"")
            .map_err(|e| invalid_data(format!("could not open content ({e})")))?
            .len();
        content.truncate(opened_len);

        Ok(content.into())
    }

    pub async fn decapsulate_chunked_content<S, O, E>(
        self,
        mut stream_buf: StreamBuf<S>,
    ) -> Result<DecapsulatedResponseStream<S>, E>
    where
        S: Stream<Item = Result<O, E>> + Send + Unpin,
        O: Into<Bytes>,
        E: From<io::Error>,
    {
        let aead_context = self.derive_aead_context(&mut stream_buf).await?;

        Ok(DecapsulatedResponseStream {
            inner: Decapsulated::new(aead_context, stream_buf),
        })
    }

    async fn derive_aead_context<S, O, E>(
        &self,
        stream_buf: &mut StreamBuf<S>,
    ) -> Result<AeadContext, E>
    where
        S: Stream<Item = Result<O, E>> + Send + Unpin,
        O: Into<Bytes>,
        E: From<io::Error>,
    {
        let response_nonce = ResponseNonce(
            stream_buf
                .read_exact(self.inner.response_secret.0.len())
                .await?,
        );

        Ok(self.inner.derive_aead_context(&response_nonce))
    }
}

pub struct DecapsulatedResponseStream<S> {
    inner: Decapsulated<AeadContext, S>,
}

impl<S> fmt::Debug for DecapsulatedResponseStream<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.fmt(f, "DecapsulatedResponseStream")
    }
}

impl<S, T, E> Stream for DecapsulatedResponseStream<S>
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
