// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use crate::config::{AeadId, AeadImpl, KdfId, KdfImpl, KemId};
use crate::keys::EncappedKey;
use crate::response::{AeadKey, AeadNonce, AeadTag, ResponseNonce, ResponseSecret};
use aead::generic_array::typenum::Unsigned;
use aead::{AeadCore, AeadInPlace, KeyInit};
use hkdf::SimpleHkdf;
use hpke::aead::{self as hpke_aead, AesGcm128, AesGcm256, ChaCha20Poly1305};
use hpke::kdf::{HkdfSha256, HkdfSha384, HkdfSha512};
use hpke::kem::{DhP256HkdfSha256, DhP384HkdfSha384, Kem as KemTrait, X25519HkdfSha256};

pub(crate) fn dispatch_triple<Args, T>(
    kem_id: KemId,
    kdf_id: KdfId,
    aead_id: AeadId,
    args: Args,
) -> T::Output
where
    T: CallTriple<Args>,
{
    // NOTE(nox): Life is too short to even try bother writing a macro for this,
    // and I could imagine a future where we forbid one of those triples, in
    // which case we will need to make the macro even worse anyway.
    match (kem_id, kdf_id, aead_id) {
        (KemId::DhP256HkdfSha256, KdfId::HkdfSha256, AeadId::AesGcm128) => {
            T::call_triple::<DhP256HkdfSha256, HkdfSha256, AesGcm128>(args)
        }
        (KemId::DhP384HkdfSha384, KdfId::HkdfSha256, AeadId::AesGcm128) => {
            T::call_triple::<DhP384HkdfSha384, HkdfSha256, AesGcm128>(args)
        }
        (KemId::X25519HkdfSha256, KdfId::HkdfSha256, AeadId::AesGcm128) => {
            T::call_triple::<X25519HkdfSha256, HkdfSha256, AesGcm128>(args)
        }
        (KemId::DhP256HkdfSha256, KdfId::HkdfSha384, AeadId::AesGcm128) => {
            T::call_triple::<DhP256HkdfSha256, HkdfSha384, AesGcm128>(args)
        }
        (KemId::DhP384HkdfSha384, KdfId::HkdfSha384, AeadId::AesGcm128) => {
            T::call_triple::<DhP384HkdfSha384, HkdfSha384, AesGcm128>(args)
        }
        (KemId::X25519HkdfSha256, KdfId::HkdfSha384, AeadId::AesGcm128) => {
            T::call_triple::<X25519HkdfSha256, HkdfSha384, AesGcm128>(args)
        }
        (KemId::DhP256HkdfSha256, KdfId::HkdfSha512, AeadId::AesGcm128) => {
            T::call_triple::<DhP256HkdfSha256, HkdfSha512, AesGcm128>(args)
        }
        (KemId::DhP384HkdfSha384, KdfId::HkdfSha512, AeadId::AesGcm128) => {
            T::call_triple::<DhP384HkdfSha384, HkdfSha512, AesGcm128>(args)
        }
        (KemId::X25519HkdfSha256, KdfId::HkdfSha512, AeadId::AesGcm128) => {
            T::call_triple::<X25519HkdfSha256, HkdfSha512, AesGcm128>(args)
        }
        (KemId::DhP256HkdfSha256, KdfId::HkdfSha256, AeadId::AesGcm256) => {
            T::call_triple::<DhP256HkdfSha256, HkdfSha256, AesGcm256>(args)
        }
        (KemId::DhP384HkdfSha384, KdfId::HkdfSha256, AeadId::AesGcm256) => {
            T::call_triple::<DhP384HkdfSha384, HkdfSha256, AesGcm256>(args)
        }
        (KemId::X25519HkdfSha256, KdfId::HkdfSha256, AeadId::AesGcm256) => {
            T::call_triple::<X25519HkdfSha256, HkdfSha256, AesGcm256>(args)
        }
        (KemId::DhP256HkdfSha256, KdfId::HkdfSha384, AeadId::AesGcm256) => {
            T::call_triple::<DhP256HkdfSha256, HkdfSha384, AesGcm256>(args)
        }
        (KemId::DhP384HkdfSha384, KdfId::HkdfSha384, AeadId::AesGcm256) => {
            T::call_triple::<DhP384HkdfSha384, HkdfSha384, AesGcm256>(args)
        }
        (KemId::X25519HkdfSha256, KdfId::HkdfSha384, AeadId::AesGcm256) => {
            T::call_triple::<X25519HkdfSha256, HkdfSha384, AesGcm256>(args)
        }
        (KemId::DhP256HkdfSha256, KdfId::HkdfSha512, AeadId::AesGcm256) => {
            T::call_triple::<DhP256HkdfSha256, HkdfSha512, AesGcm256>(args)
        }
        (KemId::DhP384HkdfSha384, KdfId::HkdfSha512, AeadId::AesGcm256) => {
            T::call_triple::<DhP384HkdfSha384, HkdfSha512, AesGcm256>(args)
        }
        (KemId::X25519HkdfSha256, KdfId::HkdfSha512, AeadId::AesGcm256) => {
            T::call_triple::<X25519HkdfSha256, HkdfSha512, AesGcm256>(args)
        }
        (KemId::DhP256HkdfSha256, KdfId::HkdfSha256, AeadId::ChaCha20Poly1305) => {
            T::call_triple::<DhP256HkdfSha256, HkdfSha256, ChaCha20Poly1305>(args)
        }
        (KemId::DhP384HkdfSha384, KdfId::HkdfSha256, AeadId::ChaCha20Poly1305) => {
            T::call_triple::<DhP384HkdfSha384, HkdfSha256, ChaCha20Poly1305>(args)
        }
        (KemId::X25519HkdfSha256, KdfId::HkdfSha256, AeadId::ChaCha20Poly1305) => {
            T::call_triple::<X25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>(args)
        }
        (KemId::DhP256HkdfSha256, KdfId::HkdfSha384, AeadId::ChaCha20Poly1305) => {
            T::call_triple::<DhP256HkdfSha256, HkdfSha384, ChaCha20Poly1305>(args)
        }
        (KemId::DhP384HkdfSha384, KdfId::HkdfSha384, AeadId::ChaCha20Poly1305) => {
            T::call_triple::<DhP384HkdfSha384, HkdfSha384, ChaCha20Poly1305>(args)
        }
        (KemId::X25519HkdfSha256, KdfId::HkdfSha384, AeadId::ChaCha20Poly1305) => {
            T::call_triple::<X25519HkdfSha256, HkdfSha384, ChaCha20Poly1305>(args)
        }
        (KemId::DhP256HkdfSha256, KdfId::HkdfSha512, AeadId::ChaCha20Poly1305) => {
            T::call_triple::<DhP256HkdfSha256, HkdfSha512, ChaCha20Poly1305>(args)
        }
        (KemId::DhP384HkdfSha384, KdfId::HkdfSha512, AeadId::ChaCha20Poly1305) => {
            T::call_triple::<DhP384HkdfSha384, HkdfSha512, ChaCha20Poly1305>(args)
        }
        (KemId::X25519HkdfSha256, KdfId::HkdfSha512, AeadId::ChaCha20Poly1305) => {
            T::call_triple::<X25519HkdfSha256, HkdfSha512, ChaCha20Poly1305>(args)
        }
    }
}

pub(crate) trait CallTriple<Args> {
    type Output;

    fn call_triple<Kem, Kdf, Aead>(args: Args) -> Self::Output
    where
        Kem: KemTrait + Send + Sync + 'static,
        Kdf: KdfImpl,
        Aead: AeadImpl,
        <Aead as hpke_aead::Aead>::AeadImpl: Send + Sync;
}

impl KdfId {
    pub(crate) fn derive_aead_key_and_nonce(
        self,
        aead_id: AeadId,
        encapped_key: &EncappedKey,
        response_secret: &ResponseSecret,
        response_nonce: &ResponseNonce,
    ) -> (AeadKey, AeadNonce<Vec<u8>>) {
        let aead_key_len = aead_id.key_len();
        let aead_nonce_len = aead_id.nonce_len();

        let salt = {
            let mut buf = Vec::with_capacity(encapped_key.0.len() + response_nonce.0.len());

            buf.extend_from_slice(&encapped_key.0);
            buf.extend_from_slice(&response_nonce.0);

            buf
        };

        fn derive<Kdf>(
            aead_key_len: usize,
            aead_nonce_len: usize,
            salt: &[u8],
            secret: &ResponseSecret,
        ) -> (AeadKey, AeadNonce<Vec<u8>>)
        where
            Kdf: KdfImpl,
        {
            let rpk = <SimpleHkdf<<Kdf as KdfImpl>::Base>>::new(Some(salt), &secret.0);

            let aead_key = AeadKey({
                let mut buf = vec![0; aead_key_len];

                // NOTE(nox): This never panics because the buf length is always correct.
                rpk.expand(b"key", &mut buf).unwrap();

                buf
            });

            let aead_nonce = AeadNonce({
                let mut buf = vec![0; aead_nonce_len];

                // NOTE(nox): This never panics because the buf length is always correct.
                rpk.expand(b"nonce", &mut buf).unwrap();

                buf
            });

            (aead_key, aead_nonce)
        }

        match self {
            Self::HkdfSha256 => {
                derive::<HkdfSha256>(aead_key_len, aead_nonce_len, &salt, response_secret)
            }
            Self::HkdfSha384 => {
                derive::<HkdfSha384>(aead_key_len, aead_nonce_len, &salt, response_secret)
            }
            Self::HkdfSha512 => {
                derive::<HkdfSha512>(aead_key_len, aead_nonce_len, &salt, response_secret)
            }
        }
    }
}

impl AeadId {
    pub(crate) fn seal_in_place_detached(
        self,
        aead_key: &AeadKey,
        aead_nonce: AeadNonce<&[u8]>,
        aad: &[u8],
        buf: &mut [u8],
    ) -> aead::Result<AeadTag> {
        fn seal<Aead>(
            aead_key: &AeadKey,
            aead_nonce: AeadNonce<&[u8]>,
            aad: &[u8],
            buf: &mut [u8],
        ) -> aead::Result<AeadTag>
        where
            Aead: AeadImpl,
        {
            let aead_key = aead_key.lift::<Aead>();
            let aead_nonce = aead_nonce.lift::<Aead>();

            let aead_tag = <<Aead as AeadImpl>::Base as KeyInit>::new(aead_key)
                .encrypt_in_place_detached(aead_nonce, aad, buf)?;

            Ok(AeadTag(Vec::from(&*aead_tag)))
        }

        match self {
            Self::AesGcm128 => seal::<AesGcm128>(aead_key, aead_nonce, aad, buf),
            Self::AesGcm256 => seal::<AesGcm256>(aead_key, aead_nonce, aad, buf),
            Self::ChaCha20Poly1305 => seal::<ChaCha20Poly1305>(aead_key, aead_nonce, aad, buf),
        }
    }

    pub(crate) fn open_in_place<'a>(
        self,
        aead_key: &AeadKey,
        aead_nonce: AeadNonce<&[u8]>,
        aad: &[u8],
        buf: &'a mut [u8],
    ) -> aead::Result<&'a mut [u8]> {
        fn open<'a, Aead>(
            aead_key: &AeadKey,
            aead_nonce: AeadNonce<&[u8]>,
            aad: &[u8],
            buf: &'a mut [u8],
        ) -> aead::Result<&'a mut [u8]>
        where
            Aead: AeadImpl,
        {
            let aead_key = aead_key.lift::<Aead>();
            let aead_nonce = aead_nonce.lift::<Aead>();

            let ciphertext_len = buf
                .len()
                .checked_sub(<<Aead as AeadImpl>::Base as AeadCore>::TagSize::to_usize())
                .ok_or(aead::Error)?;

            let (ciphertext, tag) = buf.split_at_mut(ciphertext_len);

            <<Aead as AeadImpl>::Base as KeyInit>::new(aead_key).decrypt_in_place_detached(
                aead_nonce,
                aad,
                ciphertext,
                aead::Tag::<<Aead as AeadImpl>::Base>::from_slice(tag),
            )?;

            Ok(ciphertext)
        }

        match self {
            Self::AesGcm128 => open::<AesGcm128>(aead_key, aead_nonce, aad, buf),
            Self::AesGcm256 => open::<AesGcm256>(aead_key, aead_nonce, aad, buf),
            Self::ChaCha20Poly1305 => open::<ChaCha20Poly1305>(aead_key, aead_nonce, aad, buf),
        }
    }
}
