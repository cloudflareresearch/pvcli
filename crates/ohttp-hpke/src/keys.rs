// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use crate::config::KemId;
use bytes::Bytes;
use hpke::kem::{DhP256HkdfSha256, DhP384HkdfSha384, Kem as KemTrait, X25519HkdfSha256};
use hpke::{Deserializable, HpkeError, Serializable};
use std::fmt;

pub fn derive_key_pair(kem_id: KemId, ikm: &[u8]) -> KeyPair {
    let (private_key_bytes, public_key_bytes) = match kem_id {
        KemId::DhP256HkdfSha256 => kem_derive_keypair_bytes::<DhP256HkdfSha256>(ikm),
        KemId::DhP384HkdfSha384 => kem_derive_keypair_bytes::<DhP384HkdfSha384>(ikm),
        KemId::X25519HkdfSha256 => kem_derive_keypair_bytes::<X25519HkdfSha256>(ikm),
    };

    KeyPair {
        public_key: PublicKey {
            kem_id,
            bytes: public_key_bytes,
        },
        private_key: private_key_bytes,
    }
}

fn kem_derive_keypair_bytes<Kem>(ikm: &[u8]) -> (PrivateKeyBytes, Bytes)
where
    Kem: KemTrait,
{
    let (private_key_bytes, public_key_bytes) = Kem::derive_keypair(ikm);

    (
        PrivateKeyBytes(private_key_bytes.to_bytes().to_vec()),
        public_key_bytes.to_bytes().to_vec().into(),
    )
}

pub fn key_pair_from_secret(kem_id: KemId, secret: Vec<u8>) -> Result<KeyPair, HpkeError> {
    let private_key_bytes = PrivateKeyBytes(secret);

    let public_key_bytes = match kem_id {
        KemId::DhP256HkdfSha256 => kem_sk_to_pk::<DhP256HkdfSha256>(&private_key_bytes),
        KemId::DhP384HkdfSha384 => kem_sk_to_pk::<DhP384HkdfSha384>(&private_key_bytes),
        KemId::X25519HkdfSha256 => kem_sk_to_pk::<X25519HkdfSha256>(&private_key_bytes),
    }?;

    Ok(KeyPair {
        public_key: PublicKey {
            kem_id,
            bytes: public_key_bytes,
        },
        private_key: private_key_bytes,
    })
}

fn kem_sk_to_pk<Kem>(private_key_bytes: &PrivateKeyBytes) -> Result<Bytes, HpkeError>
where
    Kem: KemTrait,
{
    Ok(Kem::sk_to_pk(&private_key_bytes.try_lift::<Kem>()?)
        .to_bytes()
        .to_vec()
        .into())
}

pub struct KeyPair {
    pub(crate) public_key: PublicKey,
    // TODO(nox): Zeroize that on drop.
    pub(crate) private_key: PrivateKeyBytes,
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("kem_id", &self.public_key.kem_id)
            .field("public_key", &DebugKeyBytes(&self.public_key.bytes))
            .field("private_key", &..)
            .finish()
    }
}

impl KeyPair {
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

#[derive(Clone)]
pub struct PublicKey {
    pub(crate) kem_id: KemId,
    pub(crate) bytes: Bytes,
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("kem_id", &self.kem_id)
            .field("bytes", &DebugKeyBytes(&self.bytes))
            .finish()
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone)]
pub(crate) struct EncappedKey(pub(crate) Bytes);

impl EncappedKey {
    pub(crate) fn try_lift<Kem>(&self) -> Result<Kem::EncappedKey, HpkeError>
    where
        Kem: KemTrait,
    {
        Kem::EncappedKey::from_bytes(&self.0)
    }
}

impl fmt::Debug for EncappedKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("EncappedKey")
            .field(&DebugKeyBytes(&self.0))
            .finish()
    }
}

pub(crate) struct PrivateKeyBytes(pub(crate) Vec<u8>);

impl PrivateKeyBytes {
    pub(crate) fn try_lift<Kem>(&self) -> Result<Kem::PrivateKey, HpkeError>
    where
        Kem: KemTrait,
    {
        Kem::PrivateKey::from_bytes(&self.0)
    }
}

impl fmt::Debug for PrivateKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("PrivateKeyBytes").field(&..).finish()
    }
}

struct DebugKeyBytes<'a>(&'a [u8]);

impl fmt::Debug for DebugKeyBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }

        Ok(())
    }
}
