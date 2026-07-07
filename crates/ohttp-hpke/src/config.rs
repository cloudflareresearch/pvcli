// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use crate::invalid_data;
use aead::generic_array::typenum::Unsigned;
use aead::{AeadCore, AeadInPlace, KeyInit, KeySizeUser};
use hkdf::hmac::digest::crypto_common::BlockSizeUser;
use hkdf::hmac::digest::Digest;
use hpke::aead::{Aead as AeadTrait, AesGcm128, AesGcm256, ChaCha20Poly1305};
use hpke::kdf::{HkdfSha256, HkdfSha384, HkdfSha512, Kdf as KdfTrait};
use hpke::kem::{DhP256HkdfSha256, DhP384HkdfSha384, Kem as KemTrait, X25519HkdfSha256};
use hpke::Serializable;
use sha2::{Sha256, Sha384, Sha512};
use std::io;

#[derive(Debug)]
pub(crate) struct KeyConfig<K> {
    pub(crate) key_id: u8,
    pub(crate) key: K,
    pub(crate) symmetric_algorithms: Vec<(KdfId, AeadId)>,
}

macro_rules! id_enum {
    (enum $name:ident($kind:expr, $constant:ident) { $($variant:ident,)+ }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #[non_exhaustive]
        #[repr(u16)]
        pub enum $name {
            $($variant = $variant::$constant,)+
        }

        impl $name {
            pub(crate) fn try_from_u16(id: u16) -> io::Result<Self> {
                Ok(match id {
                    $($variant::$constant => Self::$variant,)+
                    _ => return Err(invalid_data(format!("invalid {} id ({})", $kind, id))),
                })
            }
        }
    };
}

macro_rules! hkde {
    ($($hkde:ident,)+) => {
        id_enum! {
            enum KemId("KEM", KEM_ID) {
                $($hkde,)+
            }
        }

        impl KemId {
            pub(crate) fn public_key_len(self) -> usize {
                match self {
                    $(Self::$hkde => <<$hkde as KemTrait>::PublicKey as Serializable>::size(),)+
                }
            }

            pub(crate) fn encapped_key_len(self) -> usize {
                match self {
                    $(Self::$hkde => <<$hkde as KemTrait>::EncappedKey as Serializable>::size(),)+
                }
            }
        }
    };
}

hkde! {
    DhP256HkdfSha256,
    DhP384HkdfSha384,
    X25519HkdfSha256,
}

pub(crate) trait KdfImpl: KdfTrait + Send + Sync + 'static {
    type Base: Clone + Digest + BlockSizeUser;
}

macro_rules! kdf {
    ($($kdf:ident => $hash:ident,)+) => {
        id_enum! {
            enum KdfId("KDF", KDF_ID) {
                $($kdf,)+
            }
        }

        $(impl KdfImpl for $kdf {
            type Base = $hash;
        })+
    };
}

kdf! {
    HkdfSha256 => Sha256,
    HkdfSha384 => Sha384,
    HkdfSha512 => Sha512,
}

pub(crate) trait AeadImpl: AeadTrait + Send + Sync + 'static {
    type Base: AeadInPlace + KeyInit;
}

macro_rules! aead {
    ($($aead:ident => $base:path,)+) => {
        id_enum! {
            enum AeadId("AEAD", AEAD_ID) {
                $($aead,)+
            }
        }

        $(impl AeadImpl for $aead {
            type Base = $base;
        })+

        impl AeadId {
            pub(crate) fn key_len(self) -> usize {
                match self {
                    $(Self::$aead => <<$aead as AeadImpl>::Base as KeySizeUser>::KeySize::to_usize(),)+
                }
            }

            pub(crate) fn nonce_len(self) -> usize {
                match self {
                    $(Self::$aead => <<$aead as AeadImpl>::Base as AeadCore>::NonceSize::to_usize(),)+
                }
            }
        }
    };
}

aead! {
    AesGcm128 => aes_gcm::Aes128Gcm,
    AesGcm256 => aes_gcm::Aes256Gcm,
    ChaCha20Poly1305 => chacha20poly1305::ChaCha20Poly1305,
}
