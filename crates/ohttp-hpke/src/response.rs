// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use crate::config::{AeadId, AeadImpl, KdfId};
use crate::decapsulated::OpenInPlace;
use crate::encapsulated::SealInPlace;
use crate::keys::EncappedKey;
use aead::generic_array::GenericArray;
use aead::{AeadCore, KeySizeUser};
use bytes::Bytes;
use hpke::HpkeError;
use std::fmt;

#[derive(Clone)]
pub(crate) struct ResponseContext {
    pub(crate) kdf_id: KdfId,
    pub(crate) aead_id: AeadId,
    pub(crate) encapped_key: EncappedKey,
    pub(crate) response_secret: ResponseSecret,
}

impl ResponseContext {
    pub(crate) fn derive_aead_context(&self, response_nonce: &ResponseNonce) -> AeadContext {
        let (aead_key, aead_nonce) = self.kdf_id.derive_aead_key_and_nonce(
            self.aead_id,
            &self.encapped_key,
            &self.response_secret,
            response_nonce,
        );

        AeadContext {
            aead_id: self.aead_id,
            aead_key,
            chunk_nonce: ChunkNonce::new(aead_nonce),
        }
    }

    pub(crate) fn fmt(&self, f: &mut fmt::Formatter, name: &str) -> fmt::Result {
        f.debug_struct(name)
            .field("kdf_id", &self.kdf_id)
            .field("aead_id", &self.aead_id)
            .field("encapped_key", &self.encapped_key)
            .field("response_secret", &self.response_secret)
            .finish()
    }
}

#[derive(Debug)]
pub(crate) struct AeadContext {
    aead_id: AeadId,
    aead_key: AeadKey,
    chunk_nonce: ChunkNonce,
}

impl SealInPlace for AeadContext {
    fn seal_in_place(&mut self, ciphertext: &mut [u8], aad: &[u8]) -> Result<AeadTag, HpkeError> {
        self.aead_id
            .seal_in_place_detached(&self.aead_key, self.chunk_nonce.next()?, aad, ciphertext)
            .map_err(|aead::Error| HpkeError::SealError)
    }
}

impl OpenInPlace for AeadContext {
    fn open_in_place<'a>(
        &mut self,
        ciphertext: &'a mut [u8],
        aad: &[u8],
    ) -> Result<&'a mut [u8], HpkeError> {
        self.aead_id
            .open_in_place(&self.aead_key, self.chunk_nonce.next()?, aad, ciphertext)
            .map_err(|aead::Error| HpkeError::OpenError)
    }
}

pub(crate) struct ResponseNonce(pub(crate) Bytes);

pub(crate) struct AeadKey(pub(crate) Vec<u8>);

impl fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("AeadKey").field(&..).finish()
    }
}

impl AeadKey {
    pub(crate) fn lift<Aead>(
        &self,
    ) -> &GenericArray<u8, <<Aead as AeadImpl>::Base as KeySizeUser>::KeySize>
    where
        Aead: AeadImpl,
    {
        GenericArray::from_slice(&self.0)
    }
}

#[derive(Clone)]
pub(crate) struct AeadNonce<T>(pub(crate) T);

impl<T> fmt::Debug for AeadNonce<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("AeadNonce").field(&..).finish()
    }
}

impl<T> AeadNonce<T>
where
    T: AsRef<[u8]>,
{
    pub(crate) fn as_ref(&self) -> AeadNonce<&[u8]> {
        AeadNonce(self.0.as_ref())
    }

    pub(crate) fn lift<Aead>(
        &self,
    ) -> &GenericArray<u8, <<Aead as AeadImpl>::Base as AeadCore>::NonceSize>
    where
        Aead: AeadImpl,
    {
        GenericArray::from_slice(self.0.as_ref())
    }
}

pub(crate) struct AeadTag(pub(crate) Vec<u8>);

impl fmt::Debug for AeadTag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("AeadTag").field(&..).finish()
    }
}

#[derive(Clone)]
pub(crate) struct ResponseSecret(pub(crate) Vec<u8>);

impl fmt::Debug for ResponseSecret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ResponseSecret").field(&..).finish()
    }
}

#[derive(Debug)]
struct ChunkNonce {
    initial: AeadNonce<Vec<u8>>,
    counter: Box<[u8]>,
    current: AeadNonce<Vec<u8>>,
}

impl ChunkNonce {
    fn new(aead_nonce: AeadNonce<Vec<u8>>) -> Self {
        Self {
            initial: aead_nonce.clone(),
            counter: vec![0; aead_nonce.0.len()].into_boxed_slice(),
            current: aead_nonce,
        }
    }

    fn next(&mut self) -> Result<AeadNonce<&[u8]>, HpkeError> {
        for ((counter_byte, initial_byte), current_byte) in self
            .counter
            .iter()
            .zip(&self.initial.0)
            .zip(&mut *self.current.0)
        {
            *current_byte = *counter_byte ^ *initial_byte;
        }

        self.incr()?;

        Ok(self.current.as_ref())
    }

    fn incr(&mut self) -> Result<(), HpkeError> {
        let mut carry;

        for byte in self.counter.iter_mut().rev() {
            (*byte, carry) = byte.overflowing_add(1);

            if !carry {
                return Ok(());
            }
        }

        Err(HpkeError::MessageLimitReached)
    }
}
