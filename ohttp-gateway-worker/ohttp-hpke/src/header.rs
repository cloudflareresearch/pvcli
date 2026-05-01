use crate::config::{AeadId, KdfId, KemId};
use bytes::Bytes;
use futures::Stream;
use octets::OctetsMut;
use std::io;
use stream_buf::StreamBuf;
use stream_octets::StreamBufExt;

#[derive(Debug)]
pub(crate) struct EncapHeader {
    pub(crate) key_id: u8,
    pub(crate) kem_id: KemId,
    pub(crate) kdf_id: KdfId,
    pub(crate) aead_id: AeadId,
}

impl EncapHeader {
    pub(crate) async fn decode<O, E>(
        stream_buf: &mut StreamBuf<impl Stream<Item = Result<O, E>> + Send + Unpin>,
    ) -> Result<EncapHeader, E>
    where
        O: Into<Bytes>,
        E: From<io::Error>,
    {
        let key_id = stream_buf.decode_u8().await?;
        let kem_id = KemId::try_from_u16(stream_buf.decode_u16().await?)?;
        let kdf_id = KdfId::try_from_u16(stream_buf.decode_u16().await?)?;
        let aead_id = AeadId::try_from_u16(stream_buf.decode_u16().await?)?;

        Ok(Self {
            key_id,
            kem_id,
            kdf_id,
            aead_id,
        })
    }

    pub(crate) fn encoded_len() -> usize {
        // Key ID
        1 +
        // KEM ID
        2 +
        // KFD ID
        2 +
        // AEAD ID
        2
    }

    pub(crate) fn put(&self, octets: &mut OctetsMut<'_>) -> octets::Result<()> {
        octets.put_u8(self.key_id)?;
        octets.put_u16(self.kem_id as u16)?;
        octets.put_u16(self.kdf_id as u16)?;
        octets.put_u16(self.aead_id as u16)?;

        Ok(())
    }

    fn encoded_info_len(request_info_str: &str) -> usize {
        // String
        request_info_str.len() +
        // NUL
        1 +
        // IDs
        Self::encoded_len()
    }

    pub(crate) fn encode_info(&self, request_info_str: &str) -> Vec<u8> {
        let encoded_info_len = Self::encoded_info_len(request_info_str);
        let mut buf = vec![0; encoded_info_len];
        let mut octets = OctetsMut::with_slice(&mut buf);

        self.put_info(request_info_str, &mut octets).unwrap();

        debug_assert_eq!(octets.off(), buf.len());

        buf
    }

    pub(crate) fn put_info(
        &self,
        request_info_str: &str,
        octets: &mut OctetsMut<'_>,
    ) -> octets::Result<()> {
        octets.put_bytes(request_info_str.as_bytes())?;
        octets.put_u8(0)?;

        self.put(octets)?;

        Ok(())
    }
}
