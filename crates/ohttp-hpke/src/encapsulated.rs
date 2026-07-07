// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use crate::invalid_data;
use crate::response::AeadTag;
use bytes::Bytes;
use futures::{ready, Stream, StreamExt};
use hpke::HpkeError;
use octets::OctetsMut;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{fmt, io, mem};
use stream_buf::StreamBuf;

pub(crate) struct Encapsulated<Se, St> {
    state: State,
    sealer: Se,
    chunk: Option<Bytes>,
    stream_buf: StreamBuf<St>,
}

impl<Se, St> Encapsulated<Se, St>
where
    Se: fmt::Debug,
    St: fmt::Debug,
{
    pub(crate) fn fmt(&self, f: &mut fmt::Formatter<'_>, name: &str) -> fmt::Result {
        f.debug_struct(name)
            .field("state", &self.state)
            .field("sealer", &self.sealer)
            .field("chunk", &self.chunk)
            .field("stream_buf", &self.stream_buf)
            .finish()
    }
}

impl<Se, St, T, E> Encapsulated<Se, St>
where
    Se: SealInPlace + Unpin,
    St: Stream<Item = Result<T, E>> + Send + Unpin,
    T: Into<Bytes>,
    E: From<io::Error>,
{
    pub(crate) fn non_chunked(sealer: Se, initial_chunk: Bytes, stream_buf: StreamBuf<St>) -> Self {
        Self {
            sealer,
            chunk: Some(initial_chunk),
            state: State::NonChunked,
            stream_buf,
        }
    }

    pub(crate) fn chunked(sealer: Se, initial_chunk: Bytes, stream_buf: StreamBuf<St>) -> Self {
        Self {
            sealer,
            chunk: Some(initial_chunk),
            state: State::Chunked(ChunkState::ChunkLen),
            stream_buf,
        }
    }
}

pub(crate) trait SealInPlace: fmt::Debug + Send + Sync {
    fn seal_in_place(&mut self, plaintext: &mut [u8], aad: &[u8]) -> Result<AeadTag, HpkeError>;
}

impl SealInPlace for Box<dyn SealInPlace> {
    fn seal_in_place(&mut self, plaintext: &mut [u8], aad: &[u8]) -> Result<AeadTag, HpkeError> {
        (**self).seal_in_place(plaintext, aad)
    }
}

#[derive(Debug)]
enum State {
    NonChunked,
    Chunked(ChunkState),
    Done,
}

#[derive(Debug)]
enum ChunkState {
    ChunkLen,
    Tag(AeadTag),
}

impl<Se, T, E, St> Stream for Encapsulated<Se, St>
where
    Se: SealInPlace + Unpin,
    St: Stream<Item = Result<T, E>> + Send + Unpin,
    T: Into<Bytes>,
    E: From<io::Error>,
{
    type Item = Result<Bytes, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;

        if let Some(chunk) = this.chunk.take() {
            return Poll::Ready(Some(Ok(chunk)));
        }

        Poll::Ready(match &mut this.state {
            State::NonChunked => {
                let mut content = Vec::from(ready!(this.stream_buf.poll_read_to_end(cx))?);

                let aead_tag = this
                    .sealer
                    .seal_in_place(&mut content, b"")
                    .map_err(|e| invalid_data(format!("could not seal content ({e})")))?;

                this.chunk = Some(aead_tag.0.into());
                this.state = State::Done;

                Some(Ok(content.into()))
            }
            State::Chunked(chunk_state) => match mem::replace(chunk_state, ChunkState::ChunkLen) {
                ChunkState::ChunkLen => {
                    let Some(chunk) = ready!(this.stream_buf.poll_next_unpin(cx)?) else {
                        let aead_tag = this
                            .sealer
                            .seal_in_place(&mut [], b"final")
                            .map_err(|e| invalid_data(format!("could not seal content ({e})")))?;

                        let final_response_chunk_indicator = encoded_len(0);

                        this.chunk = Some(aead_tag.0.into());
                        this.state = State::Done;

                        return Poll::Ready(Some(Ok(final_response_chunk_indicator)));
                    };

                    if chunk.is_empty() {
                        return Poll::Ready(Some(Ok(chunk)));
                    }

                    let mut chunk = Vec::from(chunk);

                    let aead_tag = this
                        .sealer
                        .seal_in_place(&mut chunk, b"")
                        .map_err(|e| invalid_data(format!("could not seal content ({e})")))?;

                    let encoded_sealed_chunk_len = encoded_len(chunk.len() + aead_tag.0.len());

                    this.chunk = Some(chunk.into());
                    *chunk_state = ChunkState::Tag(aead_tag);

                    Some(Ok(encoded_sealed_chunk_len))
                }
                ChunkState::Tag(aead_tag) => Some(Ok(aead_tag.0.into())),
            },
            State::Done => None,
        })
    }
}

fn encoded_len(len: usize) -> Bytes {
    let encoded_len = octets::varint_len(len as u64);
    let mut buf = vec![0; encoded_len];
    let mut octets = OctetsMut::with_slice(&mut buf);

    octets.put_varint(len as u64).unwrap();

    debug_assert_eq!(encoded_len, octets.off());

    buf.into()
}
