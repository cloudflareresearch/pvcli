use crate::invalid_data;
use bytes::Bytes;
use futures::{ready, Stream};
use hpke::HpkeError;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{fmt, io};
use stream_buf::StreamBuf;
use stream_octets::StreamBufExt;

pub(crate) struct Decapsulated<O, S> {
    state: State,
    opener: O,
    stream_buf: StreamBuf<S>,
}

#[derive(Debug)]
enum State {
    ChunkLen,
    Chunk(Option<NonZeroUsize>),
    Done,
}

impl<O, S> Decapsulated<O, S>
where
    O: fmt::Debug,
    S: fmt::Debug,
{
    pub(crate) fn fmt(&self, f: &mut fmt::Formatter<'_>, name: &str) -> fmt::Result {
        f.debug_struct(name)
            .field("state", &self.state)
            .field("opener", &self.opener)
            .field("stream_buf", &self.stream_buf)
            .finish()
    }
}

impl<O, S, T, E> Decapsulated<O, S>
where
    O: OpenInPlace,
    S: Stream<Item = Result<T, E>> + Unpin,
    T: Into<Bytes>,
    E: From<io::Error>,
{
    pub(crate) fn new(opener: O, stream_buf: StreamBuf<S>) -> Self {
        Self {
            state: State::ChunkLen,
            opener,
            stream_buf,
        }
    }
}

pub(crate) trait OpenInPlace: fmt::Debug + Send + Sync {
    fn open_in_place<'a>(
        &mut self,
        ciphertext: &'a mut [u8],
        aad: &[u8],
    ) -> Result<&'a mut [u8], HpkeError>;
}

impl OpenInPlace for Box<dyn OpenInPlace> {
    fn open_in_place<'a>(
        &mut self,
        ciphertext: &'a mut [u8],
        aad: &[u8],
    ) -> Result<&'a mut [u8], HpkeError> {
        (**self).open_in_place(ciphertext, aad)
    }
}

impl<O, S, T, E> Stream for Decapsulated<O, S>
where
    O: OpenInPlace + Unpin,
    S: Stream<Item = Result<T, E>> + Send + Unpin,
    T: Into<Bytes>,
    E: From<io::Error>,
{
    type Item = Result<Bytes, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;

        let (aad, chunk) = loop {
            match &this.state {
                State::ChunkLen => {
                    let len = ready!(this.stream_buf.poll_decode_varint_usize(cx))?;

                    this.state = State::Chunk(NonZeroUsize::new(len));
                }
                State::Chunk(Some(len)) => {
                    let chunk = ready!(this.stream_buf.poll_read_exact(len.get(), cx))?;

                    this.state = State::ChunkLen;

                    break ("", chunk);
                }
                State::Chunk(None) => {
                    let chunk = ready!(this.stream_buf.poll_read_to_end(cx))?;

                    this.state = State::Done;

                    break ("final", chunk);
                }
                State::Done => return Poll::Ready(None),
            }
        };

        let mut chunk = Vec::from(chunk);

        let opened_len = self
            .opener
            .open_in_place(&mut chunk, aad.as_bytes())
            .map_err(|e| invalid_data(format!("could not open chunk ({e})")))?
            .len();
        chunk.truncate(opened_len);

        Poll::Ready(Some(Ok(chunk.into())))
    }
}
