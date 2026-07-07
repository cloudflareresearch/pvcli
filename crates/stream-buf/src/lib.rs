// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use bytes::{Buf, Bytes};
use futures::{future, ready, stream, Stream, StreamExt};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{cmp, io, mem};

const DEFAULT_MAX_BUF_SIZE: usize = 10 * 1024 * 1024;

pub type EmptyStreamBuf<E> = StreamBuf<stream::Empty<Result<Bytes, E>>>;

#[derive(Default, Debug)]
pub struct StreamBuf<S> {
    max_buf_size: usize,
    buf: Bytes,
    stream: S,
}

impl<S, O, E> StreamBuf<S>
where
    S: Stream<Item = Result<O, E>> + Send + Unpin,
    O: Into<Bytes>,
    E: From<io::Error>,
{
    pub fn new(stream: S) -> Self {
        Self {
            max_buf_size: DEFAULT_MAX_BUF_SIZE,
            buf: Default::default(),
            stream,
        }
    }

    /// Sets the maximum buffer size allowed for this `StreamBuf`.
    ///
    /// Defaults to 10MB.
    pub fn max_buf_size(self, max_buf_size: usize) -> Self {
        #[allow(clippy::needless_update)]
        Self {
            max_buf_size,
            ..self
        }
    }

    pub fn poll_read_exact(&mut self, len: usize, cx: &mut Context<'_>) -> Poll<Result<Bytes, E>> {
        loop {
            if self.buf.len() >= len {
                return Poll::Ready(Ok(self.buf.split_to(len)));
            }

            self.check_max_buf_size()?;

            let missing_len = len - self.buf.len();

            let mut more_data = ready!(self.stream.poll_next_unpin(cx))
                .transpose()?
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "could not read exact amount of bytes",
                    )
                })?
                .into();

            if more_data.len() >= missing_len {
                let bytes = if self.buf.is_empty() {
                    debug_assert_eq!(len, missing_len);

                    more_data.split_to(missing_len)
                } else {
                    let bytes = append(mem::take(&mut self.buf), &more_data[..missing_len]);

                    more_data.advance(missing_len);

                    bytes
                };

                self.buf = more_data;

                return Poll::Ready(Ok(bytes));
            }

            self.append(more_data);
        }
    }

    pub async fn read_exact(&mut self, len: usize) -> Result<Bytes, E> {
        future::poll_fn(|cx| self.poll_read_exact(len, cx)).await
    }

    pub fn poll_read_to_end(&mut self, cx: &mut Context<'_>) -> Poll<Result<Bytes, E>> {
        while let Some(more_data) = ready!(self.stream.poll_next_unpin(cx)).transpose()? {
            self.append(more_data.into());
        }

        Poll::Ready(Ok(mem::take(&mut self.buf)))
    }

    pub async fn read_to_end(&mut self) -> Result<Bytes, E> {
        future::poll_fn(|cx| self.poll_read_to_end(cx)).await
    }

    pub fn poll_has_more_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, E>> {
        if !self.buf.is_empty() {
            return Poll::Ready(Ok(true));
        }

        Poll::Ready(Ok(
            if let Some(more_data) = ready!(self.stream.poll_next_unpin(cx)).transpose()? {
                // FIXME(nox): `more_data` can be empty, in which case
                // we don't actually know if there is more data yet.
                self.buf = more_data.into();

                true
            } else {
                false
            },
        ))
    }

    pub async fn has_more_data(&mut self) -> Result<bool, E> {
        future::poll_fn(|cx| self.poll_has_more_data(cx)).await
    }

    pub async fn fill_buf(&mut self) -> Result<(), E> {
        future::poll_fn(|cx| self.poll_fill_buf(cx)).await
    }

    pub fn poll_fill_buf(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), E>> {
        self.check_max_buf_size()?;

        // FIXME(nox): `self.input` may be repeatedly yielding empty chunks.
        let more_data = ready!(self.stream.poll_next_unpin(cx))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "could not accumulate more data",
                )
            })??
            .into();

        self.append(more_data);

        Poll::Ready(Ok(()))
    }

    pub fn poll_read_at_most(
        &mut self,
        len: usize,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Bytes, E>> {
        if len == 0 {
            return Poll::Ready(Ok(Default::default()));
        }

        if self.buf.is_empty() {
            ready!(self.poll_fill_buf(cx))?;
        }

        Poll::Ready(Ok(self.buf.split_to(cmp::min(len, self.buf.len()))))
    }

    fn check_max_buf_size(&self) -> Result<(), E> {
        if self.buf.len() > self.max_buf_size {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "max buf size reached").into());
        }

        Ok(())
    }

    fn append(&mut self, more_data: Bytes) {
        if self.buf.is_empty() {
            self.buf = more_data;
        } else {
            // NOTE(nox): This can exceed `max_buf_size`, we will return
            // `UnexpectedEof` next time if `poll_fill_buf` is called again
            // if `self.buf` has not been advanced to a size below `max_buf_size`.
            self.buf = append(mem::take(&mut self.buf), &more_data);
        }
    }
}

impl<E> From<Bytes> for EmptyStreamBuf<E>
where
    E: From<io::Error>,
{
    fn from(buf: Bytes) -> Self {
        StreamBuf {
            max_buf_size: buf.len(),
            buf,
            stream: stream::empty(),
        }
    }
}

impl<S, O, E> Buf for StreamBuf<S>
where
    S: Stream<Item = Result<O, E>> + Send + Unpin,
    O: Into<Bytes>,
{
    fn remaining(&self) -> usize {
        self.buf.remaining()
    }

    fn chunk(&self) -> &[u8] {
        self.buf.chunk()
    }

    fn advance(&mut self, cnt: usize) {
        self.buf.advance(cnt)
    }

    fn copy_to_bytes(&mut self, len: usize) -> bytes::Bytes {
        self.buf.copy_to_bytes(len)
    }
}

impl<S, O, E> Stream for StreamBuf<S>
where
    S: Stream<Item = Result<O, E>> + Send + Unpin,
    O: Into<Bytes>,
    E: From<io::Error>,
{
    type Item = Result<Bytes, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;

        if !this.buf.is_empty() {
            return Poll::Ready(Some(Ok(mem::take(&mut this.buf))));
        }

        Poll::Ready(ready!(this.stream.poll_next_unpin(cx)?).map(|bytes| Ok(bytes.into())))
    }
}

fn append(data: Bytes, more_data: &[u8]) -> Bytes {
    let mut buf = Vec::from(data);

    buf.extend_from_slice(more_data);

    buf.into()
}
