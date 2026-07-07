// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use bytes::Bytes;
use futures::{ready, Stream};
use hyper::body::{Body, Frame, SizeHint};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{cmp, io};
use stream_buf::StreamBuf;
use stream_octets::StreamBufExt;

#[derive(Debug)]
pub struct DecodedBody<S> {
    kind: DecodedBodyKind,
    stream_buf: StreamBuf<S>,
}

impl<S, O, E> DecodedBody<S>
where
    S: Stream<Item = Result<O, E>> + Send + Unpin,
    O: Into<Bytes>,
    E: From<io::Error>,
{
    pub(super) async fn known_length(mut stream_buf: StreamBuf<S>) -> Result<Self, E> {
        let remaining = if stream_buf.has_more_data().await? {
            stream_buf.decode_varint_u64().await?
        } else {
            0
        };

        Ok(Self {
            kind: DecodedBodyKind::KnownLength { remaining },
            stream_buf,
        })
    }

    pub(super) fn indeterminate_length(stream_buf: StreamBuf<S>) -> Self {
        Self {
            kind: DecodedBodyKind::IndeterminateLength {
                remaining_in_current_chunk: Some(0),
            },
            stream_buf,
        }
    }
}

#[derive(Debug)]
enum DecodedBodyKind {
    KnownLength {
        remaining: u64,
    },
    IndeterminateLength {
        remaining_in_current_chunk: Option<u64>,
    },
}

impl<S, O, E> Body for DecodedBody<S>
where
    S: Stream<Item = Result<O, E>> + Send + Unpin,
    O: Into<Bytes>,
    E: From<io::Error>,
{
    type Data = Bytes;
    type Error = E;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;

        let remaining = match &mut this.kind {
            DecodedBodyKind::KnownLength { remaining: 0 }
            | DecodedBodyKind::IndeterminateLength {
                remaining_in_current_chunk: None,
            } => return Poll::Ready(None),
            DecodedBodyKind::IndeterminateLength {
                remaining_in_current_chunk: remaining_in_current_chunk @ Some(0),
            } => {
                let remaining = if !ready!(this.stream_buf.poll_has_more_data(cx))? {
                    0
                } else {
                    ready!(this.stream_buf.poll_decode_varint_u64(cx))?
                };

                if remaining == 0 {
                    *remaining_in_current_chunk = None;

                    return Poll::Ready(None);
                }

                remaining_in_current_chunk.insert(remaining)
            }
            DecodedBodyKind::KnownLength { remaining }
            | DecodedBodyKind::IndeterminateLength {
                remaining_in_current_chunk: Some(remaining),
            } => remaining,
        };

        let bytes = ready!(poll_read_at_most(remaining, &mut this.stream_buf, cx))?;

        Poll::Ready(Some(Ok(Frame::data(bytes))))
    }

    fn is_end_stream(&self) -> bool {
        matches!(
            self.kind,
            DecodedBodyKind::KnownLength { remaining: 0 }
                | DecodedBodyKind::IndeterminateLength {
                    remaining_in_current_chunk: None,
                }
        )
    }

    fn size_hint(&self) -> SizeHint {
        match self.kind {
            DecodedBodyKind::KnownLength { remaining } => SizeHint::with_exact(remaining),
            DecodedBodyKind::IndeterminateLength { .. } => SizeHint::default(),
        }
    }
}

fn poll_read_at_most<S, O, E>(
    remaining: &mut u64,
    stream_buf: &mut StreamBuf<S>,
    cx: &mut Context<'_>,
) -> Poll<Result<Bytes, E>>
where
    S: Stream<Item = Result<O, E>> + Send + Unpin,
    O: Into<Bytes>,
    E: From<io::Error>,
{
    let bytes =
        ready!(stream_buf.poll_read_at_most(cmp::min(*remaining, usize::MAX as u64) as usize, cx))?;

    *remaining -= bytes.len() as u64;

    Poll::Ready(Ok(bytes))
}
