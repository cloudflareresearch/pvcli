use bytes::{Buf, Bytes};
use futures::{future, ready, Stream};
use octets::Octets;
use std::io;
use std::task::{Context, Poll};
use stream_buf::StreamBuf;

pub trait StreamBufExt {
    type Error;

    fn poll_decode_u8(&mut self, cx: &mut Context<'_>) -> Poll<Result<u8, Self::Error>>;
    fn decode_u8(&mut self) -> impl std::future::Future<Output = Result<u8, Self::Error>> + Send;

    fn poll_decode_u16(&mut self, cx: &mut Context<'_>) -> Poll<Result<u16, Self::Error>>;
    fn decode_u16(&mut self) -> impl std::future::Future<Output = Result<u16, Self::Error>> + Send;

    fn poll_decode_u32(&mut self, cx: &mut Context<'_>) -> Poll<Result<u32, Self::Error>>;
    fn decode_u32(&mut self) -> impl std::future::Future<Output = Result<u32, Self::Error>> + Send;

    fn poll_decode_u64(&mut self, cx: &mut Context<'_>) -> Poll<Result<u64, Self::Error>>;
    fn decode_u64(&mut self) -> impl std::future::Future<Output = Result<u64, Self::Error>> + Send;

    fn poll_decode_varint_u64(&mut self, cx: &mut Context<'_>) -> Poll<Result<u64, Self::Error>>;

    fn decode_varint_u64(
        &mut self,
    ) -> impl std::future::Future<Output = Result<u64, Self::Error>> + Send;

    fn poll_decode_varint_usize(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<usize, Self::Error>>;

    fn decode_varint_usize(
        &mut self,
    ) -> impl std::future::Future<Output = Result<usize, Self::Error>> + Send;

    fn read_with_varint_length(
        &mut self,
    ) -> impl std::future::Future<Output = Result<Bytes, Self::Error>> + Send;
}

impl<S, O, E> StreamBufExt for StreamBuf<S>
where
    S: Stream<Item = Result<O, E>> + Send + Unpin,
    O: Into<Bytes>,
    E: From<io::Error>,
{
    type Error = E;

    fn poll_decode_u8(&mut self, cx: &mut Context<'_>) -> Poll<Result<u8, E>> {
        poll_with_octets(self, cx, |octets| octets.get_u8())
    }

    async fn decode_u8(&mut self) -> Result<u8, E> {
        future::poll_fn(|cx| self.poll_decode_u8(cx)).await
    }

    fn poll_decode_u16(&mut self, cx: &mut Context<'_>) -> Poll<Result<u16, E>> {
        poll_with_octets(self, cx, |octets| octets.get_u16())
    }

    async fn decode_u16(&mut self) -> Result<u16, E> {
        future::poll_fn(|cx| self.poll_decode_u16(cx)).await
    }

    fn poll_decode_u32(&mut self, cx: &mut Context<'_>) -> Poll<Result<u32, E>> {
        poll_with_octets(self, cx, |octets| octets.get_u32())
    }

    async fn decode_u32(&mut self) -> Result<u32, E> {
        future::poll_fn(|cx| self.poll_decode_u32(cx)).await
    }

    fn poll_decode_u64(&mut self, cx: &mut Context<'_>) -> Poll<Result<u64, E>> {
        poll_with_octets(self, cx, |octets| octets.get_u64())
    }

    async fn decode_u64(&mut self) -> Result<u64, E> {
        future::poll_fn(|cx| self.poll_decode_u64(cx)).await
    }

    fn poll_decode_varint_u64(&mut self, cx: &mut Context<'_>) -> Poll<Result<u64, E>> {
        poll_with_octets(self, cx, |octets| octets.get_varint())
    }

    async fn decode_varint_u64(&mut self) -> Result<u64, E> {
        future::poll_fn(|cx| self.poll_decode_varint_u64(cx)).await
    }

    fn poll_decode_varint_usize(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize, E>> {
        Poll::Ready(Ok(usize::try_from(
            ready!(self.poll_decode_varint_u64(cx))?,
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?))
    }

    async fn decode_varint_usize(&mut self) -> Result<usize, E> {
        future::poll_fn(|cx| self.poll_decode_varint_usize(cx)).await
    }

    async fn read_with_varint_length(&mut self) -> Result<Bytes, E> {
        let len = self.decode_varint_usize().await?;

        self.read_exact(len).await
    }
}

fn poll_with_octets<S, O, E, T>(
    stream_buf: &mut StreamBuf<S>,
    cx: &mut Context<'_>,
    f: impl Fn(&mut Octets<'_>) -> octets::Result<T>,
) -> Poll<Result<T, E>>
where
    S: Stream<Item = Result<O, E>> + Send + Unpin,
    O: Into<Bytes>,
    E: From<io::Error>,
{
    loop {
        let mut octets = Octets::with_slice(stream_buf.chunk());

        if let Ok(value) = f(&mut octets) {
            stream_buf.advance(octets.off());

            return Poll::Ready(Ok(value));
        }

        ready!(stream_buf.poll_fill_buf(cx))?;
    }
}
