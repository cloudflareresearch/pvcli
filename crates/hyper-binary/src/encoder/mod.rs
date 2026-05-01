use crate::invalid_data;
use bytes::Bytes;
use futures::{ready, Stream};
use http::uri::Scheme;
use http_body_util::BodyDataStream;
use hyper::body::Body;
use hyper::http::{request, response};
use hyper::{header, HeaderMap, Request, Response};
use octets::OctetsMut;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

pub fn encode_request<B>(res: Request<B>) -> io::Result<EncodedMessage<B>>
where
    B: Body + Unpin,
    <B as Body>::Data: Into<Bytes>,
{
    // TODO(nox): Support encoding as a known-length response
    // if `size_hint` is exact.
    let kind = EncodedMessageKind::IndeterminateLength;
    let (parts, body) = res.into_parts();

    // NOTE(nox): We immediately build the initial chunk here with the
    // method, URI and request headers, maybe we could be more fine-grained
    // by encoding the headers in `poll_data` until we reach a configurable
    // max chunk size.
    let initial_chunk = match kind {
        EncodedMessageKind::IndeterminateLength => {
            initial_indeterminate_length_request_chunk(&parts)?
        }
        #[allow(
            clippy::todo,
            reason = "encode_request is only used in cf-ohttp-client, which is only used in tests"
        )]
        EncodedMessageKind::KnownLength => todo!(),
    };

    Ok(EncodedMessage {
        kind,
        initial_chunk: Some(initial_chunk),
        body,
        end_of_content: false,
    })
}

pub fn encode_response<B>(res: Response<B>) -> EncodedMessage<B>
where
    B: Body + Unpin,
    <B as Body>::Data: Into<Bytes>,
{
    let (parts, body) = res.into_parts();

    // NOTE(nox): We immediately build the initial chunk here with the
    // status code and the response headers, maybe we could be more
    // fine-grained by encoding the headers in `poll_data` until we
    // reach a configurable max chunk size.
    let (kind, initial_chunk) = if let Some(size) = body.size_hint().exact() {
        (
            EncodedMessageKind::KnownLength,
            initial_known_length_response_chunk(&parts, size),
        )
    } else {
        (
            EncodedMessageKind::IndeterminateLength,
            initial_indeterminate_length_response_chunk(&parts),
        )
    };

    EncodedMessage {
        kind,
        initial_chunk: Some(initial_chunk),
        body,
        end_of_content: false,
    }
}

#[derive(Debug)]
pub struct EncodedMessage<B> {
    kind: EncodedMessageKind,
    initial_chunk: Option<Bytes>,
    body: B,
    end_of_content: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum EncodedMessageKind {
    IndeterminateLength,
    // FIXME: keep track of the expected body length to make sure inner
    // bodies do not misbehave.
    KnownLength,
}

impl<B> EncodedMessage<B> {
    pub fn kind(&self) -> EncodedMessageKind {
        self.kind
    }
}

impl<B> Stream for EncodedMessage<B>
where
    B: Body + Unpin,
    <B as Body>::Data: Into<Bytes>,
{
    type Item = Result<Bytes, B::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;

        if this.end_of_content {
            return Poll::Ready(None);
        }

        if let Some(chunk) = this.initial_chunk.take() {
            return Poll::Ready(Some(Ok(chunk)));
        }

        let chunk = match ready!(Pin::new(&mut BodyDataStream::new(&mut this.body)).poll_next(cx)) {
            Some(Ok(chunk)) => chunk.into(),
            Some(Err(e)) => return Poll::Ready(Some(Err(e))),
            None => {
                this.end_of_content = true;

                return Poll::Ready(match this.kind {
                    EncodedMessageKind::IndeterminateLength => Some(Ok([0][..].into())),
                    EncodedMessageKind::KnownLength => None,
                });
            }
        };

        Poll::Ready(Some(Ok(match this.kind {
            EncodedMessageKind::KnownLength => {
                return Poll::Ready(Some(Ok(chunk)));
            }
            EncodedMessageKind::IndeterminateLength => {
                // NOTE(nox): There is no way to encode an empty content chunk
                // with indeterminate-length contents, so we just return the
                // empty chunk without encoding its length.
                if chunk.is_empty() {
                    return Poll::Ready(Some(Ok(chunk)));
                }

                // NOTE(nox): We first return a chunk whose contents are the length of the
                // actual chunk as a varint, and next time `poll_data` is called, we return
                // the actual chunk.
                let chunk_len = chunk.len() as u64;
                let encoded_chunk_len = octets::varint_len(chunk_len);
                let mut encoded_chunk = vec![0; encoded_chunk_len + chunk.len()];

                {
                    let mut octets = OctetsMut::with_slice(&mut encoded_chunk[..encoded_chunk_len]);

                    octets.put_varint(chunk_len).unwrap();

                    debug_assert_eq!(encoded_chunk_len, octets.off());
                }

                encoded_chunk[encoded_chunk_len..].copy_from_slice(&chunk);

                encoded_chunk.into()
            }
        })))
    }
}

fn initial_indeterminate_length_request_chunk(parts: &request::Parts) -> io::Result<Bytes> {
    let scheme = parts
        .uri
        .scheme()
        .ok_or_else(|| invalid_data("request has no scheme"))?;

    let host = parts
        .headers
        .get(header::HOST)
        .map(|header| header.as_bytes());

    let authority = parts
        .uri
        .authority()
        .map(|authority| authority.as_str().as_bytes())
        .filter(|authority| host.is_none_or(|host| host != *authority))
        .unwrap_or_default();

    let framing_indicator = 2;
    let field_section_content_terminator = 0;

    // todo(fisher): fix length estimation due to potentially using the `Host`
    // header rather than the `authority` header.
    let initial_chunk_len =
        // Framing Indicator
        octets::varint_len(framing_indicator) +
        // Request Control Data
        request_control_data_len(parts, scheme, authority) +
        // Field Section Field Lines
        field_lines_len(&parts.headers) +
        // Field Section Content Terminator
        octets::varint_len(field_section_content_terminator);

    let mut initial_chunk = vec![0; initial_chunk_len];
    let mut octets = OctetsMut::with_slice(&mut initial_chunk);

    // todo(fisher):
    put_request_parts(&mut octets, parts, scheme, authority).unwrap();
    let offset = octets.off();

    initial_chunk.truncate(offset);

    Ok(initial_chunk.into())
}

fn request_control_data_len(parts: &request::Parts, scheme: &Scheme, authority: &[u8]) -> usize {
    let scheme_len = scheme.as_str().len();
    // Method Length
    let mut total = octets::varint_len(parts.method.as_str().len() as u64) +

    // Method
    parts.method.as_str().len() +

    // Scheme Length
    octets::varint_len(scheme_len as u64) +

    // Scheme
    scheme_len +

    // Authority Length
    octets::varint_len(authority.len() as u64) +

    // Authority
    authority.len();

    if let Some(query) = parts.uri.query() {
        // Path + Query Length
        let path_and_query_len = parts.uri.path().len() + "?".len() + query.len();

        total += octets::varint_len(path_and_query_len as u64) + path_and_query_len;
    } else {
        total +=
            // Path Length
            octets::varint_len(parts.uri.path().len() as u64) +

            // Path
            parts.uri.path().len();
    }
    total
}

fn put_request_parts(
    octets: &mut OctetsMut<'_>,
    parts: &request::Parts,
    scheme: &Scheme,
    authority: &[u8],
) -> octets::Result<()> {
    let framing_indicator = 2;
    let field_section_content_terminator = 0;

    // Framing Indiciator
    octets.put_varint(framing_indicator)?;

    // Request Control Data
    put_request_control_data(octets, parts, scheme, authority)?;

    // Field Section (headers)
    put_field_lines(octets, &parts.headers)?;

    // Field Section Content Terminator
    octets.put_varint(field_section_content_terminator)?;

    Ok(())
}

fn put_request_control_data(
    octets: &mut OctetsMut<'_>,
    parts: &request::Parts,
    scheme: &Scheme,
    authority: &[u8],
) -> octets::Result<()> {
    // Method Length
    octets.put_varint(parts.method.as_str().len() as u64)?;

    // Method
    octets.put_bytes(parts.method.as_str().as_bytes())?;

    // Scheme Length
    octets.put_varint(scheme.as_str().len() as u64)?;

    // Scheme
    octets.put_bytes(scheme.as_str().as_bytes())?;

    // Authority Length
    octets.put_varint(authority.len() as u64)?;

    // Authority
    octets.put_bytes(authority)?;

    if let Some(query) = parts.uri.query() {
        // Path + Query
        let path_and_query = [parts.uri.path().as_bytes(), b"?", query.as_bytes()];
        octets.put_varint(path_and_query.iter().map(|l| l.len()).sum::<usize>() as u64)?;
        path_and_query
            .iter()
            .try_for_each(|b| octets.put_bytes(b))?;
    } else {
        // Path Length
        octets.put_varint(parts.uri.path().len() as u64)?;

        // Path
        octets.put_bytes(parts.uri.path().as_bytes())?;
    }

    Ok(())
}

fn initial_indeterminate_length_response_chunk(parts: &response::Parts) -> Bytes {
    let framing_indicator = 3;
    let status_code = parts.status.as_u16() as u64;
    let field_section_content_terminator = 0;

    let initial_chunk_len =
        // Framing Indicator
        octets::varint_len(framing_indicator) +
        // Status Code
        octets::varint_len(status_code) +
        // Field Section Field Lines
        field_lines_len(&parts.headers) +
        // Field Section Content Terminator
        octets::varint_len(field_section_content_terminator);

    let mut initial_chunk = vec![0; initial_chunk_len];
    let mut octets = OctetsMut::with_slice(&mut initial_chunk);

    // NOTE(nox): We have initialized `initial_chunk` to be the
    // exact length required for the things we will put in it,
    // so this `unwrap` call should never panic.
    put_indeterminate_length_response_parts(&mut octets, parts).unwrap();

    // NOTE(nox): This checks that we did not overestimate the length
    // of the initial chunk (an underestimation would have caused
    // the `unwrap` call above to panic).
    debug_assert_eq!(initial_chunk_len, octets.off());

    initial_chunk.into()
}

fn initial_known_length_response_chunk(parts: &response::Parts, size: u64) -> Bytes {
    let framing_indicator = 1;
    let status_code = parts.status.as_u16() as u64;
    let field_line_len = field_lines_len(&parts.headers);

    let initial_chunk_len =
        // Framing Indicator
        octets::varint_len(framing_indicator) +
        // Status Code
        octets::varint_len(status_code) +
        // Length of field section
        octets::varint_len(field_line_len as u64) +
        // Field Section Field Lines
        field_line_len +
        // Content Length
        octets::varint_len(size);

    let mut initial_chunk = vec![0; initial_chunk_len];
    let mut octets = OctetsMut::with_slice(&mut initial_chunk);

    // NOTE(nox): We have initialized `initial_chunk` to be the
    // exact length required for the things we will put in it,
    // so this `unwrap` call should never panic.
    put_known_length_response_parts(&mut octets, parts).unwrap();

    // we write the body's size here, so to simplify logic in the body stream
    // encoder.
    octets.put_varint(size).unwrap();

    // NOTE(nox): This checks that we did not overestimate the length
    // of the initial chunk (an underestimation would have caused
    // the `unwrap` call above to panic).
    debug_assert_eq!(initial_chunk_len, octets.off());

    initial_chunk.into()
}

fn put_known_length_response_parts(
    octets: &mut OctetsMut<'_>,
    parts: &response::Parts,
) -> octets::Result<()> {
    let framing_indicator = 1;
    let status_code = parts.status.as_u16() as u64;

    octets.put_varint(framing_indicator)?;
    octets.put_varint(status_code)?;

    let field_line_len = field_lines_len(&parts.headers);

    octets.put_varint(field_line_len as u64)?;
    put_field_lines(octets, &parts.headers)?;

    Ok(())
}

fn put_indeterminate_length_response_parts(
    octets: &mut OctetsMut<'_>,
    parts: &response::Parts,
) -> octets::Result<()> {
    let framing_indicator = 3;
    let status_code = parts.status.as_u16() as u64;
    let field_section_content_terminator = 0;

    octets.put_varint(framing_indicator)?;
    octets.put_varint(status_code)?;

    put_field_lines(octets, &parts.headers)?;

    octets.put_varint(field_section_content_terminator)?;

    Ok(())
}

fn field_lines_len(headers: &HeaderMap) -> usize {
    headers
        .iter()
        .map(|(name, value)| {
            // Name Length
            octets::varint_len(name.as_str().as_bytes().len() as u64) +
            // Name
            name.as_str().as_bytes().len() +
            // Value Length
            octets::varint_len(value.as_bytes().len() as u64) +
            // Value
            value.as_bytes().len()
        })
        .sum()
}

fn put_field_lines(octets: &mut OctetsMut<'_>, headers: &HeaderMap) -> octets::Result<()> {
    for (name, value) in headers.iter() {
        octets.put_varint(name.as_str().as_bytes().len() as u64)?;
        octets.put_bytes(name.as_str().as_bytes())?;
        octets.put_varint(value.as_bytes().len() as u64)?;
        octets.put_bytes(value.as_bytes())?;
    }

    Ok(())
}
