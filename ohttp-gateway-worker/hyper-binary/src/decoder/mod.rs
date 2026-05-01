use crate::invalid_data;
use bytes::Bytes;
use futures::Stream;
use hyper::body::Buf;
use hyper::header::{HeaderName, HeaderValue};
use hyper::http::uri::{self, Authority, PathAndQuery, Scheme};
use hyper::http::{Method, Request, Uri};
use hyper::{header, HeaderMap, Response, StatusCode};
use octets::Octets;
use std::io;
use stream_buf::StreamBuf;
use stream_octets::StreamBufExt;

mod body;

pub use self::body::DecodedBody;

pub async fn decode_request<S, O, E>(
    mut stream_buf: StreamBuf<S>,
) -> Result<Request<DecodedBody<S>>, E>
where
    S: Stream<Item = Result<O, E>> + Send + Unpin,
    O: Into<Bytes>,
    E: From<io::Error>,
{
    let framing_indicator = stream_buf.decode_varint_u64().await?;

    match framing_indicator {
        0 => decode_known_length_request(stream_buf).await,
        2 => decode_indeterminate_length_request(stream_buf).await,
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "invalid framing indicator").into()),
    }
}

pub async fn decode_response<S, O, E>(
    mut stream_buf: StreamBuf<S>,
) -> Result<Response<DecodedBody<S>>, E>
where
    S: Stream<Item = Result<O, E>> + Send + Unpin,
    O: Into<Bytes>,
    E: From<io::Error>,
{
    let framing_indicator = stream_buf.decode_varint_u64().await?;

    match framing_indicator {
        1 => decode_known_length_response(stream_buf).await,
        3 => decode_indeterminate_length_response(stream_buf).await,
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "invalid framing indicator").into()),
    }
}

#[derive(Debug)]
struct RequestControlData {
    method: Method,
    scheme: Scheme,
    authority: Option<Authority>,
    path: PathAndQuery,
}

// https://www.rfc-editor.org/rfc/rfc9292.html#name-request-control-data:~:text=Known%2DLength%20Request%20%7B
async fn decode_known_length_request<S, O, E>(
    mut stream_buf: StreamBuf<S>,
) -> Result<Request<DecodedBody<S>>, E>
where
    S: Stream<Item = Result<O, E>> + Send + Unpin,
    O: Into<Bytes>,
    E: From<io::Error>,
{
    let request_control_data = decode_request_control_data(&mut stream_buf).await?;

    let field_section = decode_known_length_field_section(&mut stream_buf).await?;
    let body = DecodedBody::known_length(stream_buf).await?;

    request(request_control_data, field_section, body).map_err(E::from)
}

// https://www.rfc-editor.org/rfc/rfc9292.html#name-request-control-data:~:text=Known%2DLength%20Field%20Section%20%7B
async fn decode_known_length_field_section<O, E>(
    stream_buf: &mut StreamBuf<impl Stream<Item = Result<O, E>> + Send + Unpin>,
) -> Result<HeaderMap, E>
where
    O: Into<Bytes>,
    E: From<io::Error>,
{
    if !stream_buf.has_more_data().await? {
        return Ok(Default::default());
    }

    // FIXME(nox): This code shouldn't have to buffer the entire field section.
    let mut buf = stream_buf.read_with_varint_length().await?;
    let mut headers = HeaderMap::default();

    fn decode_varint_u64(buf: &mut Bytes) -> octets::Result<u64> {
        let mut octets = Octets::with_slice(buf);
        let value = octets.get_varint()?;

        buf.advance(octets.off());

        Ok(value)
    }

    while !buf.is_empty() {
        let name_length = usize::try_from(decode_varint_u64(&mut buf).map_err(invalid_data)?)
            .map_err(invalid_data)?;

        if buf.len() < name_length {
            return Err(invalid_data("could not decode field name").into());
        }

        let name = HeaderName::try_from(&*buf.split_to(name_length)).map_err(invalid_data)?;

        let value_length = usize::try_from(decode_varint_u64(&mut buf).map_err(invalid_data)?)
            .map_err(invalid_data)?;

        if buf.len() < value_length {
            return Err(invalid_data("could not decode field value").into());
        }

        let value =
            HeaderValue::from_maybe_shared(buf.split_to(value_length)).map_err(invalid_data)?;

        headers.append(name, value);
    }

    Ok(headers)
}

// https://www.rfc-editor.org/rfc/rfc9292.html#name-request-control-data:~:text=Indeterminate%2DLength%20Request%20%20%7B
async fn decode_indeterminate_length_request<S, O, E>(
    mut stream_buf: StreamBuf<S>,
) -> Result<Request<DecodedBody<S>>, E>
where
    S: Stream<Item = Result<O, E>> + Send + Unpin,
    O: Into<Bytes>,
    E: From<io::Error>,
{
    let request_control_data = decode_request_control_data(&mut stream_buf).await?;
    let field_section = decode_indeterminate_length_field_section(&mut stream_buf).await?;
    let body = DecodedBody::indeterminate_length(stream_buf);

    request(request_control_data, field_section, body).map_err(E::from)
}

// https://www.rfc-editor.org/rfc/rfc9292.html#name-indeterminate-length-messag:~:text=Indeterminate%2DLength%20Field%20Section%20%7B
async fn decode_indeterminate_length_field_section<O, E>(
    stream_buf: &mut StreamBuf<impl Stream<Item = Result<O, E>> + Send + Unpin>,
) -> Result<HeaderMap, E>
where
    O: Into<Bytes>,
    E: From<io::Error>,
{
    let mut headers = HeaderMap::default();

    loop {
        if !stream_buf.has_more_data().await? {
            return Ok(headers);
        }

        let name_length = match stream_buf.decode_varint_usize().await? {
            0 => return Ok(headers),
            len => len,
        };

        let name = HeaderName::try_from(&*stream_buf.read_exact(name_length).await?)
            .map_err(invalid_data)?;

        let value = HeaderValue::from_maybe_shared(stream_buf.read_with_varint_length().await?)
            .map_err(invalid_data)?;

        // NOTE(fisher): try_append was replaced with append. http 1.0 api...?
        headers.append(name, value);
    }
}

// https://www.rfc-editor.org/rfc/rfc9292.html#name-request-control-data
async fn decode_request_control_data<O, E>(
    stream_buf: &mut StreamBuf<impl Stream<Item = Result<O, E>> + Send + Unpin>,
) -> Result<RequestControlData, E>
where
    O: Into<Bytes>,
    E: From<io::Error>,
{
    let method =
        Method::try_from(&*stream_buf.read_with_varint_length().await?).map_err(invalid_data)?;

    let scheme =
        Scheme::try_from(&*stream_buf.read_with_varint_length().await?).map_err(invalid_data)?;

    let authority = Some(stream_buf.read_with_varint_length().await?)
        .filter(|bytes| !bytes.is_empty())
        .map(Authority::from_maybe_shared)
        .transpose()
        .map_err(invalid_data)?;

    let path = PathAndQuery::from_maybe_shared(stream_buf.read_with_varint_length().await?)
        .map_err(invalid_data)?;

    Ok(RequestControlData {
        method,
        scheme,
        authority,
        path,
    })
}

struct ResponseControlData {
    status: StatusCode,
}

async fn decode_response_control_data<O, E>(
    stream_buf: &mut StreamBuf<impl Stream<Item = Result<O, E>> + Send + Unpin>,
) -> Result<ResponseControlData, E>
where
    O: Into<Bytes>,
    E: From<io::Error>,
{
    let mut status = StatusCode::from_u16(
        u16::try_from(stream_buf.decode_varint_usize().await?).map_err(invalid_data)?,
    )
    // todo(fisher): proper erroring here for status code
    .map_err(invalid_data)?;

    // skip information since we do not support them.
    while status.is_informational() {
        let _ = decode_known_length_field_section(stream_buf).await?;
        status = StatusCode::from_u16(
            u16::try_from(stream_buf.decode_varint_usize().await?).map_err(invalid_data)?,
        )
        // todo(fisher): proper erroring here for status code
        .map_err(invalid_data)?;
    }

    Ok(ResponseControlData { status })
}

async fn decode_known_length_response<S, O, E>(
    mut stream_buf: StreamBuf<S>,
) -> Result<Response<DecodedBody<S>>, E>
where
    S: Stream<Item = Result<O, E>> + Send + Unpin,
    O: Into<Bytes>,
    E: From<io::Error>,
{
    let response_control_data = decode_response_control_data(&mut stream_buf).await?;
    let field_section = decode_known_length_field_section(&mut stream_buf).await?;
    let body = DecodedBody::known_length(stream_buf).await?;

    Ok(response(response_control_data, field_section, body))
}

async fn decode_indeterminate_length_response<S, O, E>(
    mut stream_buf: StreamBuf<S>,
) -> Result<Response<DecodedBody<S>>, E>
where
    S: Stream<Item = Result<O, E>> + Send + Unpin,
    O: Into<Bytes>,
    E: From<io::Error>,
{
    let response_control_data = decode_response_control_data(&mut stream_buf).await?;
    let field_section = decode_indeterminate_length_field_section(&mut stream_buf).await?;
    let body = DecodedBody::indeterminate_length(stream_buf);

    Ok(response(response_control_data, field_section, body))
}

fn request<S>(
    request_control_data: RequestControlData,
    field_section: HeaderMap,
    body: DecodedBody<S>,
) -> io::Result<Request<DecodedBody<S>>> {
    // NOTE(nox): A scheme is mandatory in binary HTTP, but
    // an authority isn't. As `http::Uri` cannot hold a scheme
    // without an authority, this function will return an error
    // if both the authority and host header are missing. Maybe
    // this will need to be relaxed at some point.
    let authority = match request_control_data.authority {
        Some(authority) => authority,
        None => field_section
            .get(header::HOST)
            .ok_or_else(|| invalid_data("no authority or host found"))?
            .as_bytes()
            .try_into()
            .map_err(invalid_data)?,
    };

    let uri = {
        let mut parts = uri::Parts::default();

        parts.scheme = Some(request_control_data.scheme);
        parts.authority = Some(authority);
        parts.path_and_query = Some(request_control_data.path);

        Uri::from_parts(parts).map_err(invalid_data)?
    };

    let (mut parts, ()) = Request::default().into_parts();

    parts.method = request_control_data.method;
    parts.uri = uri;
    parts.headers = field_section;

    Ok(Request::from_parts(parts, body))
}

fn response<S>(
    response_control_data: ResponseControlData,
    field_section: HeaderMap,
    body: DecodedBody<S>,
) -> Response<DecodedBody<S>> {
    let (mut parts, ()) = Response::default().into_parts();

    parts.status = response_control_data.status;
    parts.headers = field_section;

    Response::from_parts(parts, body)
}
