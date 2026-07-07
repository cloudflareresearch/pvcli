// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use bytes::{Bytes, BytesMut};
use futures::{stream, Stream, StreamExt, TryStreamExt};
use http_body_util::{BodyExt, Empty, StreamBody};
use hyper::body::Frame;
use hyper::{HeaderMap, Method, Request, Version};
use hyper_binary::{decode_request, encode_request, DecodedBody};
use std::io;
use stream_buf::StreamBuf;

const EXPECTED_USER_AGENT: &str = "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3";

#[rustfmt::skip]
const KNOWN_LENGTH_HEADERS: &[u8] = &[
    // Framing Indicator
    0x00,

    // Request Control Data

        // Method Length
        0x04,
        // Method
        b'P', b'O', b'S', b'T',
        // Scheme Length
        0x05,
        // Scheme
        b'h', b't', b't', b'p', b's',
        // Authority Length
        0x00,
        // Path Length
        0x0a,
        // Path
        b'/', b'h', b'e', b'l', b'l', b'o', b'.', b't', b'x', b't',

    // Known-Length Field Section

        // Length
        0x40, 0x6c,

        // Field Line

            // Name Length
            0x0a,
            // Name
            b'u', b's', b'e', b'r', b'-', b'a', b'g', b'e', b'n', b't',
            // Value Length
            0x34,
            // Value
            b'c', b'u', b'r', b'l', b'/', b'7', b'.', b'1', b'6', b'.', b'3', b' ',
            b'l', b'i', b'b', b'c', b'u', b'r', b'l', b'/', b'7', b'.', b'1', b'6', b'.', b'3', b' ',
            b'O', b'p', b'e', b'n', b'S', b'S', b'L', b'/', b'0', b'.', b'9', b'.', b'7', b'l', b' ',
            b'z', b'l', b'i', b'b', b'/', b'1', b'.', b'2', b'.', b'3',

        // Field Line

            // Name Length
            0x04,
            // Name
            b'h', b'o', b's', b't',
            // Value Length
            0x0f,
            // Value
            b'w', b'w', b'w', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',

        // Field Line

            // Name Length
            0x0f,
            // Name
            b'a', b'c', b'c', b'e', b'p', b't', b'-', b'l', b'a', b'n', b'g', b'u', b'a', b'g', b'e',
            // Value Length
            0x06,
            // Value
            b'e', b'n', b',', b' ', b'm', b'i',
];

#[rustfmt::skip]
const KNOWN_LENGTH_CONTENT: &[u8] = &[
    // Content Length
    0x09,
    // Content
    b'B', b'a', b'g', b'u', b'e', b't', b't', b'e', b'!',
];

#[rustfmt::skip]
const KNOWN_LENGTH_EMPTY_TRAILERS: &[u8] = &[
    // Length
    0x00,
];

#[rustfmt::skip]
const INDETERMINATE_LENGTH_HEADERS: &[u8] = &[
    // Framing Indicator
    0x02,

    // Request Control Data

        // Method Length
        0x04,
        // Method
        b'P', b'O', b'S', b'T',
        // Scheme Length
        0x05,
        // Scheme
        b'h', b't', b't', b'p', b's',
        // Authority Length
        0x00,
        // Path Length
        0x0a,
        // Path
        b'/', b'h', b'e', b'l', b'l', b'o', b'.', b't', b'x', b't',

    // Indeterminate-Length Field Section

        // Field Line

            // Name Length
            0x0a,
            // Name
            b'u', b's', b'e', b'r', b'-', b'a', b'g', b'e', b'n', b't',
            // Value Length
            0x34,
            // Value
            b'c', b'u', b'r', b'l', b'/', b'7', b'.', b'1', b'6', b'.', b'3', b' ',
            b'l', b'i', b'b', b'c', b'u', b'r', b'l', b'/', b'7', b'.', b'1', b'6', b'.', b'3', b' ',
            b'O', b'p', b'e', b'n', b'S', b'S', b'L', b'/', b'0', b'.', b'9', b'.', b'7', b'l', b' ',
            b'z', b'l', b'i', b'b', b'/', b'1', b'.', b'2', b'.', b'3',

        // Field Line

            // Name Length
            0x04,
            // Name
            b'h', b'o', b's', b't',
            // Value Length
            0x0f,
            // Value
            b'w', b'w', b'w', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',

        // Field Line

            // Name Length
            0x0f,
            // Name
            b'a', b'c', b'c', b'e', b'p', b't', b'-', b'l', b'a', b'n', b'g', b'u', b'a', b'g', b'e',
            // Value Length
            0x06,
            // Value
            b'e', b'n', b',', b' ', b'm', b'i',

        // Content Terminator
        0x00,
];

#[rustfmt::skip]
const INDETERMINATE_LENGTH_CONTENT: &[u8] = &[
    // Indeterminate-Length Content Chunk

        // Chunk Length
        0x04,
        // Chunk
        b'B', b'a', b'g', b'u',

    // Indeterminate-Length Content Chunk

        // Chunk Length
        0x04,
        // Chunk
        b'e', b't', b't', b'e',

    // Indeterminate-Length Content Chunk

        // Chunk Length
        0x01,
        // Chunk
        b'!',
];

#[rustfmt::skip]
const INDETERMINATE_LENGTH_CONTENT_TERMINATOR: &[u8] = &[
    0x00,
];

#[rustfmt::skip]
const INDETERMINATE_LENGTH_TRAILER_TERMINATOR: &[u8] = &[
    0x00,
];

#[tokio::test]
async fn known_length() {
    let request = [
        KNOWN_LENGTH_HEADERS,
        KNOWN_LENGTH_CONTENT,
        KNOWN_LENGTH_EMPTY_TRAILERS,
    ]
    .into_iter()
    .flatten()
    .cloned()
    .collect::<Vec<_>>();

    for chunk_len in 1..request.len() {
        let req = decode_request(StreamBuf::new(stream::iter(
            request.chunks(chunk_len).map(|chunk| Ok(chunk.to_owned())),
        )))
        .await
        .unwrap();

        assert_example_request(req, Ok("Baguette!")).await;
    }
}

#[tokio::test]
async fn indeterminate_length() {
    let request = [
        INDETERMINATE_LENGTH_HEADERS,
        INDETERMINATE_LENGTH_CONTENT,
        INDETERMINATE_LENGTH_CONTENT_TERMINATOR,
        INDETERMINATE_LENGTH_TRAILER_TERMINATOR,
    ]
    .into_iter()
    .flatten()
    .cloned()
    .collect::<Vec<_>>();

    for chunk_len in 1..request.len() {
        let req = decode_request(StreamBuf::new(stream::iter(
            request.chunks(chunk_len).map(|chunk| Ok(chunk.to_owned())),
        )))
        .await
        .unwrap();

        assert_example_request(req, Ok("Baguette!")).await;
    }
}

#[tokio::test]
async fn known_length_truncated_headers() {
    let truncated_len = KNOWN_LENGTH_HEADERS.len() - 3;

    let err: io::Error = decode_request(StreamBuf::new(stream::iter(
        KNOWN_LENGTH_HEADERS[..truncated_len].chunks(16).map(Ok),
    )))
    .await
    .unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

// https://www.rfc-editor.org/rfc/rfc9458.html#name-complete-example-of-a-reque
#[tokio::test]
async fn known_length_missing_headers_rfc_9458() {
    #[rustfmt::skip]
    const APPENDIX_A_EXAMPLE: &[u8] = &[
        // Framing Indicator
        0x00,
        
        // Request Control Data
    
            // Method Length
            0x03,
            // Method
            b'G', b'E', b'T',
            // Scheme Length
            0x05,
            // Scheme
            b'h', b't', b't', b'p', b's',
            // Authority Length
            0x0b,
            // Authority
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
            // Path Length
            0x01,
            // Path
            b'/',
    ];

    for chunk_len in 1..APPENDIX_A_EXAMPLE.len() {
        let req = decode_request(StreamBuf::new(stream::iter(
            APPENDIX_A_EXAMPLE.chunks(chunk_len).map(Ok::<_, io::Error>),
        )))
        .await
        .unwrap();

        assert_eq!(req.method(), Method::GET);
        assert_eq!(req.uri(), "https://example.com/");
        assert!(req.headers().is_empty());
    }
}

#[tokio::test]
async fn indeterminate_length_truncated_headers() {
    let truncated_len = INDETERMINATE_LENGTH_HEADERS.len() - 3;

    let err: io::Error = decode_request(StreamBuf::new(stream::iter(
        INDETERMINATE_LENGTH_HEADERS[..truncated_len]
            .chunks(16)
            .map(Ok),
    )))
    .await
    .unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn known_length_no_content() {
    for chunk_len in 1..KNOWN_LENGTH_HEADERS.len() {
        let req = decode_request(StreamBuf::new(stream::iter(
            KNOWN_LENGTH_HEADERS.chunks(chunk_len).map(Ok),
        )))
        .await
        .unwrap();

        assert_example_request(req, Ok("")).await;
    }
}

#[tokio::test]
async fn known_length_truncated_content() {
    let mut request = [KNOWN_LENGTH_HEADERS, KNOWN_LENGTH_CONTENT]
        .into_iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();

    request.truncate(request.len() - 4);

    for chunk_len in 1..request.len() {
        let req = decode_request(StreamBuf::new(stream::iter(
            request.chunks(chunk_len).map(|chunk| Ok(chunk.to_owned())),
        )))
        .await
        .unwrap();

        assert_example_request(req, Err(io::ErrorKind::UnexpectedEof)).await;
    }
}

#[tokio::test]
async fn indeterminate_length_truncated_content_chunk() {
    let mut request = [INDETERMINATE_LENGTH_HEADERS, INDETERMINATE_LENGTH_CONTENT]
        .into_iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();

    request.truncate(request.len() - 4);

    for chunk_len in 1..request.len() {
        let req = decode_request(StreamBuf::new(stream::iter(
            request.chunks(chunk_len).map(|chunk| Ok(chunk.to_owned())),
        )))
        .await
        .unwrap();

        assert_example_request(req, Err(io::ErrorKind::UnexpectedEof)).await;
    }
}

#[tokio::test]
async fn indeterminate_length_truncated_content() {
    let request = [INDETERMINATE_LENGTH_HEADERS, INDETERMINATE_LENGTH_CONTENT]
        .into_iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();

    for chunk_len in 1..request.len() {
        let req = decode_request(StreamBuf::new(stream::iter(
            request.chunks(chunk_len).map(|chunk| Ok(chunk.to_owned())),
        )))
        .await
        .unwrap();

        assert_example_request(req, Ok("Baguette!")).await;
    }
}

#[tokio::test]
async fn indeterminate_length_no_content() {
    for chunk_len in 1..INDETERMINATE_LENGTH_HEADERS.len() {
        let req = decode_request(StreamBuf::new(stream::iter(
            INDETERMINATE_LENGTH_HEADERS.chunks(chunk_len).map(Ok),
        )))
        .await
        .unwrap();

        assert_example_request(req, Ok("")).await;
    }
}

#[tokio::test]
async fn known_length_no_trailers() {
    let request = [KNOWN_LENGTH_HEADERS, KNOWN_LENGTH_CONTENT]
        .into_iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();

    for chunk_len in 1..request.len() {
        let req = decode_request(StreamBuf::new(stream::iter(
            request.chunks(chunk_len).map(|chunk| Ok(chunk.to_owned())),
        )))
        .await
        .unwrap();

        assert_example_request(req, Ok("Baguette!")).await;
    }
}

#[tokio::test]
async fn indeterminate_length_no_trailers() {
    let request = [
        INDETERMINATE_LENGTH_HEADERS,
        INDETERMINATE_LENGTH_CONTENT,
        INDETERMINATE_LENGTH_CONTENT_TERMINATOR,
    ]
    .into_iter()
    .flatten()
    .cloned()
    .collect::<Vec<_>>();

    for chunk_len in 1..request.len() {
        let req = decode_request(StreamBuf::new(stream::iter(
            request.chunks(chunk_len).map(|chunk| Ok(chunk.to_owned())),
        )))
        .await
        .unwrap();

        assert_example_request(req, Ok("Baguette!")).await;
    }
}

#[tokio::test]
async fn known_length_max_buf_size() {
    let err: io::Error = decode_request(
        StreamBuf::new(stream::iter(KNOWN_LENGTH_HEADERS.chunks(4).map(Ok)))
            .max_buf_size(EXPECTED_USER_AGENT.len() - 8),
    )
    .await
    .unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(err.to_string(), "max buf size reached");
}

#[tokio::test]
async fn indeterminate_length_max_buf_size() {
    let err: io::Error = decode_request(
        StreamBuf::new(stream::iter(INDETERMINATE_LENGTH_HEADERS.chunks(4).map(Ok)))
            .max_buf_size(EXPECTED_USER_AGENT.len() - 8),
    )
    .await
    .unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(err.to_string(), "max buf size reached");
}

#[tokio::test]
async fn encode_example_request() {
    let req = example_request(StreamBody::new(
        stream::iter(["Bagu", "ette", "", "!"])
            .map(|chunk| Ok::<_, io::Error>(Frame::data(Bytes::from(chunk)))),
    ));

    let encoded_req = encode_request(req).unwrap();

    let bytes = BodyExt::collect(StreamBody::new(encoded_req.map_ok(Frame::data)))
        .await
        .unwrap()
        .to_bytes();

    let expected_bytes = [
        INDETERMINATE_LENGTH_HEADERS,
        INDETERMINATE_LENGTH_CONTENT,
        INDETERMINATE_LENGTH_CONTENT_TERMINATOR,
    ]
    .into_iter()
    .flatten()
    .cloned()
    .collect::<Bytes>();

    assert_eq!(bytes, expected_bytes);
}

#[tokio::test]
async fn simple_roundtrip() {
    let encoded_request = encode_request(example_request(<Empty<Bytes>>::new())).unwrap();

    let decoded_request = decode_request(StreamBuf::new(
        encoded_request.map_err(std::io::Error::other),
    ))
    .await
    .unwrap();

    let (decoded_parts, decoded_body) = decoded_request.into_parts();
    let (expected_parts, _) = example_request(<Empty<Bytes>>::new()).into_parts();

    assert_eq!(expected_parts.version, Version::HTTP_11);
    assert_eq!(expected_parts.method, decoded_parts.method);
    assert_eq!(expected_parts.uri, decoded_parts.uri);
    assert_eq!(expected_parts.headers, decoded_parts.headers);

    let decoded_body = decoded_body.collect().await.unwrap().to_bytes();

    assert!(decoded_body.is_empty());
}

fn example_request<B>(body: B) -> Request<B> {
    Request::post("https://www.example.com/hello.txt")
        .header(
            "User-Agent",
            "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3",
        )
        .header("Host", "www.example.com")
        .header("Accept-Language", "en, mi")
        .body(body)
        .unwrap()
}

async fn assert_example_request<S, O>(
    req: Request<DecodedBody<S>>,
    expected_body: Result<&'static str, io::ErrorKind>,
) where
    S: Stream<Item = Result<O, io::Error>> + Send + Unpin,
    O: Into<Bytes>,
{
    assert_eq!(req.method(), Method::POST);
    assert_eq!(req.uri(), "https://www.example.com/hello.txt");

    assert_headers(
        req.headers(),
        &[
            ("user-agent", EXPECTED_USER_AGENT),
            ("host", "www.example.com"),
            ("accept-language", "en, mi"),
        ],
    );

    assert_eq!(
        req.into_body()
            .collect()
            .await
            .map(|bytes| bytes.to_bytes())
            .map_err(|err| err.kind()),
        expected_body.map(|body| Bytes::from(body.as_bytes())),
    );
}

fn assert_headers(actual_headers: &HeaderMap, expected_headers: &[(&str, &str)]) {
    for (name, expected_value) in expected_headers {
        let mut values = actual_headers.get_all(*name).iter().collect::<Vec<_>>();
        let actual_value = values.pop().unwrap();

        assert!(values.is_empty(), "header {name} has too many values");

        assert_eq!(
            BytesMut::from(actual_value.as_bytes()),
            BytesMut::from(expected_value.as_bytes())
        );
    }
}
