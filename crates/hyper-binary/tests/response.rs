// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use bytes::Bytes;
use futures::{stream, StreamExt, TryStreamExt};
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::body::{Body, Frame};
use hyper::header::HeaderValue;
use hyper::{HeaderMap, Response, StatusCode, Version};
use hyper_binary::{decode_response, encode_response, EncodedMessage};
use std::{fmt, io};
use stream_buf::StreamBuf;

#[rustfmt::skip]
const INDETERMINATE_LENGTH_HEADERS: &[u8] = &[
    // Framing Indicator
    0x03,

    // Final Response Control Data

        // Status Code
        0x40, 0xc8,

    // Indeterminate-Length Field Section

        // Field Line

            // Name Length
            0x04,

            // Name
            b'd', b'a', b't', b'e',

            // Value Length
            0x1d,

            // Value
            b'M', b'o', b'n', b',', b' ',
            b'2', b'7', b' ',
            b'J', b'u', b'l', b' ',
            b'2', b'0', b'0', b'9', b' ',
            b'1', b'2', b':', b'2', b'8', b':', b'5', b'3', b' ',
            b'G', b'M', b'T',

        // Field Line

            // Name Length
            0x06,

            // Name
            b's', b'e', b'r', b'v', b'e', b'r',

            // Value Length
            0x06,

            // Value
            b'A', b'p', b'a', b'c', b'h', b'e',

        // Field Line

            // Name Length
            0x0c,

            // Name
            b'c', b'o', b'n', b't', b'e', b'n', b't', b'-', b't', b'y', b'p', b'e',

            // Value Length
            0x0a,

            // Value
            b't', b'e', b'x', b't', b'/', b'p', b'l', b'a', b'i', b'n',

        // Content Terminator
        0x00,
];

#[tokio::test]
async fn indeterminate_length() {
    let res = example_response(StreamBody::new(
        // use a stream to force indeterminate length
        stream::iter([Ok::<_, io::Error>(Frame::data(Bytes::from(
            "Hello World! My content includes a trailing CRLF.\r\n",
        )))]),
    ));

    #[rustfmt::skip]
    assert_chunks(encode_response(res), &[
        INDETERMINATE_LENGTH_HEADERS,

        // Indeterminate-Length Content

            // Indeterminate-Length Content Chunk

                // Chunk
                b"\x33Hello World! My content includes a trailing CRLF.\r\n",

            // Content Terminator
            &[0x00],
    ]).await;
}

#[tokio::test]
async fn indeterminate_length_empty() {
    let res = example_response(StreamBody::new(
        // use a stream to force indeterminate length
        stream::iter([]).map(Ok::<Frame<Bytes>, io::Error>),
    ));

    assert_chunks(
        encode_response(res),
        &[INDETERMINATE_LENGTH_HEADERS, &[0x00]],
    )
    .await;
}

#[tokio::test]
async fn indeterminate_length_empty_content_chunk() {
    let res = example_response(StreamBody::new(
        stream::iter([
            "Hello World! ",
            "",
            "My content includes a trailing CRLF.\r\n",
        ])
        .map(|chunk| Ok::<_, io::Error>(Frame::data(Bytes::from(chunk)))),
    ));

    assert_chunks(
        encode_response(res),
        &[
            INDETERMINATE_LENGTH_HEADERS,
            b"\x0dHello World! ",
            &[],
            b"\x26My content includes a trailing CRLF.\r\n",
            &[0x00],
        ],
    )
    .await;
}

#[tokio::test]
async fn simple_roundtrip() {
    let encoded = encode_response(simple_response(<Empty<Bytes>>::new()));
    let (decoded_parts, decoded_body) = decode_response(StreamBuf::new(
        encoded.map_err::<io::Error, _>(|err| match err {}),
    ))
    .await
    .unwrap()
    .into_parts();

    let (expected_parts, _) = simple_response(<Empty<Bytes>>::new()).into_parts();

    assert_eq!(decoded_parts.version, Version::HTTP_11);
    assert_eq!(decoded_parts.status, expected_parts.status);
    assert_eq!(decoded_parts.headers, expected_parts.headers);

    let decoded_body = decoded_body.collect().await.unwrap().to_bytes();

    assert!(decoded_body.is_empty());
}

#[tokio::test]
async fn simple_roundtrip_headers_and_body() {
    let mut headers = HeaderMap::new();
    headers.append("Foo", HeaderValue::from_static("Bar"));

    let mut resp = simple_response(StreamBody::new(
        futures::stream::iter(["Hello,", " World!"])
            .map(|chunk| Ok::<_, io::Error>(Frame::data(Bytes::from(chunk)))),
    ));

    *resp.headers_mut() = headers;

    let encoded_resp = encode_response(resp);
    let (decoded_parts, decoded_body) = decode_response(StreamBuf::new(encoded_resp))
        .await
        .unwrap()
        .into_parts();

    assert_eq!(decoded_parts.version, Version::HTTP_11);
    assert_eq!(decoded_parts.status.as_u16(), 200);
    assert_eq!(
        decoded_parts.headers.get("foo"),
        Some(&HeaderValue::from_static("Bar"))
    );

    let decoded_body = decoded_body.collect().await.unwrap().to_bytes();

    assert_eq!(&*decoded_body, b"Hello, World!");
}

async fn assert_chunks<B>(mut message: EncodedMessage<B>, expected_chunks: &[&'static [u8]])
where
    B: Body + Unpin,
    <B as Body>::Data: Into<Bytes>,
    <B as Body>::Error: fmt::Debug,
{
    for (i, chunk) in expected_chunks.iter().cloned().enumerate() {
        assert_eq!(
            message.next().await.unwrap().unwrap(),
            Bytes::from(chunk),
            "unexpected chunk {i}",
        );
    }

    // assert that we've consumed the stream
    assert!(message.next().await.is_none(), "too many chunks");
}

#[tokio::test]
async fn known_length_simple() {
    let response = encode_response(simple_response(<Empty<Bytes>>::new()));

    // note: this is the truncated form of a request, since we are not
    // explicitly encoding the empty trailer section. Technically, `0140c8`
    // would be a valid representation of this request, however we explicitly
    // write empty header and body sections.
    assert_chunks(
        response,
        &[&[
            0x01, // known-length response
            0x40, 0xc8, // 200 OK
            0x00, // empty headers (field line section)
            0x00, // empty body
        ]],
    )
    .await;
}

#[tokio::test]
async fn known_length_simple_with_body() {
    let response = encode_response(simple_response(Full::new(Bytes::from("Hello, World!"))));

    assert_chunks(
        response,
        &[
            &[
                0x01, // known-length response
                0x40, 0xc8, // 200 OK
                0x00, // empty headers (field line section)
                0x0d, // 13 byte body
            ],
            b"Hello, World!", // body
        ],
    )
    .await;
}

#[tokio::test]
async fn known_length_simple_with_headers_with_body() {
    let mut resp = simple_response(Full::new(Bytes::from("Hello, World!")));

    resp.headers_mut()
        .append("Content-Type", "application/json".parse().unwrap());

    let response = encode_response(resp);
    assert_chunks(
        response,
        &[
            &[
                0x01, // known-length response
                0x40, 0xc8, // 200 OK
                0x1e, // 30 byte headers
                0x0c, // 12 byte header name
                // "content-type"
                0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x74, 0x79, 0x70, 0x65,
                //
                0x10, // 16 byte header value
                // "application/json"
                0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x6a, 0x73,
                0x6f, 0x6e, 0x0d, // 13 byte body
            ],
            b"Hello, World!", // body
        ],
    )
    .await;
}

fn example_response<B>(body: B) -> Response<B> {
    Response::builder()
        .header("date", "Mon, 27 Jul 2009 12:28:53 GMT")
        .header("server", "Apache")
        .header("content-type", "text/plain")
        .body(body)
        .unwrap()
}

fn simple_response<B>(body: B) -> Response<B> {
    Response::builder()
        .status(StatusCode::from_u16(200).unwrap())
        .body(body)
        .unwrap()
}
