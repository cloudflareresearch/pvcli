// THROWAWAY test — verifies whether malformed BHTTP (body length prefix says 10
// but body is 11 bytes due to a trailing newline) breaks decoding. Do not commit.

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper_binary::decode_request;
use std::io;
use stream_buf::{EmptyStreamBuf, StreamBuf};

async fn try_decode(label: &str, hex_str: &str) {
    let bytes = Bytes::from(hex::decode(hex_str).unwrap());
    let total = bytes.len();
    let buf: EmptyStreamBuf<io::Error> = StreamBuf::from(bytes);

    let fut = async {
        match decode_request(buf).await {
            Ok(req) => {
                let (parts, body) = req.into_parts();
                println!(
                    "[{label}] decode_request OK: {} {} ({} total bytes)",
                    parts.method, parts.uri, total
                );
                match body.collect().await {
                    Ok(c) => {
                        let b = c.to_bytes();
                        println!(
                            "[{label}] body OK: {} bytes = {:?}",
                            b.len(),
                            String::from_utf8_lossy(&b)
                        );
                    }
                    Err(e) => println!("[{label}] body ERROR: {} ({:?})", e, e.kind()),
                }
            }
            Err(e) => println!("[{label}] decode_request ERROR: {} ({:?})", e, e.kind()),
        }
    };

    match tokio::time::timeout(std::time::Duration::from_secs(3), fut).await {
        Ok(()) => {}
        Err(_) => println!("[{label}] TIMED OUT (likely infinite loop)"),
    }
}

#[tokio::test]
async fn bhttp_malformed_newline_check() {
    // body chunk: 0a (len 10) + {"test":1} (10 bytes) + 00 terminator
    let correct = "0204504f5354056874747073117461726765742e6f687474702e696e666f092f616e797468696e670c636f6e74656e742d74797065106170706c69636174696f6e2f6a736f6e0a757365722d6167656e740c6665727265742f302e312e30000a7b2274657374223a317d00";
    // body chunk: 0a (len 10) + {"test":1}\n (11 bytes) + 00  -> length/content mismatch
    let malformed = "0204504f5354056874747073117461726765742e6f687474702e696e666f092f616e797468696e670c636f6e74656e742d74797065106170706c69636174696f6e2f6a736f6e0a757365722d6167656e740c6665727265742f302e312e30000a7b2274657374223a317d0a00";

    try_decode("correct  ", correct).await;
    try_decode("malformed", malformed).await;
}
