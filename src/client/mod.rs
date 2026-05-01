mod http2;
mod http3;
mod ohttp;

pub use http2::Http2Client;
pub use ohttp::OHttpClient;

use crate::args::RequestArgs;
use bytes::Bytes;
use color_eyre::eyre::{Report, Result, WrapErr};
use foundations::telemetry::log;
use http_body_util::combinators::BoxBody;
use hyper::HeaderMap;

type Body = BoxBody<Bytes, Report>;

pub enum HttpClientKind {
    OHttp(OHttpClient),
    Http2(Http2Client),
}

#[allow(async_fn_in_trait)]
pub trait HttpClient {
    async fn send_request(&self, req: RequestArgs) -> Result<HttpResponse>;
}

impl HttpClient for HttpClientKind {
    async fn send_request(&self, req: RequestArgs) -> Result<HttpResponse> {
        match self {
            Self::OHttp(c) => c
                .send_request(req)
                .await
                .wrap_err("OHTTP Client failed to send request"),
            Self::Http2(c) => c
                .send_request(req)
                .await
                .wrap_err("HTTP/2 Client failed to send request"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub version: http::Version,
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl HttpResponse {
    // For final user-friendly output
    pub fn body_as_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    // For logging/debugging: attempt to display body as UTF-8 string, but escape non-printable characters (e.g. binary data) to prevent logs from getting messed up
    pub fn body_as_string_escaped(&self) -> String {
        self.body
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    (b as char).to_string()
                } else {
                    format!("\\x{:02x}", b)
                }
            })
            .collect()
    }

    // Standard hex output, common for cryptographic outputs and debugging
    pub fn body_as_hex(&self) -> String {
        hex::encode(&self.body)
    }

    pub fn log_response(&self) {
        log::info!(
            "Response status: {}, version: {:?}",
            self.status,
            self.version
        );
        log::info!("Response Headers: {:?}", self.headers);
        log::debug!(
            "Response Body, use -vvv for hex output ({} bytes): {}",
            self.body.len(),
            self.body_as_string_escaped()
        );
        log::trace!(
            "Response body ({} bytes) [HEX]: {}",
            self.body.len(),
            self.body_as_hex()
        );
    }
}
