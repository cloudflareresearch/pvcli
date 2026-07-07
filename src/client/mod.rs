// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

mod cert;
mod http2;
mod http3;
mod ohttp;
mod request;

use http::Request;
use http_body::Body;
pub use http2::Http2Client;
pub use http3::Http3Client;
pub use ohttp::OHttpClient;
pub use request::RequestHandler;

use http::HeaderValue;
use std::borrow::Cow;
use std::collections::HashMap;

use crate::{
    Args,
    args::{RequestArgs, TlsConfig},
};
use bytes::Bytes;
use color_eyre::eyre::{Result, WrapErr};
use foundations::telemetry::log;
use http_body_util::combinators::BoxBody;
use hyper::HeaderMap;

type HttpBody = BoxBody<Bytes, std::io::Error>;

pub enum HttpClientKind {
    OHttp(OHttpClient),
    Http2(Http2Client),
    Http3(Http3Client),
}

#[allow(async_fn_in_trait)]
pub trait HttpClient {
    async fn send_request(&self, req: RequestArgs, tls_config: &TlsConfig) -> Result<HttpResponse>;
}

impl HttpClient for HttpClientKind {
    async fn send_request(&self, req: RequestArgs, tls_config: &TlsConfig) -> Result<HttpResponse> {
        match self {
            Self::OHttp(c) => c
                .send_request(req, tls_config)
                .await
                .wrap_err("OHTTP Client failed to send request"),
            Self::Http2(c) => c
                .send_request(req, tls_config)
                .await
                .wrap_err("HTTP/2 Client failed to send request"),
            Self::Http3(c) => c
                .send_request(req, tls_config)
                .await
                .wrap_err("HTTP/3 Client failed to send request"),
        }
    }
}

pub enum TransportClientKind {
    Http2(Http2Client),
    Http3(Http3Client),
}

impl HttpClient for TransportClientKind {
    async fn send_request(&self, req: RequestArgs, tls_config: &TlsConfig) -> Result<HttpResponse> {
        match self {
            Self::Http2(c) => c
                .send_request(req, tls_config)
                .await
                .wrap_err("HTTP/2 Client failed to send request"),
            Self::Http3(c) => c
                .send_request(req, tls_config)
                .await
                .wrap_err("HTTP/3 Client failed to send request"),
        }
    }
}

pub async fn log_and_execute_request<F, Fut>(
    request: Request<HttpBody>,
    execute_fn: F,
) -> Result<HttpResponse>
where
    F: FnOnce(Request<HttpBody>) -> Fut,
    Fut: Future<Output = Result<HttpResponse>>,
{
    log::debug!("Request details";
        "uri" => request.uri().to_string(),
        "headers" => format!("{:?}",
        redact_headers(request.headers())),
        "body" => format!("{:?} bytes", request.body().size_hint()),
        "version" => format!("{:?}", request.version()),
        "method" => request.method().to_string()
    );

    let request_uri = request.uri().to_string();
    let http_response: HttpResponse = execute_fn(request)
        .await
        .wrap_err(format!("Failed to dispatch request to {}", request_uri))?;

    http_response.log_response();
    Ok(http_response)
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
            "[RESPONSE] Status: {}, version: {:?}",
            self.status,
            self.version
        );
        log::info!("[RESPONSE]"; "headers" => format!("{:?}", redact_headers(&self.headers)));
        log::info!(
            "[RESPONSE] Body: {} bytes, use -vvv for HEX/escaped output",
            self.body.len(),
        );
        log::debug!("Response Body [LOSSY]: {}", self.body_as_string_lossy());
        log::trace!("Response Body [HEX]: {}", self.body_as_hex());
        log::trace!("Response body [ESCAPED]: {}", self.body_as_string_escaped());
    }
}

pub fn redact_headers(headers: &HeaderMap<HeaderValue>) -> HashMap<Cow<'_, str>, Cow<'_, str>> {
    let mut redacted_headers = HashMap::new();
    for (header_name, header_value) in headers {
        let name = String::from_utf8_lossy(header_name.as_str().as_bytes());
        let value = if name.contains("authorization") {
            "REDACTED".into()
        } else {
            String::from_utf8_lossy(header_value.as_bytes())
        };
        redacted_headers.insert(name, value);
    }
    redacted_headers
}

pub fn redact_headers_vec(headers: &[String]) -> Vec<String> {
    headers
        .iter()
        .map(|h| {
            if let Some((key, _)) = h.split_once(":") {
                if key.to_lowercase().contains("authorization") {
                    format!("{}: REDACTED", key.trim())
                } else {
                    h.clone()
                }
            } else {
                log::warn!("Invalid header format: {}", h);
                h.clone()
            }
        })
        .collect()
}

pub fn redact_args(args: &Args) -> Args {
    let mut redacted_args = args.clone();
    redacted_args.header = redact_headers_vec(&redacted_args.header);
    redacted_args.first_hop_header = redact_headers_vec(&redacted_args.first_hop_header);
    redacted_args.proxy_header = redact_headers_vec(&redacted_args.proxy_header);
    redacted_args
}

pub fn redact_request_args(args: &RequestArgs) -> RequestArgs {
    let mut redacted_args = args.clone();
    redacted_args.headers = redact_headers_vec(&redacted_args.headers);
    redacted_args.proxy_header = redact_headers_vec(&redacted_args.proxy_header);
    redacted_args
}
