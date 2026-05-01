mod cert;
mod http2;
mod http3;
mod ohttp;
mod request;

use http::Request;
pub use http2::Http2Client;
pub use http3::Http3Client;
pub use ohttp::OHttpClient;
pub use request::RequestHandler;

use crate::args::{RequestArgs, TlsConfig};
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

pub enum ProxyClientKind {
    Http2(Http2Client),
    Http3(Http3Client),
}

impl HttpClient for ProxyClientKind {
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
    log::trace!("Full request details: {:?}", request);

    let request_uri = request.uri().to_string();
    let http_response: HttpResponse = execute_fn(request)
        .await
        .wrap_err(format!("Failed to dispatch request to {}", request_uri))?;

    log::info!("Successfully received response from {}", request_uri);
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
            "Response status: {}, version: {:?}",
            self.status,
            self.version
        );
        log::info!("Response Headers: {:?}", self.headers);
        log::info!(
            "Response body, use -vvv for HEX/escaped output ({} bytes)",
            self.body.len(),
        );
        log::debug!("Response Body [HEX]: {}", self.body_as_hex());
        log::debug!("Response Body [LOSSY]: {}", self.body_as_string_lossy());
        log::trace!("Response body [ESCAPED]: {}", self.body_as_string_escaped());
    }
}
