mod http2;
mod ohttp;

pub use http2::Http2Client;
pub use ohttp::OHttpClient;

use crate::args::RequestArgs;
use crate::error::Result;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;

type Body = BoxBody<Bytes, hyper::Error>;

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
            Self::OHttp(c) => c.send_request(req).await,
            Self::Http2(c) => c.send_request(req).await,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Bytes,
}

impl HttpResponse {
    pub fn body_as_string_lossy(&self) -> Result<String> {
        Ok(String::from_utf8_lossy(&self.body).to_string())
    }
    pub fn body_as_string_escaped(&self) -> Result<String> {
        Ok(self
            .body
            .iter()
            .map(|&b| {
                // all readable ascii + space, else hex escape (prevents random tabs/newlines from messing up logs)
                if b.is_ascii_graphic() || b == b' ' {
                    (b as char).to_string()
                } else {
                    format!("\\x{:02x}", b)
                }
            })
            .collect())
    }
}
