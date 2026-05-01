use crate::error::Result;

use bytes::Bytes;
use foundations::telemetry::log;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

pub struct HttpClient {
    client:
        Client<HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>, Empty<Bytes>>,
}

impl HttpClient {
    pub fn new() -> Result<Self> {
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("failed to load native TLS roots")
            .https_or_http()
            .enable_http2()
            .build();

        let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new())
            .http2_only(true)
            .build(https);

        Ok(Self { client })
    }

    pub async fn get(&self, url: &str) -> Result<HttpResponse> {
        log::info!("Fetching {}", url);
        log::debug!("Using HTTP/2");
        let uri = url.parse::<hyper::Uri>()?;

        log::debug!(
            "Parsed URI - scheme: {:?}, host: {:?}, path: {}",
            uri.scheme_str(),
            uri.host(),
            uri.path()
        );

        let request = Request::builder()
            .method("GET")
            .uri(&uri)
            .header("Host", uri.host().unwrap_or(""))
            .body(Empty::<Bytes>::new())
            .expect("failed to build request");

        log::info!("Sending request: {:?}", request);

        let response: Response<Incoming> = self.client.request(request).await?;

        let status = response.status().as_u16();
        let headers = response.headers().clone();

        log::info!("Status: {}", status);
        log::debug!("Headers: {:?}", headers);

        // collect body
        let body_bytes = response.into_body().collect().await?.to_bytes(); // TODO: ? stream for bigger response sizes
        let body = String::from_utf8_lossy(&body_bytes).to_string();

        log::debug!("Body length: {} bytes", body.len());

        Ok(HttpResponse { status, body })
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new().expect("failed to create HTTP client")
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}
