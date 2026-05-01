use crate::error::Result;

use bytes::Bytes;
use foundations::telemetry::log;
use http::request::Builder;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::{Request, Response, body::Incoming};
use hyper_rustls::HttpsConnector;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};

type Body = BoxBody<Bytes, hyper::Error>;

pub struct HttpClient {
    client: Client<HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>, Body>,
}

impl HttpClient {
    pub fn new() -> Result<Self> {
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("failed to load native TLS roots")
            .https_or_http()
            .enable_http2()
            .build();

        let client: Client<_, Body> = Client::builder(TokioExecutor::new())
            .http2_only(true)
            .build(https);

        Ok(Self { client })
    }

    pub async fn get(&self, url: &str, headers: Vec<String>) -> Result<HttpResponse> {
        log::info!("GET {}", url);
        log::debug!("Using HTTP/2");
        let uri = url.parse::<hyper::Uri>()?;

        log::debug!(
            "Parsed URI - scheme: {:?}, host: {:?}, path: {}",
            uri.scheme_str(),
            uri.host(),
            uri.path()
        );

        let builder = Request::builder().method("GET").uri(&uri);
        let request = self
            .consume_headers(builder, headers)
            .body(BoxBody::new(Empty::<Bytes>::new().map_err(|e| match e {})))
            .expect("failed to build request");

        log::debug!("request built: {:?}", request);

        self.send_request(request).await
    }

    pub async fn post(&self, url: &str, headers: Vec<String>, body: Bytes) -> Result<HttpResponse> {
        log::info!("POST {}", url);
        log::debug!("Using HTTP/2");
        let uri = url.parse::<hyper::Uri>()?;

        log::debug!(
            "Parsed URI - scheme: {:?}, host: {:?}, path: {}",
            uri.scheme_str(),
            uri.host(),
            uri.path()
        );

        let builder = Request::builder().method("POST").uri(&uri);
        let request = self
            .consume_headers(builder, headers)
            .body(BoxBody::new(Full::new(body).map_err(|e| match e {})))
            .expect("failed to build request");

        log::debug!("request built: {:?}", request);

        self.send_request(request).await
    }

    fn consume_headers(&self, mut builder: Builder, headers: Vec<String>) -> Builder {
        for h in &headers {
            if let Some((key, header)) = h.split_once(":") {
                builder = builder.header(
                    http::header::HeaderName::from_bytes(key.trim().as_bytes()).unwrap(),
                    http::header::HeaderValue::from_str(header.trim()).unwrap(),
                );
            } else {
                log::warn!("invalid header format: {}", h);
            }
        }
        builder
    }

    async fn send_request(&self, request: Request<Body>) -> Result<HttpResponse> {
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
