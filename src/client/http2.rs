use super::{Body, HttpClient, HttpResponse};
use crate::Method;
use crate::args::RequestArgs;
use crate::error::{FerretError, Result};

use bytes::Bytes;
use foundations::telemetry::log;
use http::request::Builder;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::{Request, Response, body::Incoming};
use hyper_rustls::HttpsConnector;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};

pub struct Http2Client {
    client: Client<HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>, Body>,
}

impl HttpClient for Http2Client {
    async fn send_request(&self, args: RequestArgs) -> Result<HttpResponse> {
        let request = self.create_request(args)?;
        self.dispatch_request(request).await
    }
}

impl Http2Client {
    pub fn new() -> Result<Self> {
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|e| {
                FerretError::CertificateError(format!("failed to load native TLS roots: {}", e))
            })?
            .https_or_http()
            .enable_http2()
            .build();

        let client: Client<_, Body> = Client::builder(TokioExecutor::new())
            // .http2_only(true) // --http2 flag to force this
            .build(https);

        log::debug!("Successfully initialized HTTP2 Client");
        Ok(Self { client })
    }

    fn get(&self, args: RequestArgs) -> Result<Request<Body>> {
        let headers: Vec<String> = args.headers;
        let url = args.url;

        log::info!("GET: Creating Http2Client request to {}", url);
        let uri = url.parse::<hyper::Uri>()?;

        log::debug!(
            "Parsed URI - scheme: {:?}, host: {:?}, path: {}",
            uri.scheme_str(),
            uri.host(),
            uri.path()
        );

        let builder = Request::builder().method("GET").uri(&uri);
        let request = self
            .consume_headers(builder, headers)?
            .body(BoxBody::new(Empty::<Bytes>::new().map_err(|e| match e {})))
            .expect("failed to build request");

        log::debug!("Request built: {:?}", request);

        Ok(request)
    }

    fn post(&self, args: RequestArgs) -> Result<Request<Body>> {
        let body = args.body.ok_or(FerretError::InvalidArg(
            "POST request requires a body".into(),
        ))?;
        let url = args.url;
        let headers: Vec<String> = args.headers;

        log::info!("POST: Creating Http2Client request to {}", url);
        let uri = url.parse::<hyper::Uri>()?;

        log::debug!(
            "Parsed URI - scheme: {:?}, host: {:?}, path: {}",
            uri.scheme_str(),
            uri.host(),
            uri.path()
        );

        let builder = Request::builder().method("POST").uri(&uri);
        let request = self
            .consume_headers(builder, headers)?
            .body(BoxBody::new(Full::new(body).map_err(|e| match e {})))
            .expect("failed to build request");

        log::debug!("Request built: {:?}", request);

        Ok(request)
    }

    pub fn create_request(&self, args: RequestArgs) -> Result<Request<Body>> {
        let request = match args.method {
            Method::Get => self.get(args)?,
            Method::Post => self.post(args)?,
        };

        Ok(request)
    }

    pub async fn dispatch_request(&self, request: Request<Body>) -> Result<HttpResponse> {
        log::info!("Sending request: {:?}", request);

        let response: Response<Incoming> = self.client.request(request).await.map_err(|e| {
            log::error!("Request failed: {:?}", e);
            FerretError::ClientError(e)
        })?;

        let status = response.status().as_u16();
        let headers = response.headers().clone();

        log::info!("Response version: {:?}", response.version());
        log::info!("Response Status: {}", status);
        log::info!("Response Headers: {:?}", headers);

        let body = response.into_body().collect().await?.to_bytes(); // TODO: ? stream for bigger response sizes
        log::debug!("Body length: {} bytes", body.len());

        Ok(HttpResponse { status, body })
    }

    fn consume_headers(&self, mut builder: Builder, headers: Vec<String>) -> Result<Builder> {
        for h in &headers {
            if let Some((key, header)) = h.split_once(":") {
                log::debug!(
                    "Adding header - key: '{}', value: '{}'",
                    key.trim(),
                    header.trim()
                );
                builder = builder.header(
                    http::header::HeaderName::from_bytes(key.trim().as_bytes())
                        .map_err(|e| FerretError::InvalidArg(format!("bad header name: {e}")))?,
                    http::header::HeaderValue::from_str(header.trim())
                        .map_err(|e| FerretError::InvalidArg(format!("bad header value: {e}")))?,
                );
            } else {
                log::warn!("Invalid header format: {}", h);
            }
        }
        log::info!("Successfully added headers: {:?}", builder.headers_ref());
        Ok(builder)
    }
}
