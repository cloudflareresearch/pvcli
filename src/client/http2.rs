use super::{Body, HttpClient, HttpResponse};
use crate::Method;
use crate::args::{RequestArgs, TlsConfig};
use crate::error::{FerretError, Result};

use bytes::Bytes;
use foundations::telemetry::log;
use http::request::Builder;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::{Request, Response, body::Incoming};
use hyper_rustls::HttpsConnector;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use rustls::{ClientConfig, RootCertStore};
use rustls_pemfile::certs;
use std::fs::File;
use std::io::BufReader;

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
    pub fn new(tls_config: &TlsConfig) -> Result<Self> {
        let root_store = build_root_store(tls_config.cacert)?;
        let config = build_client_config(root_store)?;

        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(config)
            .https_or_http()
            .enable_http2()
            .build();

        let client: Client<_, Body> = Client::builder(TokioExecutor::new())
            // .http2_only(true) // TODO: --http2 flag to force this
            .build(https);

        log::trace!("Successfully initialized HTTP2 Client");
        Ok(Self { client })
    }

    pub fn create_request(&self, args: RequestArgs) -> Result<Request<Body>> {
        match args.method {
            Method::Get => self.build_request("GET", args.url, args.headers, None),
            Method::Post => {
                let body = args.body.ok_or(FerretError::InvalidArg(
                    "POST request requires a body".into(),
                ))?;
                self.build_request("POST", args.url, args.headers, Some(body))
            }
        }
    }

    fn build_request(
        &self,
        method: &str,
        url: String,
        headers: Vec<String>,
        body: Option<Bytes>,
    ) -> Result<Request<Body>> {
        log::info!("Creating {} request to {}", method, url);

        let uri = url.parse::<hyper::Uri>()?;

        log::trace!(
            "Parsed URI - scheme: {:?}, host: {:?}, path: {}",
            uri.scheme_str(),
            uri.host(),
            uri.path()
        );

        let builder = Request::builder().method(method).uri(&uri);
        let builder = self.consume_headers(builder, headers)?;

        let body: Body = match body {
            Some(b) => BoxBody::new(Full::new(b).map_err(|_| unreachable!())),
            None => BoxBody::new(Empty::<Bytes>::new().map_err(|_| unreachable!())),
        };

        let request = builder.body(body).expect("failed to build request");
        log::trace!("Request built: {:?}", request);
        Ok(request)
    }

    pub async fn dispatch_request(&self, request: Request<Body>) -> Result<HttpResponse> {
        log::debug!("Dispatching request to {:?}", request.uri());
        log::trace!("Full request details: {:?}", request);

        let response: Response<Incoming> = self
            .client
            .request(request)
            .await
            .map_err(FerretError::ClientError)?;

        let http_response = HttpResponse {
            version: response.version(),
            status: response.status().as_u16(),
            headers: response.headers().clone(),
            body: response.into_body().collect().await?.to_bytes(),
        };

        log::info!("Successfully received response");
        http_response.log_response();

        Ok(http_response)
    }

    fn consume_headers(&self, mut builder: Builder, headers: Vec<String>) -> Result<Builder> {
        for h in &headers {
            if let Some((key, header)) = h.split_once(":") {
                log::trace!("Adding header: {}: {}", key.trim(), header.trim());
                builder = builder.header(
                    http::header::HeaderName::from_bytes(key.trim().as_bytes())
                        .map_err(|e| FerretError::InvalidArg(format!("bad header name: {e}")))?,
                    http::header::HeaderValue::from_str(header.trim())
                        .map_err(|e| FerretError::InvalidArg(format!("bad header value: {e}")))?,
                );
            } else {
                // match curl behavior: warn but continue without malformed header
                log::warn!("Invalid header format: {}", h);
            }
        }

        log::debug!("Headers configured: {:?}", builder.headers_ref());
        Ok(builder)
    }
}

fn build_root_store(cacert: Option<&str>) -> Result<RootCertStore> {
    log::debug!("Building root cert store");

    // add standard browser certificates
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // automatically add system CAs
    // note: we need this if we're using WARP
    let native_certs = rustls_native_certs::load_native_certs();
    for cert in native_certs.certs {
        root_store.add(cert)?;
    }
    for err in &native_certs.errors {
        log::warn!("Failed to load native cert: {}", err);
    }

    // custom certificate
    if let Some(ca_path) = cacert {
        log::debug!(
            "Loading Http2Client config with cacert (--proxy-cacert/--cacert) at path {}",
            ca_path
        );
        let mut reader = BufReader::new(File::open(ca_path).map_err(|e| {
            FerretError::CertificateError(format!("failed to open CA cert '{}': {}", ca_path, e))
        })?);
        for cert in certs(&mut reader) {
            let cert = cert.map_err(|e| {
                FerretError::CertificateError(format!(
                    "failed to parse CA cert (must be PEM format): {}",
                    e
                ))
            })?;
            root_store.add(cert)?;
        }
        log::info!("Loaded custom CA cert from {}", ca_path);
    }
    Ok(root_store)
}

fn build_client_config(root_store: RootCertStore) -> Result<ClientConfig> {
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    log::info!("Successfully built TLS client config");
    Ok(config)
}
