use super::{HttpBody, HttpClient, HttpResponse, RequestHandler, log_and_execute_request};
use crate::args::{RequestArgs, TlsConfig};

use color_eyre::eyre::{Result, WrapErr};
use foundations::telemetry::log;
use http_body_util::BodyExt;
use hyper::{Request, Response, body::Incoming};
use hyper_rustls::HttpsConnector;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use rustls::{ClientConfig, RootCertStore};
use rustls_pemfile::certs;
use std::fs::File;
use std::io::BufReader;

pub struct Http2Client {
    client: Client<HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>, HttpBody>,
}

impl HttpClient for Http2Client {
    async fn send_request(&self, args: RequestArgs) -> Result<HttpResponse> {
        let request = RequestHandler::create_request(args).wrap_err("Failed to create request")?;
        log_and_execute_request(request, |req| self.execute(req))
            .await
            .wrap_err("Failed to execute HTTP/2 request")
    }
}

impl Http2Client {
    pub fn new(tls_config: &TlsConfig) -> Result<Self> {
        let root_store =
            build_root_store(tls_config.cacert).wrap_err("Failed to build root store")?;
        let config = build_client_config(root_store).wrap_err("Failed to build client config")?;

        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(config)
            .https_or_http()
            .enable_http2()
            .build();

        let client: Client<_, HttpBody> = Client::builder(TokioExecutor::new())
            // .http2_only(true) // TODO: --http2 flag to force this
            .build(https);

        log::debug!("Successfully initialized HTTP2 Client");
        Ok(Self { client })
    }

    pub async fn execute(&self, request: Request<HttpBody>) -> Result<HttpResponse> {
        let response: Response<Incoming> = self.client.request(request).await?;

        let http_response = HttpResponse {
            version: response.version(),
            status: response.status().as_u16(),
            headers: response.headers().clone(),
            body: response.into_body().collect().await?.to_bytes(),
        };
        Ok(http_response)
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
        log::warn!("Failed to load native cert: {:?}", err);
    }

    // custom certificate
    if let Some(ca_path) = cacert {
        log::debug!(
            "Loading Http2Client config with cacert (--proxy-cacert/--cacert) at path {}",
            ca_path
        );
        let mut reader = BufReader::new(
            File::open(ca_path)
                .wrap_err_with(|| format!("Failed to open CA cert at {} ", ca_path))?,
        );
        for cert in certs(&mut reader) {
            let cert = cert.wrap_err("Failed to parse CA cert (must be PEM format)")?;
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
