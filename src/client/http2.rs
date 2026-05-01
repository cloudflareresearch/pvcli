use super::{
    HttpBody, HttpClient, HttpResponse, RequestHandler, cert::build_ssl_context_builder,
    log_and_execute_request,
};
use crate::args::{RequestArgs, TlsConfig};

use boring::ssl::{SslConnector, SslMethod};
use color_eyre::eyre::{Result, WrapErr};
use foundations::telemetry::log;
use http_body_util::BodyExt;
use hyper::{Request, Response, body::Incoming};
use hyper_boring::v1::HttpsConnector;
use hyper_util::{
    client::legacy::Client, client::legacy::connect::HttpConnector, rt::TokioExecutor,
};

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
        let https = {
            // wrap TCP connection with TLS
            let mut http = HttpConnector::new();
            http.enforce_http(false);
            let mut ssl = SslConnector::builder(SslMethod::tls())?;
            ssl.set_alpn_protos(b"\x02h2")?;
            build_ssl_context_builder(
                &mut ssl,
                tls_config.cacert,
                tls_config.client,
                tls_config.key,
            )
            .wrap_err("Failed to build HTTP/2 boringSSL context")?;

            HttpsConnector::with_connector(http, ssl)?
        };

        log::debug!("Successfully initialized HTTPS Connector for HTTP2 Client",);

        let client: Client<_, HttpBody> = Client::builder(TokioExecutor::new())
            // .http2_only(true) // TODO: --http2 flag to force this
            .build(https);

        log::debug!("Successfully initialized HTTP/2 Client");
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
