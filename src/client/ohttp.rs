use super::{HttpClient, HttpResponse, RequestHandler};
use crate::{
    Http2Client, Http3Client,
    args::{Method, RequestArgs, TlsConfig},
    client::ProxyClientKind,
    error::FerretError,
};

use bytes::Bytes;
use color_eyre::eyre::{Report, Result, WrapErr, eyre};
use foundations::telemetry::log;
use futures::TryStreamExt;
use hex;
use http_body_util::BodyExt;
use hyper_binary::{decode_response, encode_request};
use ohttp_hpke::client::{
    ClientConfig, EncapConfig, ResponseReceivingContext, decode_config, setup_request_encapsulation,
};
use stream_buf::{EmptyStreamBuf, StreamBuf};

const MESSAGE_BHTTP_REQUEST: &str = "message/bhttp request";
const MESSAGE_BHTTP_RESPONSE: &str = "message/bhttp response";

pub struct OHttpClient {
    proxy_http_client: ProxyClientKind,
    proxy_headers: Vec<String>,
    proxy_config_url: String,
    proxy_gateway_url: String,
    proxy_tls_config: TlsConfig,
    first_hop_url: Option<String>,
    first_hop_headers: Vec<String>,
    first_hop_tls_config: TlsConfig,
}

impl HttpClient for OHttpClient {
    async fn send_request(
        &self,
        args: RequestArgs,
        _tls_config: &TlsConfig, // OHTTP client manages its own TLS configs for proxy and first hop, so this is ignored
    ) -> Result<HttpResponse> {
        let (encap_config, _hex_key_response) = self
            .fetch_proxy_key()
            .await
            .wrap_err("Failed to fetch OHTTP proxy key")?;

        let (bytes, response_receiving_ctx) = self
            .encrypt(args, encap_config)
            .await
            .wrap_err("Failed to encrypt inner request")?;

        let response = self
            .send_outer_request(bytes)
            .await
            .wrap_err("Failed to send outer request")?;

        self.decrypt(response, response_receiving_ctx)
            .await
            .wrap_err("Failed to decrypt response")
    }
}

impl OHttpClient {
    pub async fn new(
        proxy_http3: bool,
        proxy_url: Option<String>,
        gateway_path: String,
        config_path: String,
        proxy_headers: Vec<String>,
        proxy_tls_config: &TlsConfig,
        first_hop_url: Option<String>,
        first_hop_headers: Vec<String>,
        first_hop_tls_config: &TlsConfig,
    ) -> Result<Self> {
        log::info!("Initializing OHTTP Client");
        let Some(proxy_url) = proxy_url else {
            return Err(eyre!("No proxy url (--proxy, -x) provided for ohttp"));
        };

        // cleanup args and construct full URLs for config and gateway
        let proxy_url = proxy_url.trim_end_matches('/');
        let gateway_path = gateway_path.trim_start_matches('/');
        let config_path = config_path.trim_start_matches('/');

        let gateway_url = format!("{}/{}", proxy_url, gateway_path);
        let key_config_url = format!("{}/{}", proxy_url, config_path);

        log::debug!("Constructed OHTTP gateway URL: {}", gateway_url);
        log::debug!("Constructed OHTTP config URL: {}", key_config_url);

        let proxy_http_client: ProxyClientKind = if proxy_http3 {
            log::info!("Using HTTP/3 client for OHTTP proxy communication");
            ProxyClientKind::Http3(
                Http3Client::new()
                    .await
                    .wrap_err("Failed to initialize HTTP/3 client for OHTTP proxy")?,
            )
        } else {
            log::info!("Using HTTP/2 client for OHTTP proxy communication");
            ProxyClientKind::Http2(Http2Client {})
        };

        log::info!("Successfully initialized OHTTP Client");

        Ok(Self {
            proxy_http_client,
            proxy_headers,
            proxy_config_url: key_config_url,
            proxy_gateway_url: gateway_url,
            proxy_tls_config: proxy_tls_config.clone(),
            first_hop_url: first_hop_url,
            first_hop_headers: first_hop_headers,
            first_hop_tls_config: first_hop_tls_config.clone(),
        })
    }

    async fn fetch_proxy_key(&self) -> Result<(EncapConfig, HttpResponse)> {
        let proxy_args = RequestArgs {
            method: Method::Get,
            url: self.proxy_config_url.clone(),
            headers: self.proxy_headers.clone(),
            body: None,
        };

        log::trace!("Key request args: {:?}", proxy_args);

        let response = self
            .proxy_http_client
            .send_request(proxy_args, &self.proxy_tls_config)
            .await
            .wrap_err(format!(
                "Failed to send request to proxy gateway {}",
                self.proxy_config_url
            ))?;

        log::trace!(
            "Raw key response body: {}",
            response.body_as_string_escaped()
        );
        if response.status != 200 {
            return Err(FerretError::UnexpectedStatus {
                status: response.status,
                message: format!(
                    "Fetching OHTTP gateway key at {} returned error {}, use -vvv to debug raw response body",
                    self.proxy_config_url,
                    response.body_as_string_escaped()
                ),
            })?;
        }

        let hex_key = hex::encode(response.body.as_ref());
        log::info!(
            "Successfully queried OHTTP key directory ({} bytes) [HEX]: {}",
            hex_key.len() / 2,
            hex_key
        );

        let mut stream_buf: EmptyStreamBuf<Report> = StreamBuf::from(response.body);
        let client_config: ClientConfig = decode_config(&mut stream_buf)
            .await
            .wrap_err("Failed to decode client config")?;
        log::info!("Decoded OHTTP client config");
        log::trace!("Full decoded client config: {:?}", client_config);

        let encap_config = client_config.first_encap_config(); // likely preferred config
        log::debug!("Using encap config key_id: {}", encap_config.key_id);
        log::trace!("Full encap config: {:?}", encap_config);

        Ok((
            encap_config,
            HttpResponse {
                version: response.version,
                status: 200,
                headers: response.headers,
                body: Bytes::from(hex_key),
            },
        ))
    }

    async fn send_outer_request(&self, encrypted_request: Bytes) -> Result<HttpResponse> {
        let (outer_request, tls_config) = match &self.first_hop_url {
            Some(first_hop) => {
                log::info!("Using first hop URL to send outer request: {}", first_hop);
                let mut headers = self.first_hop_headers.clone();
                headers.push("Content-Type: message/ohttp-req".to_string());
                (
                    RequestArgs {
                        method: Method::Post,
                        url: first_hop.clone(),
                        headers,
                        body: Some(encrypted_request),
                    },
                    &self.first_hop_tls_config,
                )
            }
            None => {
                log::info!(
                    "No first hop URL provided, using proxy gateway URL for outer request: {}",
                    self.proxy_gateway_url
                );
                let mut headers = self.proxy_headers.clone();
                headers.push("Content-Type: message/ohttp-req".to_string());
                (
                    RequestArgs {
                        method: Method::Post,
                        url: self.proxy_gateway_url.clone(),
                        headers,
                        body: Some(encrypted_request),
                    },
                    &self.proxy_tls_config,
                )
            }
        };

        let response = self
            .proxy_http_client
            .send_request(outer_request, tls_config)
            .await
            .wrap_err("Failed to execute outer OHTTP request")?;

        log::info!(
            "Received response to outer request with status: {}",
            response.status
        );
        Ok(response)
    }

    async fn encrypt(
        &self,
        args: RequestArgs,
        encap_config: EncapConfig,
    ) -> Result<(Bytes, ResponseReceivingContext)> {
        log::info!("Encapsulating inner request");
        let (request_sending_ctx, response_receiving_ctx) = setup_request_encapsulation(
            encap_config,
            MESSAGE_BHTTP_REQUEST,
            MESSAGE_BHTTP_RESPONSE,
        )
        .map_err(|e| FerretError::HpkeError(format!("{:?}", e)))
        .wrap_err("Failed to set up request encapsulation, use -vvv to debug raw bytes")?;

        log::trace!("Request sending context: {:?}", request_sending_ctx);
        log::trace!("Response receiving context: {:?}", response_receiving_ctx);

        // the actual request you want to send through OHTTP
        let inner_request =
            RequestHandler::create_request(args).wrap_err("Failed to create inner request")?;
        let bhttp_encoded =
            encode_request(inner_request).wrap_err("Failed to encode inner request")?;

        let bhttp_bytes: Bytes = bhttp_encoded
            .try_collect::<Vec<Bytes>>()
            .await
            .wrap_err("Failed to collect BHTTP encoded request bytes")?
            .concat()
            .into();

        log::info!(
            "BHTTP encoding inner request complete ({} bytes)",
            bhttp_bytes.len()
        );
        log::trace!(
            "BHTTP encoded request bytes ({} bytes) [HEX]: {}",
            bhttp_bytes.len(),
            hex::encode(bhttp_bytes.as_ref())
        );

        let bhttp_stream: EmptyStreamBuf<Report> = StreamBuf::from(bhttp_bytes);
        let encapsulated_stream = request_sending_ctx.encapsulate_non_chunked_content(bhttp_stream);
        log::debug!("Encapsulated inner request");

        let encrypted_request: Bytes = encapsulated_stream
            .try_collect::<Vec<Bytes>>()
            .await
            .wrap_err("Failed to collect encrypted request bytes")?
            .concat()
            .into();

        log::trace!(
            "Encrypted request bytes ({} bytes) [HEX]: {}",
            encrypted_request.len(),
            hex::encode(encrypted_request.as_ref())
        );

        log::info!(
            "Successfully encapsulated request with HPKE ({} bytes)",
            encrypted_request.len()
        );

        Ok((encrypted_request, response_receiving_ctx))
    }

    async fn decrypt(
        &self,
        response: HttpResponse,
        response_receiving_ctx: ResponseReceivingContext,
    ) -> Result<HttpResponse> {
        log::info!("Decrypting OHTTP response");
        log::trace!(
            "Raw response body ({} bytes): {}",
            response.body.len(),
            response.body_as_string_escaped()
        );
        match response.status {
            200 => {}
            526 => {
                return Err(FerretError::UnexpectedStatus {
                    status: response.status,
                    message: format!(
                        "OHTTP Gateway returned error, try disabling WARP or use a different wifi network and try again: {}",
                        response.body_as_string_escaped()
                    ),
                })?;
            }
            _ => {
                return Err(FerretError::UnexpectedStatus {
                    status: response.status,
                    message: format!(
                        "OHTTP Gateway returned error: {}",
                        response.body_as_string_escaped()
                    ),
                })?;
            }
        }

        let mut response_buf: EmptyStreamBuf<Report> = StreamBuf::from(response.body);

        let decapsulated_bhttp = response_receiving_ctx
            .decapsulate_non_chunked_content(&mut response_buf)
            .await
            .wrap_err(
                "Failed to decapsulate response. This may indicate the relay forwarded to a different gateway than specified by -x"
            )?;

        log::trace!(
            "Decapsulated response ({} bytes) [HEX]: {}",
            decapsulated_bhttp.len(),
            hex::encode(decapsulated_bhttp.as_ref())
        );

        let decapsulated_buf: EmptyStreamBuf<Report> = StreamBuf::from(decapsulated_bhttp);
        let bhttp_decoded = decode_response(decapsulated_buf)
            .await
            .wrap_err("Failed to decode BHTTP response")?;

        let http_response = HttpResponse {
            version: bhttp_decoded.version(),
            status: bhttp_decoded.status().as_u16(),
            headers: bhttp_decoded.headers().clone(),
            body: bhttp_decoded.into_body().collect().await?.to_bytes(),
        };

        log::info!("Successfully decapsulated OHTTP response");
        http_response.log_response();

        Ok(http_response)
    }
}

#[cfg(test)]
mod unit_tests {
    use crate::{Args, OHttpClient};
    use httpmock::MockServer;
    use test_case::test_case;

    const MOCK_GATEWAY_KEY_RESPONSE: &str =
        "0029000020f891675f4f738c4b23e9a32942f1508db5daaf395b0e78a471907eb457e15c7c000400010001";

    fn get_local_mock_server() -> String {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method("GET").path("/ohttp-config");
            then.status(200)
                .body(hex::decode(MOCK_GATEWAY_KEY_RESPONSE).unwrap());
        });

        server.base_url()
    }

    #[test_case(Args {url: get_local_mock_server(), ohttp: true, proxy: Some(get_local_mock_server()), ..Default::default()}, MOCK_GATEWAY_KEY_RESPONSE ; "fetch hex key from mock ohttp gateway")]
    #[test_case(Args {url: get_local_mock_server(), ohttp: true, proxy: Some(format!("{}/wrong-path", get_local_mock_server())), ..Default::default()}, "Request did not match any route" ; "incorrect proxy path")]
    #[tokio::test]
    async fn test_fetch_ohttp_key(mut args: Args, expected_result: &str) {
        args.validate()
            .expect("Invalid args in unit test; they should be valid");

        let ohttp_client = OHttpClient::new(
            args.proxy_http3,
            args.proxy.clone(),
            args.gateway_path.clone(),
            args.config_path.clone(),
            args.proxy_header.clone(),
            &args.proxy_tls_config(),
            args.first_hop.clone(),
            args.first_hop_header.clone(),
            &args.first_hop_tls_config(),
        )
        .await
        .expect("Failed to create OHTTP client with provided proxy URL");
        let result = ohttp_client.fetch_proxy_key().await;

        match result {
            Ok((_, http_response)) => assert_eq!(
                http_response.body_as_string_lossy(),
                expected_result,
                "expected identical mock hex key"
            ),
            Err(e) => assert!(
                e.to_string().contains(expected_result),
                "expected error message to contain: {}, got: {}",
                expected_result,
                e.to_string()
            ),
        }
    }
}
