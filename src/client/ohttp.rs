// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use super::{HttpClient, HttpResponse, RequestHandler};
use crate::{
    Http2Client, Http3Client,
    args::{Method, RequestArgs, TlsConfig},
    client::{Resolver, TransportClientKind, redact_request_args},
    error::PvcliError,
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
    proxy_http_client: TransportClientKind,
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
        log::info!("[FETCH KEY] Requesting gateway key");
        let (encap_config, hex_key_response) = self
            .fetch_proxy_key()
            .await
            .wrap_err("Failed to fetch OHTTP proxy key")?;
        log::info!("[FETCH KEY]"; "key" => hex_key_response.body_as_hex());

        log::info!("[ENCRYPT] Encrypt inner request");
        let (bytes, response_receiving_ctx) = self
            .encrypt(args, encap_config)
            .await
            .wrap_err("Failed to encrypt inner request")?;

        log::info!("[OUTER REQUEST] Sending outer request to proxy");
        let response = self
            .send_outer_request(bytes)
            .await
            .wrap_err("Failed to send outer request")?;
        log::info!("[OUTER REQUEST] Response status: {}", response.status);

        log::info!("[DECRYPT] Decrypt response");
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
        resolver: &Resolver,
    ) -> Result<Self> {
        let Some(proxy_url) = proxy_url else {
            return Err(eyre!("No proxy url (--proxy, -x) provided for ohttp"));
        };

        // cleanup args and construct full URLs for config and gateway
        let proxy_url = proxy_url.trim_end_matches('/');
        let gateway_path = gateway_path.trim_start_matches('/');
        let config_path = config_path.trim_start_matches('/');

        let gateway_url = format!("{}/{}", proxy_url, gateway_path);
        let key_config_url = format!("{}/{}", proxy_url, config_path);

        log::debug!("Constructed OHTTP endpoints";
            "gateway_url" => gateway_url.clone(),
            "config_url" => key_config_url.clone()
        );

        let proxy_http_client = if proxy_http3 {
            log::info!("[OHTTP] Using HTTP/3 client for proxy requests");
            TransportClientKind::Http3(
                Http3Client::new(resolver)
                    .await
                    .wrap_err("Failed to initialize HTTP/3 client for OHTTP proxy")?,
            )
        } else {
            log::info!("[OHTTP] Using HTTP/2 client for proxy requests");
            TransportClientKind::Http2(Http2Client::new(resolver))
        };

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
            ..Default::default()
        };

        log::trace!("Key request"; "args" => format!("{:?}", redact_request_args(&proxy_args)));

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
            return Err(PvcliError::UnexpectedStatus {
                status: response.status,
                message: format!(
                    "Fetching OHTTP gateway key at {} returned error {}, use -vvv to debug raw response body",
                    self.proxy_config_url,
                    response.body_as_string_escaped()
                ),
            })?;
        }

        let hex_key = hex::encode(response.body.as_ref());
        log::debug!(
            "Queried OHTTP key directory";
            "n_bytes" => hex_key.len() / 2,
            "hex_key" => hex_key.clone()
        );

        let mut stream_buf: EmptyStreamBuf<Report> = StreamBuf::from(response.body);
        let client_config: ClientConfig = decode_config(&mut stream_buf)
            .await
            .wrap_err("Failed to decode client config")?;
        log::info!("[FETCH KEY] Decoded key client config");
        log::trace!("Full decoded client config: {:?}", client_config);

        let encap_config = client_config.first_encap_config(); // likely preferred config
        log::debug!("Using encap config"; "key_id" => encap_config.key_id);
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
                log::info!(
                    "[OUTER REQUEST] Send request to first hop relay";
                    "url" => first_hop
                );
                let mut headers = self.first_hop_headers.clone();
                headers.push("Content-Type: message/ohttp-req".to_string());
                (
                    RequestArgs {
                        method: Method::Post,
                        url: first_hop.clone(),
                        headers,
                        body: Some(encrypted_request),
                        ..Default::default()
                    },
                    &self.first_hop_tls_config,
                )
            }
            None => {
                log::info!(
                    "[OUTER REQUEST] Send request to proxy gateway";
                    "url" => self.proxy_gateway_url.clone()
                );
                let mut headers = self.proxy_headers.clone();
                headers.push("Content-Type: message/ohttp-req".to_string());
                (
                    RequestArgs {
                        method: Method::Post,
                        url: self.proxy_gateway_url.clone(),
                        headers,
                        body: Some(encrypted_request),
                        ..Default::default()
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

        Ok(response)
    }

    async fn encrypt(
        &self,
        args: RequestArgs,
        encap_config: EncapConfig,
    ) -> Result<(Bytes, ResponseReceivingContext)> {
        let (request_sending_ctx, response_receiving_ctx) = setup_request_encapsulation(
            encap_config,
            MESSAGE_BHTTP_REQUEST,
            MESSAGE_BHTTP_RESPONSE,
        )
        .map_err(|e| PvcliError::HpkeError(format!("{:?}", e)))
        .wrap_err("Failed to set up request encapsulation, use -vvv to debug raw bytes")?;
        log::info!("[ENCRYPT] Use key config to set encapsulation context");

        log::trace!("Request sending context: {:?}", request_sending_ctx);
        log::trace!("Response receiving context: {:?}", response_receiving_ctx);

        // the actual request you want to send through OHTTP
        let inner_request = RequestHandler::build_request_wrapper(args)
            .wrap_err("Failed to create inner request")?;
        let bhttp_encoded =
            encode_request(inner_request).wrap_err("Failed to encode inner request")?;

        let bhttp_bytes: Bytes = bhttp_encoded
            .try_collect::<Vec<Bytes>>()
            .await
            .wrap_err("Failed to collect BHTTP encoded request bytes")?
            .concat()
            .into();

        log::info!(
            "[ENCRYPT] BHTTP-encoded inner request";
            "n_bytes" => bhttp_bytes.len()
        );
        log::trace!(
            "BHTTP encoded request bytes";
            "n_bytes" => bhttp_bytes.len(),
            "hex" => hex::encode(bhttp_bytes.as_ref())
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
            "Encrypted request bytes";
            "n_bytes" => encrypted_request.len(),
            "hex" => hex::encode(encrypted_request.as_ref())
        );

        log::info!(
            "[ENCRYPT] Encapsulated request (HPKE)";
            "n_bytes" => encrypted_request.len()
        );

        Ok((encrypted_request, response_receiving_ctx))
    }

    async fn decrypt(
        &self,
        response: HttpResponse,
        response_receiving_ctx: ResponseReceivingContext,
    ) -> Result<HttpResponse> {
        log::trace!(
            "Raw response body";
            "n_bytes" => response.body.len(),
            "body" => response.body_as_string_escaped()
        );
        match response.status {
            200 => {}
            526 => {
                return Err(PvcliError::UnexpectedStatus {
                    status: response.status,
                    message: format!(
                        "OHTTP Gateway returned error, try disabling WARP or use a different wifi network and try again: {}",
                        response.body_as_string_escaped()
                    ),
                })?;
            }
            403 => {
                return Err(PvcliError::UnexpectedStatus {
                    status: response.status,
                    message: format!(
                        "OHTTP Gateway returned error, check if the endpoint is a relay with a path: {}",
                        response.body_as_string_escaped()
                    ),
                })?;
            }
            _ => {
                return Err(PvcliError::UnexpectedStatus {
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
        log::info!(
            "[DECRYPT] Decapsulated response";
            "n_bytes" => decapsulated_bhttp.len()
        );

        log::trace!(
            "Decapsulated response";
            "n_bytes" => decapsulated_bhttp.len(),
            "hex" => hex::encode(decapsulated_bhttp.as_ref())
        );

        let decapsulated_buf: EmptyStreamBuf<Report> = StreamBuf::from(decapsulated_bhttp);
        let bhttp_decoded = decode_response(decapsulated_buf)
            .await
            .wrap_err("Failed to decode BHTTP response")?;

        let (version, status, headers) = (
            bhttp_decoded.version(),
            bhttp_decoded.status().as_u16(),
            bhttp_decoded.headers().clone(),
        );
        let body = bhttp_decoded.into_body().collect().await?.to_bytes();

        log::info!("[DECRYPT] Decoded response";
            "n_bytes" => body.len()
        );

        let http_response = HttpResponse {
            version,
            status,
            headers,
            body,
        };
        http_response.log_response();

        Ok(http_response)
    }
}

#[cfg(test)]
mod unit_tests {
    use crate::{Args, OHttpClient, client::Resolver};
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
            &Resolver::default(),
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
