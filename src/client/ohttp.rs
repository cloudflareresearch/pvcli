use super::{HttpClient, HttpResponse};
use crate::{
    Http2Client,
    args::{Method, RequestArgs},
    error::{FerretError, Result},
};
use bytes::Bytes;
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
    proxy_http_client: Http2Client,
    proxy_config_url: String,
    proxy_gateway_url: String,
}

impl HttpClient for OHttpClient {
    async fn send_request(&self, args: RequestArgs) -> Result<HttpResponse> {
        let (encap_config, _hex_key_response) = self.fetch_proxy_key().await?;

        let (bytes, response_receiving_ctx) = self.encrypt(args, encap_config).await?;

        let response = self.dispatch_outer_request(bytes).await?;

        self.decrypt(response, response_receiving_ctx).await
    }
}

impl OHttpClient {
    pub fn new(
        proxy_url: Option<String>,
        gateway_path: String,
        config_path: String,
    ) -> Result<Self> {
        let Some(proxy_url) = proxy_url else {
            return Err(FerretError::InvalidArg(
                "No proxy url (--proxy, -x) provided for ohttp".to_string(),
            ));
        };

        // cleanup args and construct full URLs for config and gateway
        let proxy_url = proxy_url.trim_end_matches('/');
        let gateway_path = gateway_path.trim_start_matches('/');
        let config_path = config_path.trim_start_matches('/');

        let gateway_url = format!("{}/{}", proxy_url, gateway_path);
        let key_config_url = format!("{}/{}", proxy_url, config_path);

        log::debug!("Constructed OHTTP gateway URL: {}", gateway_url);
        log::debug!("Constructed OHTTP config URL: {}", key_config_url);

        Ok(Self {
            proxy_http_client: Http2Client::new()?,
            proxy_config_url: key_config_url,
            proxy_gateway_url: gateway_url,
        })
    }

    async fn fetch_proxy_key(&self) -> Result<(EncapConfig, HttpResponse)> {
        log::info!("Fetching OHTTP key configuration, use -vvv to debug the raw response body");

        let proxy_args = RequestArgs {
            method: Method::Get,
            url: self.proxy_config_url.clone(),
            headers: vec![],
            body: None,
        };

        log::trace!("Key request args: {:?}", proxy_args);

        let response = self.proxy_http_client.send_request(proxy_args).await?;
        if response.status != 200 {
            log::error!(
                "OHTTP Key at {} responded with non-200 status, use -vvv to debug raw response body: {}",
                self.proxy_config_url,
                response.status,
            );

            return Err(FerretError::UnexpectedStatus {
                status: response.status,
                message: format!(
                    "Gateway at {} returned error status: {}",
                    self.proxy_config_url, response.status
                ),
            });
        }
        log::trace!("Raw key response: {:?}", response.body);

        let hex_key = hex::encode(response.body.as_ref());
        log::info!(
            "Successfully queried OHTTP key directory ({} bytes) [HEX]: {}",
            hex_key.len() / 2,
            hex_key
        );

        log::debug!("Decoded client config, extracting encapsulation config");
        let mut stream_buf: EmptyStreamBuf<FerretError> = StreamBuf::from(response.body);
        let client_config: ClientConfig = decode_config(&mut stream_buf).await?;
        let encap_config = client_config.first_encap_config(); // likely preferred config
        log::info!("Successfully extracted encapsulated config key");
        log::trace!("Encapsulated config key: {:?}", encap_config);

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

    async fn dispatch_outer_request(&self, encrypted_request: Bytes) -> Result<HttpResponse> {
        log::info!(
            "Sending encapsulated request to gateway: {}",
            self.proxy_gateway_url
        );

        let outer_request = self.proxy_http_client.create_request(RequestArgs {
            method: Method::Post,
            url: self.proxy_gateway_url.clone(),
            headers: vec!["Content-Type: message/ohttp-req".to_string()],
            body: Some(encrypted_request),
        })?;

        self.proxy_http_client.dispatch_request(outer_request).await
    }

    async fn encrypt(
        &self,
        args: RequestArgs,
        encap_config: EncapConfig,
    ) -> Result<(Bytes, ResponseReceivingContext)> {
        log::info!("Starting OHTTP encryption process, use -vvv to debug raw bytes at each step");
        let (request_sending_ctx, response_receiving_ctx) = setup_request_encapsulation(
            encap_config,
            MESSAGE_BHTTP_REQUEST,
            MESSAGE_BHTTP_RESPONSE,
        )?;
        log::trace!("Request sending context: {:?}", request_sending_ctx);
        log::trace!("Response receiving context: {:?}", response_receiving_ctx);

        // the actual request you want to send through OHTTP
        log::trace!("BHTTP encoding inner request");
        let inner_request = self.proxy_http_client.create_request(args)?;
        let bhttp_encoded = encode_request(inner_request)?;

        log::trace!("Starting BHTTP byte collection");
        let bhttp_bytes: Bytes = bhttp_encoded
            .map_err(|e| FerretError::OhttpError(format!("BHTTP encoding error: {}", e)))
            .try_collect::<Vec<Bytes>>()
            .await?
            .concat()
            .into();

        log::trace!(
            "BHTTP encoded request bytes ({} bytes) [HEX]: {}",
            bhttp_bytes.len(),
            hex::encode(bhttp_bytes.as_ref())
        );

        log::trace!("Encapsulating inner request");
        let bhttp_stream: EmptyStreamBuf<FerretError> = StreamBuf::from(bhttp_bytes);
        let encapsulated_stream = request_sending_ctx.encapsulate_non_chunked_content(bhttp_stream);

        log::trace!("Starting encrypted byte collection");
        let encrypted_request: Bytes = encapsulated_stream
            .try_collect::<Vec<Bytes>>()
            .await?
            .concat()
            .into();

        log::trace!(
            "Encrypted request bytes ({} bytes) [HEX]: {}",
            encrypted_request.len(),
            hex::encode(encrypted_request.as_ref())
        );

        log::info!("Successfully encapsulated request with HPKE");

        Ok((encrypted_request, response_receiving_ctx))
    }

    async fn decrypt(
        &self,
        response: HttpResponse,
        response_receiving_ctx: ResponseReceivingContext,
    ) -> Result<HttpResponse> {
        log::info!("Decrypting OHTTP response, use -vvv to debug raw bytes at each step");
        if response.status != 200 {
            return Err(FerretError::UnexpectedStatus {
                status: response.status,
                message: format!(
                    "Gateway returned error status {}: {}",
                    response.status,
                    response.body_as_string_escaped()
                ),
            });
        }

        log::trace!("Decapsulating response");
        let mut response_buf: EmptyStreamBuf<FerretError> = StreamBuf::from(response.body);

        let decrypted_bhttp = response_receiving_ctx
            .decapsulate_non_chunked_content(&mut response_buf)
            .await?;

        log::trace!(
            "Decrypted BHTTP ({} bytes) [HEX]: {}",
            decrypted_bhttp.len(),
            hex::encode(decrypted_bhttp.as_ref())
        );

        log::trace!("Decoding BHTTP response");
        let decrypted_buf: EmptyStreamBuf<FerretError> = StreamBuf::from(decrypted_bhttp);
        let bhttp_decoded = decode_response(decrypted_buf).await?;

        let http_response = HttpResponse {
            version: bhttp_decoded.version(),
            status: bhttp_decoded.status().as_u16(),
            headers: bhttp_decoded.headers().clone(),
            body: bhttp_decoded.into_body().collect().await?.to_bytes(),
        };

        log::info!("Successfully decrypted OHTTP response");
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
    #[test_case(Args {url: get_local_mock_server(), ohttp: true, proxy: Some(format!("{}/wrong-path", get_local_mock_server())), ..Default::default()}, "error status" ; "incorrect proxy path")]
    #[tokio::test]
    async fn test_fetch_ohttp_key(mut args: Args, expected_result: &str) {
        args.validate()
            .expect("Invalid args in unit test; they should be valid");

        let ohttp_client = OHttpClient::new(
            args.proxy.clone(),
            args.gateway_path.clone(),
            args.config_path.clone(),
        )
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
