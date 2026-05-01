use super::{HttpClient, HttpResponse};
use crate::{
    Http2Client,
    args::{Method, RequestArgs},
    error::{FerretError, Result},
};
use bytes::Bytes;
use foundations::telemetry::log;
use hex;
use ohttp_hpke::client::{ClientConfig, EncapConfig, ResponseReceivingContext, decode_config};
use stream_buf::{EmptyStreamBuf, StreamBuf};

pub struct OHttpClient {
    proxy_http_client: Http2Client,
    proxy_config_url: String,
    _proxy_gateway_url: String,
}

impl HttpClient for OHttpClient {
    async fn send_request(&self, _args: RequestArgs) -> Result<HttpResponse> {
        let (_encap_config, hex_key_response) = self.fetch_proxy_key().await?;
        Ok(hex_key_response)

        // self.encrypt().await?;

        // self.create_ohttp_request().await?;

        // self.decrypt().await
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
            _proxy_gateway_url: gateway_url,
        })
    }

    async fn fetch_proxy_key(&self) -> Result<(EncapConfig, HttpResponse)> {
        let proxy_args = RequestArgs {
            method: Method::Get,
            url: self.proxy_config_url.clone(),
            headers: vec![],
            body: None,
        };

        log::debug!("Fetching key from OHTTP proxy client: {:?}", proxy_args);

        let response = self.proxy_http_client.send_request(proxy_args).await?;

        if response.status != 200 {
            log::debug!(
                "Key Response (String): {}",
                response.body_as_string_escaped()?
            );
            return Err(FerretError::UnexpectedStatus {
                status: response.status,
                message: format!(
                    "Gateway at {} returned error status: {}",
                    self.proxy_config_url, response.status
                ),
            });
        }

        let hex_key = hex::encode(response.body.as_ref());
        log::info!(
            "Successfully queried OHTTP key directory (HEX): {}",
            hex_key
        );

        let mut stream_buf: EmptyStreamBuf<FerretError> = StreamBuf::from(response.body);
        let client_config: ClientConfig = decode_config(&mut stream_buf).await?;
        let encap_config = client_config.first_encap_config(); // likely preferred config
        log::info!(
            "Successfully extracted encapsulated config key: {:?}",
            encap_config
        );

        Ok((
            encap_config,
            HttpResponse {
                status: 200,
                body: Bytes::from(hex_key),
            },
        ))
    }

    async fn _create_ohttp_request(&self) -> Result<()> {
        Err(FerretError::Todo(
            "OHTTP request creation not implemented yet".to_string(),
        ))
    }

    async fn _encrypt(&self) -> Result<(Bytes, ResponseReceivingContext)> {
        Err(FerretError::Todo(
            "OHTTP request encryption not implemented yet".to_string(),
        ))
    }

    async fn _decrypt(&self) -> Result<HttpResponse> {
        Err(FerretError::Todo(
            "OHTTP response decryption not implemented yet".to_string(),
        ))
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
                http_response.body_as_string_lossy().unwrap(),
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
