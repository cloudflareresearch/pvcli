// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use axum::body::Body;
use axum::response::Response;
use axum::{Router, body::Bytes, routing::post};
use httpmock::MockServer;
use pvcli::HttpClient;
use pvcli::args::ResolveOverride;
use pvcli::{
    Http2Client,
    args::{Method, RequestArgs, TlsConfig},
};
use std::env::var;
use std::net::SocketAddr;
use url::Url;

pub const ECHO_BODY: &str = "This is a test body for OHTTP encryption and decryption";

pub const MOCK_GATEWAY_KEY_RESPONSE: &str =
    "0029000020f891675f4f738c4b23e9a32942f1508db5daaf395b0e78a471907eb457e15c7c000400010001";

pub struct MockH2Server {
    server: MockServer,
}

impl MockH2Server {
    pub fn new() -> Self {
        let server = MockServer::start();

        MockH2Server::mock_http2(&server);
        MockH2Server::mock_ohttp(&server);

        MockH2Server { server }
    }

    pub fn url(&self) -> String {
        self.server.base_url()
    }

    pub fn addr(&self) -> SocketAddr {
        self.server.address().clone()
    }

    fn mock_http2(server: &MockServer) {
        server.mock(|when, then| {
            when.method("GET").path("/testget");
            then.status(200).body("get successful");
        });
        server.mock(|when, then| {
            when.method("POST").path("/testpost").body(ECHO_BODY);
            then.status(200).body(ECHO_BODY);
        });
        server.mock(|when, then| {
            when.method("POST").path("/testpost").body_includes("data");
            then.status(200).body("post successful");
        });
    }

    // Solely to test that the OHTTP client can fetch the gateway's public key and encrypt the request properly
    // Does not actually implement OHTTP request handling
    fn mock_ohttp(server: &MockServer) {
        server.mock(|when, then| {
            when.method("GET").path("/ohttp-config");
            then.status(200)
                .body(hex::decode(MOCK_GATEWAY_KEY_RESPONSE).unwrap());
        });
    }
}

pub struct MockRelay {
    addr: SocketAddr,
}

impl MockRelay {
    pub async fn new() -> Self {
        let app = Router::new().route("/relay", post(MockRelay::relay_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0") // 0 = random port
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        MockRelay { addr }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr.clone()
    }

    async fn relay_handler(headers: axum::http::HeaderMap, body: Bytes) -> Response<Body> {
        if headers.get("content-type")
            != Some(&http::header::HeaderValue::from_static("message/ohttp-req"))
        {
            Response::builder()
                .status(400)
                .header("content-type", "message/ohttp-res")
                .body(Body::from("invalid request to relay"))
                .unwrap()
        } else {
            let http_client = Http2Client::default();
            let url = format!("{}/gateway", get_mock_gateway());
            let body = Some(body);
            let args = RequestArgs {
                method: Method::Post,
                url,
                headers: headers
                    .into_iter()
                    .map(|(k, v)| format!("{}:{}", k.unwrap().as_str(), v.to_str().unwrap_or("")))
                    .collect(),
                body,
                ..Default::default()
            };
            let tls = TlsConfig {
                cacert: None,
                client: None,
                key: None,
            };
            let result = http_client.send_request(args, &tls).await;

            match result {
                Ok(resp) => {
                    let body_bytes = resp.body.clone();
                    let mut builder = Response::builder().status(resp.status);
                    for (k, v) in resp.headers.iter() {
                        let key = k.as_str();
                        // skip these headers, as they're related to the hop transport-level connection.
                        // we rebuild the response so we shouldn't keep these headers which are no longer relevant
                        if key != "transfer-encoding" && key != "connection" && key != "keep-alive"
                        {
                            builder = builder.header(k, v);
                        }
                    }
                    builder.body(Body::from(body_bytes)).unwrap()
                }
                Err(e) => Response::builder()
                    .status(502)
                    .body(Body::from(format!("relay failed: {:?}", e)))
                    .unwrap(),
            }
        }
    }
}

pub fn get_mock_gateway() -> String {
    var("GATEWAY_URL").unwrap_or_else(|_| "http://localhost:8787".into())
}

pub fn get_mock_gateway_override(host: &str) -> ResolveOverride {
    ResolveOverride {
        host: host.to_owned(),
        port: 80,
        addresses: vec![
            Url::parse(&get_mock_gateway())
                .expect("mock gateway url must be valid")
                .socket_addrs(|| Some(80))
                .expect("mock gateway address must be valid")
                .into_iter()
                .next()
                .expect("mock gateway address is expected to resolve to at least one address"),
        ],
    }
}
