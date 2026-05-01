use httpmock::MockServer;
use std::env::var;

pub const ECHO_BODY: &str = "This is a test body for OHTTP encryption and decryption";

pub const MOCK_GATEWAY_KEY_RESPONSE: &str =
    "0029000020f891675f4f738c4b23e9a32942f1508db5daaf395b0e78a471907eb457e15c7c000400010001";

pub fn setup_mock_server() -> MockServer {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method("GET").path("/testget");
        then.status(200).body("get successful");
    });
    server.mock(|when, then| {
        when.method("GET").path("/ohttp-config");
        then.status(200)
            .body(hex::decode(MOCK_GATEWAY_KEY_RESPONSE).unwrap());
    });
    server.mock(|when, then| {
        when.method("POST").path("/testpost").body(ECHO_BODY);
        then.status(200).body(ECHO_BODY);
    });
    server.mock(|when, then| {
        when.method("POST").path("/testpost").body_includes("data");
        then.status(200).body("post successful");
    });

    server
}

pub fn get_mock_server() -> String {
    setup_mock_server().base_url()
}

pub fn get_mock_gateway() -> String {
    var("GATEWAY_URL").unwrap_or_else(|_| "http://localhost:8787".into())
}
