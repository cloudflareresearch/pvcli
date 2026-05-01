mod common;

use common::{ECHO_BODY, MockH2Server, MockRelay, get_mock_gateway};
use ferret::{Args, Method, run};
use std::sync::LazyLock;
use test_case::test_case;

static MOCK_SERVER: LazyLock<MockH2Server> = LazyLock::new(|| MockH2Server::new());

fn get_mock_server_url() -> String {
    MOCK_SERVER.url()
}

#[test_case(Args {url: format!("{}/testget", get_mock_server_url()), ..Default::default()}, "get successful" ; "basic get")]
#[test_case(Args {url: format!("{}/testpost", get_mock_server_url()), data: Some("data".into()), ..Default::default()}, "post successful" ; "basic post")]
#[test_case(Args {url: format!("{}/testget", get_mock_server_url()), method: Some(Method::Get), data: Some("data".into()), ..Default::default()}, "validation failed" ; "get with data")]
#[test_case(Args {url: format!("{}/invalid", get_mock_server_url()), ..Default::default()}, "{\"message\":\"Request did not match any route or mock\"}" ; "get invalid path")]
#[test_case(Args {url: "https://invalid.com".into(), ..Default::default()}, "client error" ; "invalid url fails")]
#[test_case(Args {url: "".into(), ..Default::default()}, "validation failed" ; "empty url fails")]
#[test_case(Args {url: format!("{}/testget", get_mock_server_url()), cacert: Some("./nonexistent.pem".into()), ..Default::default()}, "certificate" ; "invalid cacert fails")]
#[tokio::test]
async fn test_http2(args: Args, expected_result: &str) {
    let result = run(args).await;
    match result {
        Ok(output) => assert_eq!(output, expected_result),
        Err(e) => assert!(
            e.to_string().to_lowercase().contains(expected_result),
            "expected error '{}' to contain '{}'",
            e,
            expected_result
        ),
    };
}

#[test_case(Args {url: format!("{}/testget", get_mock_server_url()), ohttp: true, proxy: Some(get_mock_gateway()), ..Default::default()}, "get successful" ; "ohttp basic get")]
#[test_case(Args {url: format!("{}/testget", get_mock_server_url()), ohttp: true, proxy: Some(get_mock_gateway()), header: vec!["content-type:application/json".into()], ..Default::default()}, "get successful" ; "ohttp with header")]
#[test_case(Args {url: format!("{}/testpost", get_mock_server_url()), ohttp: true, proxy: Some(get_mock_gateway()), data: Some("data".into()), ..Default::default()}, "post successful" ; "ohttp basic post")]
#[test_case(Args {url: format!("{}/testpost", get_mock_server_url()), ohttp: true, proxy: Some(get_mock_gateway()), data: Some(ECHO_BODY.into()), ..Default::default()}, ECHO_BODY ; "ohttp echo body")]
#[test_case(Args {url: format!("{}/invalid", get_mock_server_url()), ohttp: true, proxy: Some(get_mock_gateway()), ..Default::default()}, "Request did not match" ; "ohttp invalid path")]
#[test_case(Args {url: format!("{}/testget", get_mock_server_url()), ohttp: true, ..Default::default()}, "proxy" ; "ohttp without proxy fails")]
#[test_case(Args {url: format!("{}/testget", get_mock_server_url()), ohttp: true, proxy: Some(get_mock_gateway()), proxy_cacert: Some("./nonexistent.pem".into()), ..Default::default()}, "certificate" ; "ohttp invalid proxy-cacert fails")]
#[tokio::test]
async fn test_ohttp_with_gateway(args: Args, expected_result: &str) {
    let result = run(args).await;
    match result {
        Ok(output) => assert!(
            output.contains(expected_result),
            "expected '{}' to contain '{}'",
            output,
            expected_result
        ),
        Err(e) => assert!(
            e.to_string().to_lowercase().contains(expected_result),
            "expected error '{}' to contain '{}'",
            e,
            expected_result
        ),
    };
}

#[tokio::test]
async fn test_ohttp_with_relay() {
    let mock_relay = MockRelay::new().await;
    let args = Args {
        url: format!("{}/testget", get_mock_server_url()),
        ohttp: true,
        proxy: Some(get_mock_gateway()),
        first_hop: Some(format!("http://{}/relay", mock_relay.url())),
        ..Default::default()
    };
    let result = run(args).await;
    let expected_result = "get successful";
    match result {
        Ok(output) => assert!(
            output.contains(expected_result),
            "expected '{}' to contain '{}'",
            output,
            expected_result
        ),
        Err(e) => assert!(
            e.to_string().to_lowercase().contains(expected_result),
            "expected error '{}' to contain '{}'",
            e,
            expected_result
        ),
    };
}
