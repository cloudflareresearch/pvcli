mod common;

use common::{ECHO_BODY, MockH2Server, MockRelay, get_mock_gateway};
use pvcli::{Args, Method, run};
use std::sync::LazyLock;
use test_case::test_case;

static MOCK_H2_SERVER: LazyLock<MockH2Server> = LazyLock::new(MockH2Server::new);

fn get_mock_server_url() -> String {
    MOCK_H2_SERVER.url()
}

async fn run_and_match(args: Args, expected_result: &str) {
    let result = run(args).await;
    match result {
        Ok(output) => assert!(
            output.contains(expected_result),
            "expected '{}' to contain '{}'",
            output,
            expected_result
        ),
        Err(e) => assert!(
            format!("{:?}", e)
                .to_lowercase()
                .contains(expected_result.to_lowercase().as_str()),
            "expected error '{}' to contain '{}'",
            format!("{:?}", e).to_lowercase(),
            expected_result
        ),
    };
}

#[test_case(Args {url: format!("{}/testget", get_mock_server_url()), ..Default::default()}, "get successful" ; "basic get")]
#[test_case(Args {url: format!("{}/testpost", get_mock_server_url()), data: Some("data".into()), ..Default::default()}, "post successful" ; "basic post")]
#[tokio::test]
async fn test_http2_success(args: Args, expected_result: &str) {
    run_and_match(args, expected_result).await;
}

#[test_case(Args {url: format!("{}/testget", get_mock_server_url()), method: Some(Method::Get), data: Some("data".into()), ..Default::default()}, "validation failed" ; "get with data")]
#[test_case(Args {url: format!("{}/invalid", get_mock_server_url()), ..Default::default()}, "Request did not match any route" ; "get invalid path")]
#[test_case(Args {url: "https://invalid.com".into(), ..Default::default()}, "Failed to send request" ; "invalid url fails")]
#[test_case(Args {url: "".into(), ..Default::default()}, "validation failed" ; "empty url fails")]
#[tokio::test]
async fn test_http2_failure(args: Args, expected_result: &str) {
    run_and_match(args, expected_result).await;
}

#[test_case(Args {url: format!("{}/testget", get_mock_server_url()), ohttp: true, proxy: Some(get_mock_gateway()), ..Default::default()}, "get successful" ; "ohttp basic get")]
#[test_case(Args {url: format!("{}/testget", get_mock_server_url()), ohttp: true, proxy: Some(get_mock_gateway()), header: vec!["content-type:application/json".into()], ..Default::default()}, "get successful" ; "ohttp with header")]
#[test_case(Args {url: format!("{}/testpost", get_mock_server_url()), ohttp: true, proxy: Some(get_mock_gateway()), data: Some("data".into()), ..Default::default()}, "post successful" ; "ohttp basic post")]
#[test_case(Args {url: format!("{}/testpost", get_mock_server_url()), ohttp: true, proxy: Some(get_mock_gateway()), data: Some(ECHO_BODY.into()), ..Default::default()}, ECHO_BODY ; "ohttp echo body")]
#[tokio::test]
async fn test_ohttp_with_gateway_success(args: Args, expected_result: &str) {
    run_and_match(args, expected_result).await;
}

#[test_case(Args {url: format!("{}/invalid", get_mock_server_url()), ohttp: true, proxy: Some(get_mock_gateway()), ..Default::default()}, "Request did not match" ; "ohttp invalid path")]
#[test_case(Args {url: format!("{}/testget", get_mock_server_url()), ohttp: true, ..Default::default()}, "proxy" ; "ohttp without proxy fails")]
#[tokio::test]
async fn test_ohttp_with_gateway_failure(args: Args, expected_result: &str) {
    run_and_match(args, expected_result).await;
}

#[test_case(Args {url: format!("{}/testget", get_mock_server_url()), ohttp: true, proxy: Some(get_mock_gateway()), ..Default::default()}, "get successful" ; "ohttp first-hop basic get")]
#[test_case(Args {url: format!("{}/testpost", get_mock_server_url()), ohttp: true, proxy: Some(get_mock_gateway()), data: Some("data".into()), ..Default::default()}, "post successful" ; "ohttp first-hop basic post")]
#[tokio::test]
async fn test_ohttp_with_first_hop_relay(mut args: Args, expected_result: &str) {
    let mock_relay = MockRelay::new().await;
    args.first_hop = Some(format!("http://{}/relay", mock_relay.url()));
    run_and_match(args, expected_result).await;
}
