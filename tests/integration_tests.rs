mod common;

use common::get_mock_server;
use ferret::{Args, Method, run};
use test_case::test_case;

#[test_case(Args {url: format!("{}/testget", get_mock_server()), ..Default::default()}, "get successful" ; "basic get")]
#[test_case(Args {url: format!("{}/testpost", get_mock_server()), data: Some("data".into()), ..Default::default()}, "post successful" ; "basic post")]
#[test_case(Args {url: format!("{}/testget", get_mock_server()), method: Some(Method::Get), data: Some("data".into()), ..Default::default()}, "get successful" ; "get with data")]
#[test_case(Args {url: format!("{}/invalid", get_mock_server()), ..Default::default()}, "{\"message\":\"Request did not match any route or mock\"}" ; "get invalid path")]
#[test_case(Args {url: "https://invalid.com".into(), ..Default::default()}, "client error" ; "invalid url fails")]
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
