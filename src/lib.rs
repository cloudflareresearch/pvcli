pub mod args;
mod client;
pub mod error;

pub use args::{Args, Method};
pub use client::{Http2Client, HttpClient, HttpClientKind, HttpResponse, OHttpClient};
pub use error::{FerretError, Result};

use clap::Parser;
use foundations::{
    BootstrapResult,
    telemetry::{
        self, TelemetryConfig, TelemetryDriver, log,
        settings::{LogFormat, LogOutput, LogVerbosity, TelemetrySettings},
    },
};

pub async fn tunnel() {
    let args = Args::parse();
    let mut driver = configure_logging(&args).expect("error configuring telemetry logging");

    let result = run_handle_error(args).await;

    driver.shutdown_logger();
    print!("{}", result);
}

pub async fn run_handle_error(args: Args) -> String {
    match run(args).await {
        Ok(body) => body,
        Err(e) => {
            log::error!("{}", e);
            String::new()
        }
    }
}

pub async fn run(mut args: Args) -> Result<String> {
    args.validate()?;
    let client = select_http_client(&args)?;
    Ok(client
        .send_request(args.try_into()?)
        .await?
        .body_as_string_lossy())
}

fn select_http_client(args: &Args) -> Result<HttpClientKind> {
    if args.ohttp {
        Ok(HttpClientKind::OHttp(OHttpClient::new(
            args.proxy.clone(),
            args.gateway_path.clone(),
            args.config_path.clone(),
            &args.proxy_tls_config(),
        )?))
    } else if let Some(_proxy_url) = &args.proxy {
        Err(FerretError::Todo(
            "CONNECT proxying not implemented yet".to_string(),
        ))
    } else {
        Ok(HttpClientKind::Http2(Http2Client::new(&args.tls_config())?))
    }
}

fn configure_logging(args: &Args) -> BootstrapResult<TelemetryDriver> {
    let service_info: foundations::ServiceInfo = foundations::service_info!();
    let mut settings = TelemetrySettings::default();
    settings.logging.output = LogOutput::Stderr;

    settings.logging.verbosity = if args.silent {
        LogVerbosity::Critical
    } else {
        match args.verbosity {
            0 => LogVerbosity::Warning,
            1 => LogVerbosity::Info,
            2 => LogVerbosity::Debug,
            _ => LogVerbosity::Trace,
        }
    };

    settings.logging.format = LogFormat::Text;

    telemetry::init(TelemetryConfig {
        service_info: &service_info,
        settings: &settings,
        custom_server_routes: vec![],
    })
}

#[cfg(test)]
mod unit_tests {
    use crate::Args;
    use clap::Parser;
    use test_case::test_case;

    #[test_case(&["ferret", "https://test_url.com"], true, "get" ; "default get")]
    #[test_case(&["ferret", "https://test_url.com", "-d", "testdata"], true, "post" ; "default post")]
    #[test_case(&["ferret", "https://test_url.com", "-d", "@./tests/testdata.txt"], true, "hello world" ; "post data with filepath")]
    #[test_case(&["ferret", "https://test_url.com", "-X", "post"], false, "" ; "post without data")]
    #[test_case(&["ferret", "https://test_url.com", "-X", "post", "-d", "testdata"], true, "content-type" ; "http2 post without header")]
    #[test_case(&["ferret", "https://test_url.com", "--ohttp", "-x", "proxyurl.com"], true, "user-agent" ; "ohttp without header")]
    #[test_case(&["ferret", "https://test_url.com", "-d", "testdata", "-H", "content-type:json"], true, "json" ; "post with header")]
    fn test_args_validation(case: &[&str], expect_pass: bool, expected_contain: &str) {
        let mut args = Args::parse_from(case);
        let result = args.validate();

        if expect_pass {
            assert!(result.is_ok(), "result should be Ok()");
            let all_fields =
                format!("{:?} {:?} {:?}", args.method, args.header, args.data).to_lowercase();
            assert!(
                all_fields.contains(expected_contain),
                "expected fields {:?} to contain '{}'",
                all_fields,
                expected_contain
            );
        } else {
            assert!(result.is_err(), "should have failed");
        }
    }
}
