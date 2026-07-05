pub mod args;
mod client;
pub mod error;

pub use args::{Args, Method};
pub use client::{Http2Client, Http3Client, HttpClient, HttpClientKind, HttpResponse, OHttpClient};

use clap::Parser;
use color_eyre::eyre::{Result, WrapErr, eyre};
use foundations::{
    BootstrapResult,
    telemetry::{
        self, TelemetryConfig, TelemetryDriver, log,
        settings::{LogFormat, LogOutput, LogVerbosity, TelemetrySettings},
    },
};

use crate::args::TlsConfig;

pub async fn tunnel() {
    let args = Args::parse();
    let mut driver = configure_logging(&args).expect("error configuring telemetry logging");
    if let Err(e) = color_eyre::install() {
        // enable for better error messages
        log::error!("Failed to install color_eyre: {:?}", e);
        // Proceeding without color_eyre, but error messages may be less informative
    }

    let result = run_handle_error(args).await;

    driver.shutdown_logger();
    print!("{}", result);
}

pub async fn run_handle_error(args: Args) -> String {
    match run(args).await {
        Ok(body) => body,
        Err(e) => {
            log::error!("{:?}", e);
            log::error!("See -v for info, -vv for debug, -vvv for trace logs");
            String::new()
        }
    }
}

pub async fn run(args: Args) -> Result<String> {
    Ok(raw_run(args).await?.body_as_string_lossy())
}

pub async fn raw_run(mut args: Args) -> Result<HttpResponse> {
    args.validate()?;
    let (client, tls_config) = select_http_client(&args).await?;
    client.send_request(args.try_into()?, &tls_config).await
}

async fn select_http_client(args: &Args) -> Result<(HttpClientKind, TlsConfig)> {
    if args.ohttp {
        return Ok((
            HttpClientKind::OHttp(
                OHttpClient::new(
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
                .wrap_err("OHTTP Client initialization error")?,
            ),
            TlsConfig::default(),
        ));
    }

    if args.proxy.is_some() {
        if args.proxy_http3 {
            if args.http3 {
                return Err(eyre!(
                    "MASQUE, or proxy-http3 connect with inner http3 is not implemented yet"
                ));
            }
            return Err(eyre!(
                "CONNECT-TLS proxying through http3 is not implemented yet"
            ));
        } else {
            log::info!("[CLIENT] Using HTTP/2 for proxy connection");
            return Ok((HttpClientKind::Http2(Http2Client {}), args.tls_config()));
        }
    }

    if args.http3 {
        return Ok((
            HttpClientKind::Http3(
                Http3Client::new()
                    .await
                    .wrap_err("HTTP/3 Client initialization error")?,
            ),
            args.tls_config(),
        ));
    }

    Ok((HttpClientKind::Http2(Http2Client {}), args.tls_config()))
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

    #[test_case(&["pvcli", "https://test_url.com"], true, "get" ; "default get")]
    #[test_case(&["pvcli", "https://test_url.com", "-d", "testdata"], true, "post" ; "default post")]
    #[test_case(&["pvcli", "https://test_url.com", "-d", "@./tests/testdata.txt"], true, "hello world" ; "post data with filepath")]
    #[test_case(&["pvcli", "https://test_url.com", "-X", "post"], false, "" ; "post without data")]
    #[test_case(&["pvcli", "https://test_url.com", "-X", "post", "-d", "testdata"], true, "content-type" ; "http2 post without header")]
    #[test_case(&["pvcli", "https://test_url.com", "--ohttp", "-x", "proxyurl.com"], true, "user-agent" ; "ohttp without header")]
    #[test_case(&["pvcli", "https://test_url.com", "-d", "testdata", "-H", "content-type:json"], true, "json" ; "post with header")]
    #[test_case(&["pvcli", "https://test_url.com", "--http3", "--proxy", "proxyurl.com"], false, "support http3" ; "http3 with proxy requires proxy-http3")]
    #[test_case(&["pvcli", "https://test_url.com", "--proxy", "proxyurl.com", "--proxy-http3"], true, "proxy_http3: true" ; "proxy-http3 connect is valid but unsupported")]
    #[test_case(&["pvcli", "https://test_url.com", "--http3", "--proxy", "proxyurl.com", "--proxy-http3"], true, "proxy_http3: true" ; "MASQUE, or proxy-http3 connect with inner http3 is valid but unsupported")]
    fn test_args_validation(case: &[&str], expect_pass: bool, expected_contain: &str) {
        let mut args = Args::parse_from(case);
        let result = args.validate();

        if expect_pass {
            assert!(result.is_ok(), "result should be Ok(), is {:?}", result);
            let all_fields = format!("{:?}", args).to_lowercase();
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
