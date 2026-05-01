pub mod args;
pub mod error;
pub mod http;

pub use args::{Args, Method};
use bytes::Bytes;
pub use error::FerretError;
pub use http::{HttpClient, HttpResponse};

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

    let result = async {
        let args = validate_args(args)?;
        send_request(args).await
    }
    .await;

    match result {
        Ok(body) => println!("{}", body),
        Err(e) => log::error!("{}", e),
    };

    // see https://github.com/cloudflare/foundations/pull/168 for fix
    // remove Cargo.toml patch once merged
    driver.shutdown_logger();
}

async fn send_request(args: Args) -> Result<String, FerretError> {
    let client = HttpClient::new()?;
    let url = &args.url;
    let headers = args.header.unwrap_or_default();

    let response = match args.method {
        Some(Method::Get) => client.get(url, headers).await?,
        Some(Method::Post) => {
            client
                .post(url, headers, Bytes::from(args.data.unwrap()))
                .await?
        }
        None => return Err(FerretError::InvalidArg("No method provided".to_string())),
    };

    Ok(response.body)
}

fn validate_args(mut args: Args) -> Result<Args, FerretError> {
    let method = args.method.unwrap_or(if args.data.is_none() {
        Method::Get
    } else {
        Method::Post
    });
    args.method = Some(method);

    if method == Method::Get && args.data.is_some() {
        log::warn!("data argument (-d, --data) provided for GET request");
    }
    if method == Method::Post {
        if args.header.as_ref().is_none_or(|headers| {
            !headers
                .iter()
                .any(|h| h.to_ascii_lowercase().contains("content-type"))
        }) {
            log::warn!(
                "Header (-H, --header) does not contain \"Content-Type\", defaulting to application/x-www-form-urlencoded"
            );
            args.header
                .get_or_insert(Vec::new())
                .push("Content-Type:application/x-www-form-urlencoded".to_string());
        }

        if args.data.is_none() {
            return Err(FerretError::InvalidArg(
                "no data argument (-d, --data) provided for POST request".to_string(),
            ));
        }
    }

    log::debug!("{:?}", args);

    Ok(args)
}

fn configure_logging(args: &Args) -> BootstrapResult<TelemetryDriver> {
    let service_info: foundations::ServiceInfo = foundations::service_info!();
    let mut settings = TelemetrySettings::default();
    settings.logging.output = LogOutput::Stderr;

    settings.logging.verbosity = match args.verbosity {
        0_u8 => LogVerbosity::Warning,
        1_u8 => LogVerbosity::Info,
        2_u8 => LogVerbosity::Debug,
        _ => LogVerbosity::Trace,
    };

    // takes priority over verbosity
    settings.logging.verbosity = match args.silent {
        true => LogVerbosity::Critical,
        false => settings.logging.verbosity,
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
    use crate::{Args, validate_args};
    use clap::Parser;
    use test_case::test_case;

    #[test_case(&["ferret", "https://test_url.com"], true, "get" ; "default get")]
    #[test_case(&["ferret", "https://test_url.com", "-d", "testdata"], true, "post" ; "default post")]
    #[test_case(&["ferret", "https://test_url.com", "-X", "post"], false, "" ; "post without data")]
    #[test_case(&["ferret", "https://test_url.com", "-X", "post", "-d", "testdata"], true, "content-type" ; "post without header")]
    #[test_case(&["ferret", "https://test_url.com", "-d", "testdata", "-H", "content-type:json"], true, "json" ; "post with header")]
    fn test_args_validation(case: &[&str], should_pass: bool, should_contain: &str) {
        let args = Args::parse_from(case);
        let result = validate_args(args);

        if should_pass {
            assert!(result.is_ok());
            if !should_contain.is_empty() {
                let validated = result.unwrap();
                let all_fields = format!(
                    "{:?} {:?} {:?}",
                    validated.method, validated.header, validated.data
                );
                assert!(all_fields.to_lowercase().contains(should_contain));
            }
        } else {
            assert!(result.is_err());
        }
    }
}
