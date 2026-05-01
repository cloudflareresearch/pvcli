use crate::error::{FerretError, Result};
use bytes::Bytes;
use clap::Parser;
use foundations::telemetry::log;
use std::fs;

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq)]
pub enum Method {
    Get,
    Post,
}

pub struct TlsConfig<'a> {
    pub cacert: Option<&'a str>,
}

#[derive(Parser, Debug)]
#[command(name = "ferret", about = "A curl-like client for privacy protocols")]
#[command(next_line_help = true)]
pub struct Args {
    pub url: String,

    #[arg(short, long, action = clap::ArgAction::Count)]
    /// -v: info logs | -vv: debug logs | -vvv: all logs
    pub verbosity: u8,

    /// boolean flag to suppress all non-error output
    #[arg(short, long)]
    pub silent: bool,

    #[arg(short = 'X', long, ignore_case = true)]
    pub method: Option<Method>,

    #[arg(short = 'H', long)]
    pub header: Vec<String>,

    /// ferret uses "Content-Type: application/x-www-form-urlencoded" by default. See --header to customize
    #[arg(short, long, value_parser = parse_data)]
    pub data: Option<String>,

    /// path to CA certificate (PEM format) for TLS validation.
    /// If using --proxy, this is ignored. Use --proxy-cacert to specify a CA cert for the gateway when using OHTTP.
    #[arg(long = "cacert")]
    pub cacert: Option<String>,

    /// url to proxy for CONNECT or OHTTP
    #[arg(short = 'x', long)]
    pub proxy: Option<String>,

    /// path to OHTTP gateway ("{proxy}/{gateway_path}")
    #[arg(long, default_value = "gateway")]
    pub gateway_path: String,

    /// path to OHTTP gateway config ("{proxy}/{config-path}")
    #[arg(long, default_value = "ohttp-config")]
    pub config_path: String,

    /// path to CA certificate (PEM format) for validating the --proxy gateway's TLS certificate.
    #[arg(long = "proxy-cacert")]
    pub proxy_cacert: Option<String>,

    /// boolean flag to use ohttp, requires a proxy (see --proxy)
    #[arg(short, long, requires = "proxy")]
    pub ohttp: bool,

    /// relay URL for OHTTP, if different from proxy URL
    #[arg(long, requires = "ohttp")]
    pub first_hop: Option<String>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            url: String::new(),
            verbosity: 0,
            silent: false,
            method: None,
            header: vec![],
            data: None,
            cacert: None,
            proxy: None,
            gateway_path: "gateway".to_string(),
            config_path: "ohttp-config".to_string(),
            ohttp: false,
            first_hop: None,
            proxy_cacert: None,
        }
    }
}

impl Args {
    pub fn proxy_tls_config(&self) -> TlsConfig<'_> {
        TlsConfig {
            cacert: self.proxy_cacert.as_deref(),
        }
    }

    pub fn tls_config(&self) -> TlsConfig<'_> {
        TlsConfig {
            cacert: self.cacert.as_deref(),
        }
    }

    /// Validates the provided arguments and prints all warnings, then errors if any warnings are found.
    /// This is done to avoid silent failures where the client runs but doesn't behave as the user intended due to invalid args.
    pub fn validate(&mut self) -> Result<()> {
        self.setup_args()?;

        let warnings = [self.validate_basic()?, self.validate_ohttp()?].concat();
        let active: Vec<_> = warnings.into_iter().filter(|(_, cond)| *cond).collect();

        if !active.is_empty() {
            log::info!("Use --help for more information on valid arguments");
            for (msg, _) in active {
                log::warn!("{}", msg);
            }
            return Err(FerretError::InvalidArg(format!(
                "Argument validation failed for {:?}",
                self,
            )));
        }

        log::debug!("Validated args: {:?}", self);

        Ok(())
    }

    fn setup_args(&mut self) -> Result<()> {
        if !self.contains(&self.header, "user-agent") {
            let user_agent_header = format!(
                "User-Agent:{}/{}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            );
            log::debug!(
                "Header (-H, --header) does not contain \"User-Agent\", defaulting to {}",
                user_agent_header,
            );
            self.header.push(user_agent_header);
        }

        let method = self.method.unwrap_or(if self.data.is_none() {
            Method::Get
        } else {
            Method::Post
        });
        self.method = Some(method);

        // Standard content types for different types of requests
        if method == Method::Post && !self.contains(&self.header, "content-type") {
            let default_content_type = "Content-Type:application/x-www-form-urlencoded".to_string();
            log::debug!(
                "Header (-H, --header) does not contain \"Content-Type\", defaulting to {}",
                default_content_type,
            );
            self.header.push(default_content_type);
        }

        Ok(())
    }

    fn validate_basic(&self) -> Result<Vec<(String, bool)>> {
        let warnings: Vec<(String, bool)> = vec![
            (
                "URL is empty, must be provided".to_string(),
                self.url.is_empty(),
            ),
            (
                "data argument (-d, --data) provided for GET request".to_string(),
                self.method == Some(Method::Get) && self.data.is_some(),
            ),
            (
                "no data argument (-d, --data) provided for POST request".to_string(),
                self.method == Some(Method::Post) && self.data.is_none(),
            ),
        ];
        Ok(warnings)
    }

    fn validate_ohttp(&self) -> Result<Vec<(String, bool)>> {
        let warnings: Vec<(String, bool)> = vec![
            (
                "--cacert is not used with --ohttp (gateway handles target TLS). Did you mean --proxy-cacert?".to_string(),
                self.ohttp && self.cacert.is_some(),
            ),
            (
                "--proxy-cacert is not used without --ohttp or --proxy".to_string(),
                self.proxy.is_none() && self.proxy_cacert.is_some(),
            ),
        ];
        Ok(warnings)
    }

    fn contains(&self, vec: &[String], key: &str) -> bool {
        vec.iter().any(|h| {
            h.to_ascii_lowercase()
                .contains(key.to_ascii_lowercase().as_str())
        })
    }
}

#[derive(Debug)]
pub struct RequestArgs {
    pub method: Method,
    pub url: String,
    pub headers: Vec<String>,
    pub body: Option<Bytes>,
}

impl TryFrom<Args> for RequestArgs {
    type Error = FerretError;
    fn try_from(args: Args) -> Result<Self> {
        Ok(RequestArgs {
            method: args.method.ok_or_else(|| {
                FerretError::InvalidArg("No method provided for RequestArgs conversion".to_string())
            })?,
            url: args.url,
            headers: args.header,
            body: args.data.map(Bytes::from),
        })
    }
}

fn parse_data(d: &str) -> std::result::Result<String, String> {
    if let Some(path) = d.strip_prefix("@") {
        fs::read_to_string(path).map_err(|e| format!("failed to read file '{}': {}", path, e))
    } else {
        Ok(d.to_string())
    }
}
