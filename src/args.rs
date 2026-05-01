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

    #[arg(short, long, value_parser = parse_data)]
    /// ferret uses "Content-Type: application/x-www-form-urlencoded" by default. See --header to customize
    pub data: Option<String>,

    /// url to proxy for CONNECT or OHTTP
    #[arg(short = 'x', long)]
    pub proxy: Option<String>,

    /// path to OHTTP gateway ("{proxy}/{gateway_path}")
    #[arg(long, default_value = "gateway")]
    pub gateway_path: String,

    /// path to OHTTP gateway config ("{proxy}/{config-path}")
    #[arg(long, default_value = "ohttp-config")]
    pub config_path: String,

    /// boolean flag to use ohttp, requires a proxy (see --proxy)
    #[arg(short, long, requires = "proxy")]
    pub ohttp: bool,
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
            proxy: None,
            gateway_path: "gateway".to_string(),
            config_path: "ohttp-config".to_string(),
            ohttp: false,
        }
    }
}

impl Args {
    pub fn validate(&mut self) -> Result<()> {
        if !self
            .header
            .iter()
            .any(|h| h.to_ascii_lowercase().contains("user-agent"))
        {
            let user_agent_header = format!(
                "User-Agent:{}/{}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            );
            self.header.push(user_agent_header);
        }

        if self.url.is_empty() {
            return Err(FerretError::InvalidArg("URL is required".to_string()));
        }

        let method = self.method.unwrap_or(if self.data.is_none() {
            Method::Get
        } else {
            Method::Post
        });
        self.method = Some(method);

        if method == Method::Get && self.data.is_some() {
            // curl allows data with GET
            log::warn!("data argument (-d, --data) provided for GET request");
        }
        if method == Method::Post && self.data.is_none() {
            return Err(FerretError::InvalidArg(
                "no data argument (-d, --data) provided for POST request".to_string(),
            ));
        }

        // Standard content types for different types of requests
        if method == Method::Post
            && !self
                .header
                .iter()
                .any(|h| h.to_ascii_lowercase().contains("content-type"))
        {
            let default_content_type = "Content-Type:application/x-www-form-urlencoded".to_string();
            log::debug!(
                "Header (-H, --header) does not contain \"Content-Type\", defaulting to {}",
                default_content_type,
            );
            self.header.push(default_content_type);
        }

        log::debug!("Validated args: {:?}", self);

        Ok(())
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
