use bytes::Bytes;
use clap::Parser;
use color_eyre::eyre::{Report, Result, eyre};
use foundations::telemetry::log;
use std::fs;

use crate::client::redact_args;

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq)]
pub enum Method {
    Get,
    Post,
}

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cacert: Option<String>,
    pub client: Option<String>,
    pub key: Option<String>,
}

#[derive(Parser, Debug, Clone)]
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

    /// HTTP method to use, defaults to GET or POST based on presence of --data
    /// In proxying contexts, this is the method for the inner request.
    #[arg(short = 'X', long, ignore_case = true)]
    pub method: Option<Method>,

    #[arg(short = 'H', long)]
    pub header: Vec<String>,

    /// ferret uses "Content-Type: application/x-www-form-urlencoded" by default. See --header to customize
    #[arg(short, long, value_parser = parse_data)]
    pub data: Option<String>,

    /// path to CA certificate (PEM format) for TLS validation.
    /// If using --proxy, this is ignored. Use --proxy-cacert to specify a CA cert for the gateway when using OHTTP.
    #[arg(long, conflicts_with = "proxy")]
    pub cacert: Option<String>,

    /// path to client certificate (PEM format) for TLS validation.
    /// If using --proxy, this is ignored. Use --proxy-client to specify a client cert for the gateway when using OHTTP.
    #[arg(long, conflicts_with = "proxy", requires = "key")]
    pub client: Option<String>,

    /// path to key certificate (PEM format) for TLS validation.
    /// If using --proxy, this is ignored. Use --proxy-key to specify a key cert for the gateway when using OHTTP.
    #[arg(long, conflicts_with = "proxy", requires = "client")]
    pub key: Option<String>,

    /// Use http3 for the request instead of the default http2.
    /// If used with --proxy, only the inner request will be http3.
    /// This requires the outer request to be http3 as well, specified with --proxy-http3.
    #[arg(long, conflicts_with = "ohttp")]
    pub http3: bool,

    /** PROXYING */
    /// url to proxy for CONNECT proxying or OHTTP
    #[arg(short = 'x', long)]
    pub proxy: Option<String>,

    /// boolean flag to use ohttp, requires a proxy (see --proxy)
    /// to proxy over http3, use --proxy-http3.
    #[arg(short, long, requires = "proxy", conflicts_with = "http3")]
    pub ohttp: bool,

    /// boolean flag to use http3 for the outer request to the proxy
    #[arg(long, requires = "proxy")]
    pub proxy_http3: bool,

    /// path to OHTTP gateway ("{proxy}/{gateway_path}")
    #[arg(long, default_value = "gateway", requires = "proxy")]
    pub gateway_path: String,

    /// path to OHTTP gateway config ("{proxy}/{config-path}")
    #[arg(long, default_value = "ohttp-config", requires = "proxy")]
    pub config_path: String,

    /// proxy headers are applied to the encrypted request sent to the specified --proxy
    #[arg(long, requires = "proxy")]
    pub proxy_header: Vec<String>,

    /// path to CA certificate (PEM format) for validating the --proxy gateway's TLS certificate.
    #[arg(long, requires = "proxy")]
    pub proxy_cacert: Option<String>,

    /// path to client certificate (PEM format) for TLS validation for --proxy.
    #[arg(long, requires = "proxy", requires = "proxy_key")]
    pub proxy_client: Option<String>,

    /// path to key certificate (PEM format) for TLS validation --proxy.
    #[arg(long, requires = "proxy", requires = "proxy_client")]
    pub proxy_key: Option<String>,

    /// relay URL for OHTTP, if different from proxy URL
    #[arg(long, requires = "proxy")]
    pub first_hop: Option<String>,

    /// first-hop headers are applied to the encrypted request sent to the specified --first-hop
    #[arg(long, requires = "first_hop")]
    pub first_hop_header: Vec<String>,

    /// path to CA certificate (PEM format) for validating the --first-hop gateway's TLS certificate.
    #[arg(long, requires = "first_hop")]
    pub first_hop_cacert: Option<String>,

    /// path to client certificate (PEM format) for TLS validation for --first-hop.
    #[arg(long, requires = "first_hop", requires = "first_hop_key")]
    pub first_hop_client: Option<String>,

    /// path to key certificate (PEM format) for TLS validation --first-hop.
    #[arg(long, requires = "first_hop", requires = "first_hop_client")]
    pub first_hop_key: Option<String>,
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
            client: None,
            key: None,
            http3: false,
            proxy: None,
            gateway_path: "gateway".to_string(),
            config_path: "ohttp-config".to_string(),
            proxy_header: vec![],
            ohttp: false,
            proxy_http3: false,
            proxy_cacert: None,
            proxy_client: None,
            proxy_key: None,
            first_hop: None,
            first_hop_header: vec![],
            first_hop_cacert: None,
            first_hop_client: None,
            first_hop_key: None,
        }
    }
}

impl TlsConfig {
    pub fn is_empty(&self) -> bool {
        self.cacert.is_none() && self.client.is_none() && self.key.is_none()
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cacert: None,
            client: None,
            key: None,
        }
    }
}

impl Args {
    pub fn proxy_tls_config(&self) -> TlsConfig {
        TlsConfig {
            cacert: self.proxy_cacert.clone(),
            client: self.proxy_client.clone(),
            key: self.proxy_key.clone(),
        }
    }

    pub fn first_hop_tls_config(&self) -> TlsConfig {
        TlsConfig {
            cacert: self.first_hop_cacert.clone(),
            client: self.first_hop_client.clone(),
            key: self.first_hop_key.clone(),
        }
    }

    pub fn tls_config(&self) -> TlsConfig {
        TlsConfig {
            cacert: self.cacert.clone(),
            client: self.client.clone(),
            key: self.key.clone(),
        }
    }

    /// Validates the provided arguments and prints all warnings, then errors if any warnings are found.
    /// This is done to avoid silent failures where the client runs but doesn't behave as the user intended due to invalid args.
    pub fn validate(&mut self) -> Result<()> {
        self.setup_args()?;

        let warnings = [self.validate_basic()?, self.validate_proxy()?].concat();
        let active: Vec<_> = warnings.into_iter().filter(|(_, cond)| *cond).collect();

        log::debug!("Validated args: {:?}", redact_args(self));

        if !active.is_empty() {
            log::info!("See --help for more information on valid arguments");
            for (msg, _) in active {
                log::warn!("{}", msg);
            }
            return Err(eyre!("Argument validation failed for CLI argument input"));
        }

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

    fn validate_proxy(&self) -> Result<Vec<(String, bool)>> {
        let warnings: Vec<(String, bool)> = vec![
            (
                "--proxy paired with --http3 requires --proxy-http3 as we need the outer protocol to support http3 if the inner request is http3".to_string(),
                self.http3 && self.proxy.is_some() && !self.proxy_http3,
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

#[derive(Debug, Clone)]
pub struct RequestArgs {
    pub method: Method,
    pub url: String,
    pub headers: Vec<String>,
    pub body: Option<Bytes>,
    pub proxy_connect: Option<String>,
    pub proxy_tls_config: Option<TlsConfig>,
    pub proxy_header: Vec<String>,
}

impl TryFrom<Args> for RequestArgs {
    type Error = Report;
    fn try_from(args: Args) -> Result<Self> {
        let is_connect = args.proxy.is_some() && !args.ohttp;
        let proxy_tls_config = is_connect.then(|| args.proxy_tls_config());
        let proxy_header = is_connect.then(|| args.proxy_header).unwrap_or_default();
        Ok(RequestArgs {
            method: args.method.ok_or_else(|| {
                eyre!("No method provided for RequestArgs conversion".to_string())
            })?,
            url: args.url,
            headers: args.header,
            body: args.data.map(Bytes::from),
            proxy_connect: is_connect.then(|| args.proxy.clone()).flatten(),
            proxy_tls_config,
            proxy_header,
        })
    }
}

impl Default for RequestArgs {
    fn default() -> Self {
        Self {
            method: Method::Get,
            url: String::new(),
            headers: vec![],
            body: None,
            proxy_header: vec![],
            proxy_connect: None,
            proxy_tls_config: None,
        }
    }
}

fn parse_data(d: &str) -> std::result::Result<String, String> {
    if let Some(path) = d.strip_prefix("@") {
        fs::read_to_string(path).map_err(|e| format!("failed to read file '{}': {}", path, e))
    } else {
        Ok(d.to_string())
    }
}
