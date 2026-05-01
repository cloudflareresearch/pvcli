use super::HttpBody;

use crate::args::{Method, RequestArgs};
use crate::client::{redact_headers, redact_headers_vec};
use bytes::Bytes;
use color_eyre::eyre::{Result, WrapErr, eyre};
use foundations::telemetry::log;
use http::request::Builder;
use http::{Request, uri::Scheme};
use http_body::Body;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};

pub const REQUEST_TIMEOUT_SECONDS: u64 = 10;

/**
 * This is a utility struct to help build requests for HTTP/2 and HTTP/3 clients, as much of their
 * request-building logic is shared.
 *
 * Decouples the request-building logic from the client-specific http request flow logic.
*/
pub struct RequestHandler;

impl RequestHandler {
    pub fn build_request_wrapper(args: RequestArgs) -> Result<Request<HttpBody>> {
        match args.method {
            Method::Get => RequestHandler::build_request("GET", args.url, args.headers, None),
            Method::Post => {
                let body = args.body.ok_or(eyre!("POST request requires a body"))?;
                RequestHandler::build_request("POST", args.url, args.headers, Some(body))
            }
        }
    }

    pub fn build_request(
        method: &str,
        url: String,
        headers: Vec<String>,
        body: Option<Bytes>,
    ) -> Result<Request<HttpBody>> {
        log::debug!("Creating {} request to {}", method, url);

        let uri = url.parse::<hyper::Uri>()?;
        let host = uri
            .host()
            .ok_or_else(|| eyre!("Target URL must include host"))?;
        let port = uri.port_u16().unwrap_or(match uri.scheme() {
            Some(s) if s == &Scheme::HTTPS => 443,
            _ => 80,
        });

        if uri.scheme_str().is_none() {
            return Err(eyre!("URL must include scheme (http:// or https://)"));
        }

        // for CONNECT, use authority-form: host:port
        let uri = if method == "CONNECT" {
            format!("{}:{}", host, port).parse::<hyper::Uri>()?
        } else {
            uri.clone()
        };

        log::debug!(
            "Parsed URI: scheme: {:?}, host: {:?}, port: {:?}, path: {}",
            uri.scheme_str(),
            uri.host(),
            uri.port_u16(),
            uri.path()
        );

        log::trace!(
            "Building request with headers: {:?}, body: {:?}",
            redact_headers_vec(&headers),
            body
        );

        let builder = Request::builder().method(method).uri(&uri);
        let builder = RequestHandler::consume_headers(builder, headers)
            .wrap_err("Failed to consume headers")?;

        let body: HttpBody = match body {
            Some(b) => BoxBody::new(Full::new(b).map_err(|_| unreachable!())),
            None => BoxBody::new(Empty::<Bytes>::new().map_err(|_| unreachable!())),
        };

        let request = builder.body(body).wrap_err("Failed to build request")?;
        log::debug!("Request details";
            "uri" => request.uri().to_string(),
            "headers" => format!("{:?}",
            redact_headers(request.headers())),
            "body" => format!("{:?} bytes", request.body().size_hint()),
            "version" => format!("{:?}", request.version()),
            "method" => request.method().to_string()
        );

        Ok(request)
    }

    fn consume_headers(mut builder: Builder, headers: Vec<String>) -> Result<Builder> {
        log::debug!("Parsing headers: {:?}", redact_headers_vec(&headers));
        for h in &headers {
            if let Some((key, header)) = h.split_once(":") {
                log::trace!(
                    "Adding header: {}: {}",
                    key.trim(),
                    if key.to_lowercase().contains("authorization") {
                        "[REDACTED]"
                    } else {
                        header
                    }
                );
                builder = builder.header(
                    http::header::HeaderName::from_bytes(key.trim().as_bytes())
                        .wrap_err_with(|| format!("bad header name: {}", key))?,
                    http::header::HeaderValue::from_str(header.trim())
                        .wrap_err_with(|| "bad header value")?,
                );
            } else {
                // match curl behavior: warn but continue without malformed header
                log::warn!("Invalid header format: {}", h);
            }
        }

        log::debug!(
            "Headers configured: {:?}",
            redact_headers(builder.headers_ref().unwrap_or(&http::HeaderMap::new()))
        );
        Ok(builder)
    }
}
