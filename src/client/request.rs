use super::HttpBody;

use crate::args::{Method, RequestArgs};
use bytes::Bytes;
use color_eyre::eyre::{Result, WrapErr, eyre};
use foundations::telemetry::log;
use http::Request;
use http::request::Builder;
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
    pub fn create_request(args: RequestArgs) -> Result<Request<HttpBody>> {
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
        log::info!("Creating {} request to {}", method, url);

        let uri = url.parse::<hyper::Uri>()?;

        if uri.scheme_str().is_none() {
            return Err(eyre!("URL must include scheme (http:// or https://)"));
        }

        log::debug!(
            "Parsed URI: scheme: {:?}, host: {:?}, path: {}",
            uri.scheme_str(),
            uri.host(),
            uri.path()
        );

        log::trace!(
            "Building request with headers: {:?}, body: {:?}",
            headers,
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
        log::trace!("Request built: {:?}", request);
        log::info!("Successfully built {} request to {}", method, url);

        Ok(request)
    }

    fn consume_headers(mut builder: Builder, headers: Vec<String>) -> Result<Builder> {
        for h in &headers {
            if let Some((key, header)) = h.split_once(":") {
                log::trace!("Adding header: {}: {}", key.trim(), header.trim());
                builder = builder.header(
                    http::header::HeaderName::from_bytes(key.trim().as_bytes())
                        .wrap_err_with(|| format!("bad header name: {}", key))?,
                    http::header::HeaderValue::from_str(header.trim())
                        .wrap_err_with(|| format!("bad header value: {}", header))?,
                );
            } else {
                // match curl behavior: warn but continue without malformed header
                log::warn!("Invalid header format: {}", h);
            }
        }

        log::debug!("Headers configured: {:?}", builder.headers_ref());
        Ok(builder)
    }
}
