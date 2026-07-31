// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use std::net::SocketAddr;

use super::{
    HttpBody, HttpClient, HttpResponse, RequestHandler, cert::build_ssl_context_builder,
    log_and_execute_request,
};
use crate::{
    args::{RequestArgs, TlsConfig},
    client::{redact_headers, request::REQUEST_TIMEOUT_SECONDS, resolver::Resolver},
};

use boring::ssl::{SslConnector, SslMethod};
use color_eyre::eyre::{Result, WrapErr, eyre};
use foundations::telemetry::log;
use http::uri::Scheme;
use http_body_util::BodyExt;
use hyper::{Request, Response, body::Incoming};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    time::timeout,
};

/**
 * HTTP/2 Client supports both HTTP/1.1 and HTTP/2 via ALPN negotiation during the TLS handshake.
 * If the server does not support HTTP/2, it will gracefully fall back to HTTP/1.1.
 */
#[derive(Default)]
pub struct Http2Client {
    resolver: Resolver,
}

impl HttpClient for Http2Client {
    async fn send_request(
        &self,
        args: RequestArgs,
        tls_config: &TlsConfig,
    ) -> Result<HttpResponse> {
        let sender = self
            .establish_sender(&args, tls_config)
            .await
            .wrap_err("Failed to establish connection and get sender for HTTP/2 request")?;

        let request =
            RequestHandler::build_request_wrapper(args).wrap_err("Failed to create request")?;
        log_and_execute_request(request, |req| Http2Client::execute_request(req, sender))
            .await
            .wrap_err("Failed to execute HTTP/2 request")
    }
}
enum HttpSender {
    H1(hyper::client::conn::http1::SendRequest<HttpBody>),
    H2(hyper::client::conn::http2::SendRequest<HttpBody>),
}

impl HttpSender {
    async fn execute_request(
        &mut self,
        mut req: Request<HttpBody>,
    ) -> Result<hyper::Response<Incoming>> {
        match self {
            Self::H1(s) => {
                // add Host header if not already present
                if !req.headers().contains_key(http::header::HOST) {
                    let host = req
                        .uri()
                        .authority()
                        .map(|a| a.as_str().to_string())
                        .ok_or_else(|| eyre!("Request URI must include authority (host)"))?;
                    req.headers_mut().insert(
                        http::header::HOST,
                        host.parse()
                            .map_err(|e| eyre!("Invalid host header: {e}"))?,
                    );
                }
                // convert to origin-form URI
                if let Some(pq) = req.uri().path_and_query().cloned() {
                    *req.uri_mut() = pq.as_str().parse()?;
                }

                log::debug!(
                    "Executing HTTP/1.1 request";
                    "method"=> req.method().to_string(),
                    "uri" => req.uri().to_string(),
                    "headers" => format!("{:?}", redact_headers(req.headers()))
                );
                log::info!("[REQUEST] Sending HTTP/1.1 request";"uri" => req.uri().to_string());
                s.send_request(req).await.map_err(|e| eyre!("{e}"))
            }
            Self::H2(s) => {
                log::info!("[REQUEST] Sending HTTP/2 request"; "uri" => req.uri().to_string());
                s.send_request(req).await.map_err(|e| eyre!("{e}"))
            }
        }
    }
}

impl Http2Client {
    pub fn new(resolver: &Resolver) -> Self {
        Self {
            resolver: resolver.clone(),
        }
    }

    async fn execute_request(
        request: Request<HttpBody>,
        mut sender: HttpSender,
    ) -> Result<HttpResponse> {
        let response: Response<Incoming> = sender
            .execute_request(request)
            .await
            .map_err(|e| eyre!("{e}"))?;

        let (version, status, headers) = (
            response.version().clone(),
            response.status().as_u16(),
            response.headers().clone(),
        );

        let body = response
            .into_body()
            .collect()
            .await
            .wrap_err("Failed to read response body")?
            .to_bytes();

        Ok(HttpResponse {
            version,
            status,
            headers,
            body,
        })
    }

    async fn establish_sender(
        &self,
        args: &RequestArgs,
        target_tls_config: &TlsConfig,
    ) -> Result<HttpSender> {
        let request_url = args.proxy_connect.as_ref().unwrap_or(&args.url);
        let tls_config = args.proxy_tls_config.as_ref().unwrap_or(target_tls_config);
        let (scheme, host, port) = Http2Client::url_parts(request_url.clone())?;
        let scheme_str = scheme.as_str().to_uppercase();

        let addresses = self.resolver.resolve(&host, port).await?;
        log::info!(
            "Resolved target addresses";
            "target" => format!("{host}:{port}"),
            "addresses" => format!("{addresses:?}")
        );
        if addresses.is_empty() {
            return Err(eyre!("No addresses to connect to"));
        }

        log::info!("[TCP HANDSHAKE] Sending connection request"; "url" => request_url.clone());

        let tcp_stream = Http2Client::tcp_connection(&addresses).await?;
        log::info!("[TCP HANDSHAKE] Connection established");

        log::debug!(
            "[{}]", scheme_str;
            "IP"=> tcp_stream
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "unknown IP".to_string()),
            "host"=> host.clone(),
            "port" => port
        );

        log::info!("[TLS HANDSHAKE] Initiating handshake");
        let (sender, alpn) =
            Http2Client::tls_handshake(request_url.clone(), host, port, tcp_stream, tls_config)
                .await
                .wrap_err("Failed to create HTTP/2 client for proxy connection")?;

        log::info!(
            "[TLS HANDSHAKE] Completed";
            "ALPN" => alpn.to_string(),
            "boringSSL" => format!("{:?}", tls_config)
        );

        // If proxy is specified, establish CONNECT tunnel + tls handshake with target through proxy
        if args.proxy_connect.is_some() {
            log::debug!(
                "Proxy CONNECT option detected, using tunnel through proxy: {} to connect to target: {}",
                request_url,
                args.url
            );
            let (_scheme, host, port) = Http2Client::url_parts(args.url.clone())?;
            log::info!("[CONNECT] Requesting tunnel"; "target" => args.url.clone());
            let stream = Http2Client::connect(sender, args.url.clone(), args.proxy_header.clone())
                .await
                .wrap_err("Failed to establish CONNECT tunnel to target through proxy")?;

            log::info!("[CONNECT TLS HANDSHAKE] Initiating handshake over tunnel");
            let (sender, alpn) =
                Http2Client::tls_handshake(args.url.clone(), host, port, stream, target_tls_config)
                    .await
                    .wrap_err("Failed to handshake target connection through proxy")?;
            log::info!(
                "[CONNECT] Tunnel ready";
                "ALPN" => alpn.to_string(),
                "boringSSL" => format!("{:?}", target_tls_config)
            );
            return Ok(sender);
        }
        Ok(sender)
    }

    async fn tcp_connection(peer_addresses: &[SocketAddr]) -> Result<TcpStream> {
        log::debug!("Initiating TCP connection to peer"; "peer_addresses" => format!("{peer_addresses:?}"));

        let tcp_stream = timeout(
            std::time::Duration::from_secs(REQUEST_TIMEOUT_SECONDS),
            tokio::net::TcpStream::connect(peer_addresses),
        )
        .await
        .map_err(|_| {
            eyre!("TCP connection to {peer_addresses:?} timed out after {REQUEST_TIMEOUT_SECONDS}s")
        })?
        .wrap_err_with(|| {
            format!("Failed to connect to any of the candidate addresses: {peer_addresses:?}")
        })?;

        log::info!(
            "Successfully established TCP connection";
            "peer" => tcp_stream.peer_addr().map_or_else(|_| format!("unknown"), |a| a.to_string())
        );
        Ok(tcp_stream)
    }

    async fn tls_handshake<S>(
        peer: String,
        host: String,
        port: u16,
        tcp_stream: S,
        tls_config: &TlsConfig,
    ) -> Result<(HttpSender, String)>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        log::debug!(
            "Initiating TLS handshake";
            "peer" => peer.clone(),
            "host_and_port" => format!("{}:{}", host, port),
            "boringSSL" => format!("{:?}", tls_config)
        );
        // if we use HTTPS, use tls_config for TLS handshake and examine ALPN to determine H/2 or H/1.1
        // TODO: --http2 flag to force HTTP/2 only
        if peer.starts_with("https://") {
            log::debug!("Proceeding with HTTPS Scheme");
            let ssl_connector = Http2Client::ssl_config_from_tls_config(tls_config)?;

            let connection =
                tokio_boring::connect(ssl_connector.configure()?, host.as_ref(), tcp_stream)
                    .await
                    .map_err(|e| eyre!("TLS handshake failed: {e}"))?;

            let alpn = connection.ssl().selected_alpn_protocol();
            let (sender, alpn_str) = match alpn {
                Some(b"h2") => {
                    log::debug!("Selected ALPN protocol: HTTP/2 {:?}", alpn);
                    (
                        Http2Client::http2_handshake(TokioIo::new(connection), host, port)
                            .await
                            .wrap_err("Failed http/2 handshake")?,
                        "h2",
                    )
                }
                _ => {
                    log::debug!("Default to ALPN protocol: HTTP/1.1 from {:?}", alpn);
                    (
                        Http2Client::http1_handshake(TokioIo::new(connection), host, port)
                            .await
                            .wrap_err("Failed http/1.1 handshake")?,
                        "http/1.1",
                    )
                }
            };
            Ok((sender, alpn_str.to_string()))
        } else {
            if !tls_config.is_empty() {
                log::warn!("Ignoring TLS configuration for non-HTTPS URL scheme");
            }
            log::debug!("Proceeding with HTTP Scheme");
            let sender = Http2Client::http1_handshake(TokioIo::new(tcp_stream), host, port)
                .await
                .wrap_err("Failed http/1.1 handshake")?;
            Ok((sender, "http/1.1".to_string()))
        }
    }

    fn ssl_config_from_tls_config(tls_config: &TlsConfig) -> Result<SslConnector> {
        log::debug!("Configuring TLS context"; "boringSSL" => format!("{:?}", tls_config));
        let mut ssl_builder = SslConnector::builder(SslMethod::tls())?;
        ssl_builder.set_alpn_protos(b"\x02h2\x08http/1.1")?; // TODO --http2 only flag to set ALPN to only h2
        log::debug!("Set ALPN protocols for HTTP/2 and HTTP/1.1");

        build_ssl_context_builder(
            &mut ssl_builder,
            tls_config.cacert.as_ref(),
            tls_config.client.as_ref(),
            tls_config.key.as_ref(),
        )
        .wrap_err("Failed to build boringSSL context")?;
        log::debug!("Built boringSSL context");
        Ok(ssl_builder.build())
    }

    async fn http2_handshake(
        tcp: TokioIo<impl AsyncRead + AsyncWrite + Unpin + Send + 'static>,
        host: String,
        port: u16,
    ) -> Result<HttpSender> {
        log::debug!("Initiating HTTP/2 handshake"; "peer" => format!("{}:{}", host, port));
        let (sender, conn) =
            hyper::client::conn::http2::handshake::<_, _, HttpBody>(TokioExecutor::new(), tcp)
                .await
                .wrap_err(format!("HTTP/2 handshake with {}:{} failed", host, port))?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                log::error!("Connection driver error: {:?}", e);
            }
        });
        log::debug!("HTTP/2 handshake complete"; "peer" => format!("{}:{}", host, port));
        Ok(HttpSender::H2(sender))
    }

    async fn http1_handshake(
        tcp: TokioIo<impl AsyncRead + AsyncWrite + Unpin + Send + 'static>,
        host: String,
        port: u16,
    ) -> Result<HttpSender> {
        log::debug!("Initiating HTTP/1.1 handshake"; "peer" => format!("{}:{}", host, port));
        let (sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake::<_, HttpBody>(tcp)
            .await
            .wrap_err(format!("HTTP/1.1 handshake with {}:{} failed", host, port))?;
        tokio::spawn(async move {
            if let Err(e) = conn.with_upgrades().await {
                log::error!("proxy connection driver error: {:?}", e);
            }
        });
        log::debug!("HTTP/1.1 handshake complete"; "peer" => format!("{}:{}", host, port));
        Ok(HttpSender::H1(sender))
    }

    async fn connect(
        mut sender: HttpSender,
        target: String,
        headers: Vec<String>,
    ) -> Result<TokioIo<hyper::upgrade::Upgraded>> {
        let request = RequestHandler::build_request("CONNECT", target.clone(), headers, None)?;

        log::debug!("Connect request created";
            "uri" => request.uri().to_string(),
            "headers" => format!("{:?}", redact_headers(request.headers()))
        );

        let response: Response<Incoming> = sender.execute_request(request).await?;
        if response.status() != 200 {
            return Err(eyre!(
                "CONNECT to {} failed with status: {}",
                target,
                response.status()
            ));
        }

        log::info!("[CONNECT] Response status: {}", response.status());

        log::debug!(
            "Received response to CONNECT request";
            "version" => format!("{:?}", response.version()),
            "status" => response.status().to_string(),
            "headers" => format!("{:?}", redact_headers(response.headers()))
        );

        let upgraded = tokio::time::timeout(
            std::time::Duration::from_secs(REQUEST_TIMEOUT_SECONDS),
            hyper::upgrade::on(response),
        )
        .await
        .map_err(|_| {
            eyre!(
                "CONNECT upgrade to {} timed out after {}s",
                target,
                REQUEST_TIMEOUT_SECONDS
            )
        })?
        .map_err(|e| eyre!("Failed to upgrade CONNECT connection to {}: {e}", target))?;

        log::info!("[CONNECT] Upgraded tunnel");

        Ok(TokioIo::new(upgraded))
    }

    fn url_parts(peer: String) -> Result<(Scheme, String, u16)> {
        let uri = peer
            .parse::<hyper::Uri>()
            .wrap_err("Failed to parse peer URL")?;
        let Some(host) = uri.host() else {
            return Err(eyre!("Peer URL must include host"));
        };
        let port = uri.port_u16().unwrap_or(match uri.scheme() {
            Some(s) if s == &Scheme::HTTPS => 443,
            _ => 80,
        });

        let Some(scheme) = uri.scheme() else {
            return Err(eyre!("Peer URL must include scheme (http or https)"));
        };

        log::debug!(
            "Parsed peer URL";
            "uri" => uri.to_string(),
            "scheme" => scheme.to_string(),
            "host_and_port" => format!("{}:{}", host, port),
            "path_and_query" => format!("{:?}", uri.path_and_query())
        );
        Ok((scheme.clone(), host.to_string(), port))
    }
}
