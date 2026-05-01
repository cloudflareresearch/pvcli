use super::{
    HttpBody, HttpClient, HttpResponse, RequestHandler, cert::build_ssl_context_builder,
    log_and_execute_request,
};
use crate::args::{RequestArgs, TlsConfig};

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
};

/**
 * HTTP/2 Client supports both HTTP/1.1 and HTTP/2 via ALPN negotiation during the TLS handshake.
 * If the server does not support HTTP/2, it will gracefully fall back to HTTP/1.1.
 */
pub struct Http2Client {}

impl HttpClient for Http2Client {
    async fn send_request(
        &self,
        args: RequestArgs,
        tls_config: &TlsConfig,
    ) -> Result<HttpResponse> {
        let sender = Http2Client::create_connection(args.url.clone(), tls_config)
            .await
            .wrap_err("Failed to create HTTP/2 client")?;
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
                    if let Some(host) = req.uri().authority().map(|a| a.as_str().to_string()) {
                        req.headers_mut().insert(
                            http::header::HOST,
                            host.parse()
                                .map_err(|e| eyre!("Invalid host header: {e}"))?,
                        );
                    }
                }
                // convert to origin-form URI
                if let Some(pq) = req.uri().path_and_query().cloned() {
                    *req.uri_mut() = pq.as_str().parse()?;
                }
                s.send_request(req).await.map_err(|e| eyre!("{e}"))
            }
            Self::H2(s) => s.send_request(req).await.map_err(|e| eyre!("{e}")),
        }
    }
}

impl Http2Client {
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

    async fn create_connection(peer: String, tls_config: &TlsConfig) -> Result<HttpSender> {
        let (tcp_stream, host, port): (TcpStream, String, u16) =
            Http2Client::tcp_connection(peer.clone()).await?;

        // if we use HTTPS, use tls_config for TLS handshake and examine ALPN to determine H/2 or H/1.1
        // TODO: --http2 flag to force HTTP/2 only
        let sender = if peer.starts_with("https://") {
            log::info!(
                "Proceeding with HTTPS Scheme: initiating TLS handshake and ALPN negotiation with peer {}",
                peer
            );
            let ssl_connector = Http2Client::ssl_config_from_tls_config(tls_config)?;
            log::debug!(
                "Starting TLS handshake with boringSSL, using provided TLS configuration: {:?}",
                ssl_connector
            );
            let connection =
                tokio_boring::connect(ssl_connector.configure()?, host.as_ref(), tcp_stream)
                    .await
                    .map_err(|e| eyre!("TLS handshake failed: {e}"))?;

            log::info!("Successfully performed TLS handshake and ALPN negotiation",);
            let alpn = connection.ssl().selected_alpn_protocol();
            let sender = match alpn {
                Some(b"h2") => {
                    log::info!("Selected ALPN protocol: HTTP/2");
                    Http2Client::http2_handshake(TokioIo::new(connection), host, port)
                        .await
                        .wrap_err("Failed http/2 handshake")?
                }
                _ => {
                    log::info!("Default to ALPN protocol: HTTP/1.1 from {:?}", alpn);
                    Http2Client::http1_handshake(TokioIo::new(connection), host, port)
                        .await
                        .wrap_err("Failed http/1.1 handshake")?
                }
            };
            sender
        } else {
            // http/1.1 fallback
            if !tls_config.is_empty() {
                log::warn!("Ignoring TLS configuration for non-HTTPS URL scheme");
            }
            log::info!("Proceeding with HTTP Scheme: initiating HTTP/1.1 handshake with peer");
            let sender = Http2Client::http1_handshake(TokioIo::new(tcp_stream), host, port)
                .await
                .wrap_err("Failed http/1.1 handshake")?;
            sender
        };
        log::info!(
            "Successfully performed handshake and established connection to peer: {}",
            peer
        );
        Ok(sender)
    }

    async fn tcp_connection(peer: String) -> Result<(TcpStream, String, u16)> {
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
        log::debug!("Parsed peer URI {}: host: {}, port: {}", uri, host, port);

        let tcp_stream = tokio::net::TcpStream::connect((host, port))
            .await
            .map_err(|e| eyre!("Failed to TCP connect to peer {}:{}: {e}", host, port))?;
        log::info!(
            "Successfully established TCP connection to peer {}:{}",
            host,
            port
        );
        Ok((tcp_stream, host.to_string(), port))
    }

    async fn http2_handshake(
        tcp: TokioIo<impl AsyncRead + AsyncWrite + Unpin + Send + 'static>,
        host: String,
        port: u16,
    ) -> Result<HttpSender> {
        let (sender, conn) =
            hyper::client::conn::http2::handshake::<_, _, HttpBody>(TokioExecutor::new(), tcp)
                .await
                .wrap_err(format!("HTTP/2 handshake with {}:{} failed", host, port))?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                log::error!("Connection driver error: {:?}", e);
            }
        });
        log::info!(
            "Successfully completed HTTP/2 handshake with {}:{}",
            host,
            port
        );
        Ok(HttpSender::H2(sender))
    }

    async fn http1_handshake(
        tcp: TokioIo<impl AsyncRead + AsyncWrite + Unpin + Send + 'static>,
        host: String,
        port: u16,
    ) -> Result<HttpSender> {
        let (sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake::<_, HttpBody>(tcp)
            .await
            .wrap_err(format!("HTTP/1.1 handshake with {}:{} failed", host, port))?;
        tokio::spawn(async move {
            if let Err(e) = conn.with_upgrades().await {
                log::error!("proxy connection driver error: {:?}", e);
            }
        });
        log::info!(
            "Successfully completed HTTP/1.1 handshake with {}:{}",
            host,
            port
        );
        Ok(HttpSender::H1(sender))
    }

    fn ssl_config_from_tls_config(tls_config: &TlsConfig) -> Result<SslConnector> {
        log::debug!("Configuring TLS context with boringSSL");
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
        log::info!("Successfully built TLS context for HTTP/2 client");
        Ok(ssl_builder.build())
    }
}
