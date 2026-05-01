pub mod body;
pub mod connection;

use super::{HttpBody, HttpClient, HttpResponse, RequestHandler, log_and_execute_request};
use crate::args::{RequestArgs, TlsConfig};
use crate::client::cert::X509ConnectionHook;
use crate::client::request::REQUEST_TIMEOUT_SECONDS;

use bytes::Bytes;
use color_eyre::eyre::{Result, WrapErr, eyre};
use connection::SendRequest;
use foundations::telemetry::log;
use http::Request;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc::UnboundedSender;
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::quic::{self, ConnectionHook, ConnectionShutdownBehaviour};
use tokio_quiche::quiche::{ConnectionId, WireErrorCode};
use tokio_quiche::settings::{
    CertificateKind, ConnectionParams, Hooks, QuicSettings, TlsCertificatePaths,
};
use tokio_quiche::{ClientH3Connection, ClientH3Driver};
use url::Url;

#[derive(Clone)]
pub struct Http3Client {
    quic_settings: QuicSettings,
}

struct Http3Connection {
    _scid: Arc<ConnectionId<'static>>,
    request_sender: SendRequest,
    shutdown: UnboundedSender<ConnectionShutdownBehaviour>,
}

impl Http3Connection {
    pub fn _scid(&self) -> &ConnectionId<'static> {
        &self._scid
    }
}

impl HttpClient for Http3Client {
    async fn send_request(
        &self,
        args: RequestArgs,
        tls_config: &TlsConfig,
    ) -> Result<HttpResponse> {
        let connection = self
            .new_connection(args.url.clone(), tls_config)
            .await
            .wrap_err("Failed to establish HTTP/3 connection")?;
        log::info!("[HTTP/3] Connection ready";
            "certs" => format!("{:?}", tls_config)
        );

        let request =
            RequestHandler::build_request_wrapper(args).wrap_err("Failed to create request")?;
        log_and_execute_request(request, |req| self.execute(req, connection))
            .await
            .wrap_err("Failed to execute HTTP/3 request")
    }
}

impl Http3Client {
    pub async fn new() -> Result<Self> {
        let mut settings = QuicSettings::default();
        settings.verify_peer = true;
        settings.handshake_timeout = Some(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECONDS));
        log::debug!(
            "Initialized default QUIC settings for HTTP/3 Client";
            "settings" => format!("{:?}", settings)
        );

        Ok(Self {
            quic_settings: settings,
        })
    }

    async fn new_connection(
        &self,
        peer: String,
        tls_config: &TlsConfig,
    ) -> Result<Http3Connection> {
        let (dummy_tls, hooks) = self.configure_tls(tls_config)?;
        let peer_url = Url::parse(&peer)?;
        let params: ConnectionParams<'_> =
            ConnectionParams::new_client(self.quic_settings.clone(), dummy_tls, hooks.clone());
        let client = Http3Client::start_connection(&peer_url, params)
            .await
            .wrap_err(format!(
                "Http3Client failed to start connection to {}",
                peer_url
            ))?;
        Ok(client)
    }

    fn configure_tls(
        &self,
        tls_config: &TlsConfig,
    ) -> Result<(Option<TlsCertificatePaths<'_>>, Hooks)> {
        let (dummy_tls, connection_hook) = if !tls_config.is_empty() {
            let tls = TlsCertificatePaths {
                cert: "",
                private_key: "",
                kind: CertificateKind::X509,
            };
            let hook = Arc::new(X509ConnectionHook {
                cacert: tls_config.cacert.clone(),
                client: tls_config.client.clone(),
                key: tls_config.key.clone(),
            }) as Arc<dyn ConnectionHook + Send + Sync>;
            (Some(tls), Some(hook))
        } else {
            (None, None)
        };
        let hooks = Hooks { connection_hook };
        Ok((dummy_tls, hooks))
    }

    async fn start_connection(url: &Url, params: ConnectionParams<'_>) -> Result<Http3Connection> {
        let peer_addr = url
            .socket_addrs(|| Some(443))?
            .into_iter()
            .next()
            .ok_or_else(|| eyre!("Failed to resolve peer address from URL: {}", url))?;

        let bind_addr = match peer_addr {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };

        let socket = tokio::net::UdpSocket::bind(bind_addr)
            .await
            .wrap_err(format!("Failed to bind UDP socket to {}", bind_addr))?;
        log::debug!("Bound UDP socket to {}", bind_addr);

        socket.connect(peer_addr).await.wrap_err(format!(
            "Failed to connect UDP socket {} to peer address {}",
            bind_addr, peer_addr
        ))?;
        let socket = tokio_quiche::socket::Socket::try_from(socket)?;

        log::info!("[HTTP/3 UDP] Set up socket connection");

        let client = {
            let host = url.host_str();
            let (h3_driver, h3_driver_channel) = ClientH3Driver::new(Http3Settings::default());
            log::info!(
                "[HTTP/3 QUIC] Starting connection, {}",
                if let Some(timeout) = params.settings.handshake_timeout {
                    format!("timeout in {} seconds", timeout.as_secs())
                } else {
                    "No timeout configured".to_string()
                }
            );
            log::debug!("Using QUIC connection parameters: {:?}", params);
            let quic_connection = quic::connect_with_config(socket, host, &params, h3_driver)
                .await
                .map_err(|e| {
                    eyre!("Failed to connect with QUIC. Are you missing certificates? {e}")
                })?;

            let h3_over_quic = ClientH3Connection::new(quic_connection, h3_driver_channel);
            connection::Connection::new_with_connection(h3_over_quic)
        };
        let scid = Arc::new(client.quic_connection.scid().to_owned());
        let request_sender = client.request_sender();
        let shutdown = client.client_shutdown_sender();
        log::add_fields!("quic_scid" => format!("{:.16}", format!("{:?}", scid))); // only print first 16 digits
        log::info!("[HTTP/3 QUIC] Established connection");

        tokio::spawn({
            async move {
                if let Err(error) = client.run().await {
                    log::error!(
                        "[HTTP/3 DRIVER] connect: h3 connection errored: {:?}",
                        error
                    );
                } else {
                    log::debug!("[HTTP/3 DRIVER] connect: h3 connection shutdown");
                };
            }
        });

        Ok(Http3Connection {
            _scid: scid,
            request_sender,
            shutdown,
        })
    }

    async fn execute(
        &self,
        request: Request<HttpBody>,
        connection: Http3Connection,
    ) -> Result<HttpResponse> {
        log::info!("[HTTP/3] Sending request");
        let response = connection
            .request_sender
            .send_request(request)
            .await
            .map_err(|e| eyre!("{e}"))?;

        let (version, status, headers) = (
            response.version().clone(),
            response.status().as_u16(),
            response.headers().clone(),
        );

        let body = {
            let mut buf = Vec::new();
            response
                .into_body()
                .read_to_end(&mut buf)
                .await
                .wrap_err("Failed to read H3Body")?;
            Bytes::from(buf)
        };

        Ok(HttpResponse {
            version,
            status,
            headers,
            body,
        })
    }
}

impl Drop for Http3Connection {
    fn drop(&mut self) {
        log::info!(
            "[HTTP/3] Dropping HTTP3Connection, sending shutdown signal (it's fine if the runtime exits before shutdown completes)."
        );
        let _ = self.shutdown.send(ConnectionShutdownBehaviour {
            send_application_close: true,
            error_code: if std::thread::panicking() {
                WireErrorCode::InternalError
            } else {
                WireErrorCode::NoError
            } as _,
            reason: vec![],
        });
    }
}
