pub mod body;
pub mod connection;
pub mod logging;

use super::{HttpBody, HttpClient, HttpResponse, RequestHandler, log_and_execute_request};
use crate::args::RequestArgs;
use crate::client::http3::logging::H3ConnectionLogger;

use bytes::Bytes;
use color_eyre::eyre::{Result, WrapErr, eyre};
use connection::SendRequest;
use foundations::telemetry::{log, settings::Level};
use http::Request;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc::UnboundedSender;
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::quic::{self, ConnectionShutdownBehaviour};
use tokio_quiche::quiche::{ConnectionId, WireErrorCode};
use tokio_quiche::settings::{self};
use tokio_quiche::{ClientH3Connection, ClientH3Driver, ConnectionParams};
use url::Url;

#[derive(Clone)]
pub struct Http3Client {
    scid: Arc<ConnectionId<'static>>,
    request_sender: SendRequest,
    shutdown: UnboundedSender<ConnectionShutdownBehaviour>,
}

impl HttpClient for Http3Client {
    async fn send_request(&self, args: RequestArgs) -> Result<HttpResponse> {
        let request = RequestHandler::create_request(args).wrap_err("Failed to create request")?;
        log_and_execute_request(request, |req| self.execute(req))
            .await
            .wrap_err("Failed to dispatch request")
    }
}

impl Http3Client {
    pub async fn new(peer: String) -> Result<Self> {
        let peer_url = Url::parse(&peer)?;

        let settings = settings::QuicSettings::default();
        // settings.verify_peer = true; // insecure by default TODO: make this configurable
        let params = ConnectionParams::new_client(
            settings,
            None, // No mTLS yet
            settings::Hooks::default(),
        );
        log::debug!("Http3Client connection params: {:?}", params);
        let client = Http3Client::start_connection(&peer_url, params)
            .await
            .wrap_err(format!(
                "Http3Client failed to start connection to {}",
                peer_url
            ))?;
        log::info!(
            "Successfully initialized Http3Client, scid: {:?}",
            client.scid()
        );
        Ok(client)
    }

    async fn start_connection(url: &Url, params: ConnectionParams<'_>) -> Result<Self> {
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

        log::info!("Successfully set up UDP socket connection to {}", peer_addr);

        let client = {
            let host = url.host_str();
            let (h3_driver, h3_driver_channel) = ClientH3Driver::new(Http3Settings::default());
            let quic_connection = quic::connect_with_config(socket, host, &params, h3_driver)
                .await
                .map_err(|e| eyre!("Failed to connect with QUIC: {e}"))?;

            let h3_over_quic = ClientH3Connection::new(quic_connection, h3_driver_channel);
            connection::Connection::new_with_connection(h3_over_quic)
        };
        let scid = Arc::new(client.quic_connection.scid().to_owned());
        let request_sender = client.request_sender();
        let shutdown = client.client_shutdown_sender();
        log::info!("Successfully established QUIC connection, scid: {:?}", scid);
        log::add_fields!("quic_scid" => format!("{:.16}", format!("{:?}", scid))); // only print first 16 digits

        tokio::spawn({
            async move {
                if let Err(error) = client.run().await {
                    H3ConnectionLogger::log(
                        Level::Error,
                        format!("connect: h3 connection errored: {:?}", error),
                    );
                } else {
                    H3ConnectionLogger::log(
                        Level::Debug,
                        format!("connect: h3 connection shutdown"),
                    );
                };
            }
        });

        Ok(Self {
            scid: scid,
            request_sender,
            shutdown,
        })
    }

    async fn execute(&self, request: Request<HttpBody>) -> Result<HttpResponse> {
        let response = self
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

    pub fn scid(&self) -> &ConnectionId<'static> {
        &self.scid
    }
}

impl Drop for Http3Client {
    fn drop(&mut self) {
        H3ConnectionLogger::log(
            Level::Info,
            format!(
                "Dropping Http3Client, sending shutdown signal (it's fine if the runtime exits before shutdown completes)."
            ),
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
