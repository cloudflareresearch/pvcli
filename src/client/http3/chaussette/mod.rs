pub mod body;
pub mod connection;

use body::H3Body;
use bytes::Bytes;
use connection::SendRequest;
use foundations::telemetry::log;
use http::{Request, Response};
use http_body::Body;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc::UnboundedSender;
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::quic::{self, ConnectionShutdownBehaviour};
use tokio_quiche::quiche::{ConnectionId, WireErrorCode};
use tokio_quiche::settings::{self, TlsCertificatePaths};
use tokio_quiche::{BoxError, ClientH3Connection, ClientH3Driver, ConnectionParams};
use url::Url;

use std::future::Future;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    H2,
    H3,
}

pub struct Config {
    pub proxy: Url,
    pub geohash: String,
    pub request_timeout: Option<u64>,
    pub masque_preshared_key: Option<String>,
    pub proxy_ca: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub http_version: HttpVersion,
}

trait ProxyClient: Clone + Send + Sync {
    async fn new(config: &mut Config) -> anyhow::Result<Self>;

    fn connect(
        self,
        request: hyper::Request<http_body_util::Empty<Bytes>>,
    ) -> impl Future<Output = anyhow::Result<impl AsyncWrite + AsyncRead + Unpin + Send + 'static>> + Send;
}

#[derive(Clone)]
pub struct ProxyH3Client {
    scid: Arc<ConnectionId<'static>>,
    request_sender: SendRequest,
    shutdown: UnboundedSender<ConnectionShutdownBehaviour>,
}

impl ProxyH3Client {
    pub async fn connect(url: &Url, params: ConnectionParams<'_>) -> anyhow::Result<Self> {
        let peer_addr = url.socket_addrs(|| Some(443))?[0];

        let bind_addr = match peer_addr {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };

        let socket = tokio::net::UdpSocket::bind(bind_addr).await?;
        socket.connect(peer_addr).await?;
        let socket = tokio_quiche::socket::Socket::try_from(socket)?;

        let host = url.host_str();
        let (h3_driver, h3_driver_channel) = ClientH3Driver::new(Http3Settings::default());
        let quic_connection = quic::connect_with_config(socket, host, &params, h3_driver)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        let h3_over_quic = ClientH3Connection::new(quic_connection, h3_driver_channel);
        let client = connection::Connection::new_with_connection(h3_over_quic);
        let scid = client.quic_connection.scid().to_owned();
        let request_sender = client.request_sender();
        let shutdown = client.client_shutdown_sender();
        tokio::spawn({
            async move {
                if let Err(error) = client.run().await {
                    log::error!("connect: h3 connection errored: {:?}", error);
                } else {
                    log::debug!("connect: h3 connection shutdown")
                };
            }
        });

        Ok(Self {
            scid: Arc::new(scid),
            request_sender,
            shutdown,
        })
    }

    pub async fn send_request<B>(&self, request: Request<B>) -> Result<Response<H3Body>, BoxError>
    where
        B: Body<Data = Bytes> + Send + Sync + 'static,
        B::Error: std::error::Error + Send + Sync + Unpin,
    {
        self.request_sender.send_request(request).await
    }

    pub fn scid(&self) -> &ConnectionId<'static> {
        &self.scid
    }
}

impl Drop for ProxyH3Client {
    fn drop(&mut self) {
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

impl ProxyClient for ProxyH3Client {
    async fn new(config: &mut Config) -> anyhow::Result<Self> {
        let params = ConnectionParams::new_client(
            settings::QuicSettings::default(),
            match (config.client_cert.as_ref(), config.client_key.as_ref()) {
                (None, None) => None,
                (Some(cert), Some(private_key)) => Some(TlsCertificatePaths {
                    cert,
                    private_key,
                    kind: settings::CertificateKind::X509,
                }),
                (None, Some(_)) => anyhow::bail!("client cert is missing"),
                (Some(_), None) => anyhow::bail!("client key is missing"),
            },
            settings::Hooks::default(),
        );
        let connection = ProxyH3Client::connect(&config.proxy, params).await?;
        log::info!("scid: {:?}", connection.scid());
        Ok(connection)
    }

    async fn connect(
        self,
        request: hyper::Request<http_body_util::Empty<Bytes>>,
    ) -> anyhow::Result<impl AsyncWrite + AsyncRead + Unpin + Send + 'static> {
        log::debug!("sending H3 CONNECT request");
        let response = self
            .send_request(request)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        Ok(response.into_body())
    }
}
