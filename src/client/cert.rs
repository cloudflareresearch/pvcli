// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use boring::ssl::{SslContextBuilder, SslFiletype, SslMethod, SslVerifyMode};
use boring::x509::X509;
use boring::x509::store::{X509StoreBuilder, X509StoreBuilderRef};
use color_eyre::eyre::{Result, WrapErr, eyre};
use foundations::telemetry::log;
use tokio_quiche::quic::ConnectionHook;

/// [`ConnectionHook`] that configures X.509 TLS for a QUIC connection.
///
/// When client and key certs are provided, they're loaded for mTLS.
/// When only [`cacert`](Self::extra_ca) is set, the hook just adds an extra
/// CA certificate to the trust store (useful for trusting self-signed origin servers).
pub struct X509ConnectionHook {
    /// Optional extra CA certificate (PEM-encoded) to add to the trust store.
    pub cacert: Option<String>,
    /// Optional client certificate (PEM-encoded) to use for mTLS.
    pub client: Option<String>,
    /// Optional private key (PEM-encoded) to use for mTLS.
    pub key: Option<String>,
}

impl ConnectionHook for X509ConnectionHook {
    fn create_custom_ssl_context_builder(
        &self,
        _settings: tokio_quiche::settings::TlsCertificatePaths,
    ) -> Option<SslContextBuilder> {
        let mut builder = SslContextBuilder::new(SslMethod::tls_client()).ok()?;
        build_ssl_context_builder(
            &mut builder,
            self.cacert.as_ref(),
            self.client.as_ref(),
            self.key.as_ref(),
        )
        .wrap_err("failed to build ssl context")
        .ok()?;

        log::debug!("Built SSL context");
        Some(builder)
    }
}

pub fn build_ssl_context_builder(
    builder: &mut SslContextBuilder,
    cacert_path: Option<&String>,
    client_path: Option<&String>,
    key_path: Option<&String>,
) -> Result<()> {
    builder.set_verify(SslVerifyMode::PEER);

    log::debug!(
        "Building SSL context with cacert: {:?}, client: {:?}, key: {:?}",
        cacert_path,
        client_path,
        key_path
    );

    if let Some(path) = cacert_path {
        log::info!("[TLS CONFIG] Using custom CA certificate: {}", path);
        let mut store_builder = X509StoreBuilder::new()?;
        let pem = &std::fs::read(path).wrap_err("Failed to read proxy CA cert")?;
        let ca =
            X509::from_pem(pem).wrap_err("Failed to deserialize to PEM-encoded X509 structure")?;
        store_builder
            .add_cert(ca)
            .wrap_err("Failed to add CA cert to store")?;
        builder
            .set_verify_cert_store(store_builder.build())
            .wrap_err("Failed to set custom cert store")?;
    } else {
        log::debug!("No custom CA certificate provided, using default system trust store");
        builder.set_default_verify_paths()?;
        load_native_certs(builder.cert_store_mut());
    }

    match (client_path, key_path) {
        (Some(_), None) | (None, Some(_)) => {
            return Err(eyre!(
                "Both client certificate and key must be provided for mTLS"
            ));
        }
        (Some(client), Some(key)) => {
            log::info!("[mTLS] Using cert/key: {}, {}", client, key);
            builder.set_certificate_file(client, SslFiletype::PEM)?;
            builder.set_private_key_file(key, SslFiletype::PEM)?;
        }
        (None, None) => {
            log::debug!("No client certificate or key provided, skipping mTLS configuration");
        }
    }
    Ok(())
}

fn load_native_certs(store: &mut X509StoreBuilderRef) {
    let native = rustls_native_certs::load_native_certs();

    for err in &native.errors {
        log::debug!("Failed to load a native CA certificate: {}", err);
    }

    let added = native
        .certs
        .iter()
        .filter_map(|cert| X509::from_der(cert.as_ref()).ok())
        .filter(|cert| store.add_cert(cert.clone()).is_ok())
        .count();

    log::debug!("Loaded {} native CA certificate(s) into trust store", added);
}
