// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use bytes::Bytes;
use color_eyre::eyre::{Result, WrapErr, eyre};
use privacypass::TokenType;
use privacypass::auth::authenticate::TokenChallenge;
use privacypass::public_tokens::{PublicKey, TokenRequest, TokenResponse};
use serde::Deserialize;
use tls_codec::{Deserialize as _, Serialize as _};
use url::Url;

use crate::args::{Method, RequestArgs, TlsConfig};
use crate::{Http2Client, HttpClient};

const ISSUER_SCHEME: &str = "https";
const PRIVATE_TOKEN_REQUEST: &str = "application/private-token-request";
const PRIVATE_TOKEN_RESPONSE: &str = "application/private-token-response";
const TOKEN_TYPE_PUBLIC: u16 = 2;

#[derive(Deserialize, Debug)]
struct IssuerConfig {
    #[serde(rename = "issuer-request-uri")]
    issuer_request_uri: String,
    #[serde(rename = "token-keys")]
    token_keys: Vec<TokenKeyInfo>,
}

#[derive(Deserialize, Debug, Clone)]
struct TokenKeyInfo {
    #[serde(rename = "token-type")]
    token_type: u16,
    #[serde(rename = "token-key")]
    token_key: String,
    #[serde(rename = "not-before")]
    not_before: Option<i64>,
}

/// Requests a public Privacy Pass token from `issuer` and returns the full
/// `PrivateToken token=<base64url>` value for a `Proxy-Authorization` header.
pub async fn request_token(issuer: &str, directory: &str) -> Result<String> {
    let issuer_host = normalize_issuer_host(issuer)?;
    let issuer_host = issuer_host.as_str();

    let client = Http2Client::default();
    let tls_config = TlsConfig::default();

    let config = fetch_issuer_config(&client, &tls_config, issuer_host, directory).await?;
    let token_key = select_public_token_key(config.token_keys)
        .ok_or_else(|| eyre!("issuer directory has no usable public (type-2) token key"))?;

    let public_key = parse_public_key(&token_key.token_key)?;
    let challenge = TokenChallenge::new(
        TokenType::Public,
        issuer_host,
        None,
        std::slice::from_ref(&issuer_host.to_string()),
    );

    let mut rng = blind_rsa_signatures::reexports::rand::rng();
    let (token_request, token_state) = TokenRequest::new(&mut rng, public_key, &challenge)
        .map_err(|e| eyre!("failed to build token request: {e:?}"))?;

    let request_body = token_request
        .tls_serialize_detached()
        .map_err(|e| eyre!("failed to serialize token request: {e:?}"))?;

    let issue_uri = join_uri(issuer_host, &config.issuer_request_uri)?;
    let response = client
        .send_request(
            RequestArgs {
                method: Method::Post,
                url: issue_uri,
                headers: vec![
                    format!("Content-Type: {PRIVATE_TOKEN_REQUEST}"),
                    format!("Accept: {PRIVATE_TOKEN_RESPONSE}"),
                ],
                body: Some(Bytes::from(request_body)),
                ..Default::default()
            },
            &tls_config,
        )
        .await
        .wrap_err("token issuance request failed")?;

    if !(200..300).contains(&response.status) {
        return Err(eyre!("token issuance got status {}", response.status));
    }

    let token_response = TokenResponse::tls_deserialize_exact(response.body.as_ref())
        .map_err(|e| eyre!("failed to deserialize token response: {e:?}"))?;

    let token = token_response
        .issue_token(&token_state)
        .map_err(|e| eyre!("failed to finalize token: {e:?}"))?;

    let serialized_token = token
        .tls_serialize_detached()
        .map_err(|e| eyre!("failed to serialize token: {e:?}"))?;

    let mut header_value = String::from("PrivateToken token=");
    URL_SAFE.encode_string(serialized_token, &mut header_value);
    Ok(header_value)
}

fn normalize_issuer_host(issuer: &str) -> Result<String> {
    let host = match issuer.split_once("://") {
        Some(("https", rest)) => rest,
        Some((scheme, _)) => {
            return Err(eyre!(
                "unsupported --pat-issuer scheme {scheme:?}: only https is supported"
            ));
        }
        None => issuer,
    };
    let host = host.trim_end_matches('/');
    if host.is_empty() {
        return Err(eyre!("--pat-issuer host is empty"));
    }
    if host.contains('/') {
        return Err(eyre!(
            "--pat-issuer must be a host (optionally https://<host>), not a path: {host:?}"
        ));
    }
    Ok(host.to_string())
}

async fn fetch_issuer_config(
    client: &Http2Client,
    tls_config: &TlsConfig,
    issuer_host: &str,
    directory: &str,
) -> Result<IssuerConfig> {
    let uri = join_uri(issuer_host, directory)?;
    let response = client
        .send_request(
            RequestArgs {
                method: Method::Get,
                url: uri,
                ..Default::default()
            },
            tls_config,
        )
        .await
        .wrap_err("failed to fetch issuer directory")?;

    if !(200..300).contains(&response.status) {
        return Err(eyre!("issuer directory got status {}", response.status));
    }

    serde_json::from_slice::<IssuerConfig>(response.body.as_ref())
        .wrap_err("failed to parse issuer directory JSON")
}

fn select_public_token_key(mut token_keys: Vec<TokenKeyInfo>) -> Option<TokenKeyInfo> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default();

    // Prefer the most recently published, already-valid public key.
    token_keys.reverse();
    token_keys.into_iter().find(|k| {
        k.token_type == TOKEN_TYPE_PUBLIC && k.not_before.map(|nb| nb <= now).unwrap_or(true)
    })
}

fn parse_public_key(token_key_b64: &str) -> Result<PublicKey> {
    let key_bytes = URL_SAFE
        .decode(token_key_b64)
        .or_else(|_| URL_SAFE_NO_PAD.decode(token_key_b64))
        .wrap_err("failed to base64-decode token key")?;

    let spki = spki::SubjectPublicKeyInfoRef::try_from(key_bytes.as_slice())
        .map_err(|e| eyre!("failed to parse SubjectPublicKeyInfo: {e:?}"))?;
    let raw = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| eyre!("SPKI public key has unused bits"))?;

    PublicKey::from_der(raw).map_err(|e| eyre!("failed to parse RSA public key: {e:?}"))
}

fn join_uri(host: &str, path_and_query: &str) -> Result<String> {
    let base = format!("{ISSUER_SCHEME}://{host}");
    let uri = Url::parse(&base)
        .wrap_err("invalid issuer base URL")?
        .join(path_and_query)
        .wrap_err("invalid issuer request URI")?;
    Ok(uri.into())
}
