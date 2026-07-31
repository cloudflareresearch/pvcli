use std::{collections::HashMap, net::SocketAddr};

use color_eyre::eyre::{ContextCompat, Result};
use foundations::telemetry::log;
use url::Url;

#[derive(Clone, Default)]
pub struct Resolver {
    resolve_overrides: HashMap<(String, u16), Vec<SocketAddr>>,
}

impl Resolver {
    pub fn new(resolve_overrides: HashMap<(String, u16), Vec<SocketAddr>>) -> Self {
        Self { resolve_overrides }
    }

    pub async fn resolve_url(&self, url: &Url) -> Result<Vec<SocketAddr>> {
        let host = url.host_str().wrap_err("No host name in the URL")?;
        let port = url.port_or_known_default().unwrap_or(443);

        self.resolve(host, port).await
    }

    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        if let Some(addresses) = self.resolve_overrides.get(&(host.to_owned(), port)) {
            log::debug!(
                "Resolve override hit, skipping DNS lookup";
                "host" => format!("{host}:{port}"),
                "addresses" => format!("{addresses:?}")
            );

            return Ok(addresses.clone());
        }

        if let Some(addresses) = self.resolve_overrides.get(&("*".to_string(), port)) {
            log::debug!(
                "Resolve wildcard override hit, skipping DNS lookup";
                "host" => format!("*:{port}"),
                "addresses" => format!("{addresses:?}")
            );

            return Ok(addresses.clone());
        }

        log::debug!(
            "No resolve override, using system DNS";
            "host" => format!("{host}:{port}"),
        );

        let addresses = tokio::net::lookup_host((host, port)).await?.collect();
        Ok(addresses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("test address should be valid")
    }

    fn resolver(overrides: &[(&str, u16, &[&str])]) -> Resolver {
        Resolver::new(
            overrides
                .iter()
                .map(|(host, port, addrs)| {
                    (
                        ((*host).to_owned(), *port),
                        addrs.iter().map(|a| addr(a)).collect(),
                    )
                })
                .collect(),
        )
    }

    #[tokio::test]
    async fn override_hit_returns_addresses_in_order() {
        let resolver = resolver(&[("test.invalid", 443, &["127.0.0.1:443", "[::1]:443"])]);
        let addresses = resolver.resolve("test.invalid", 443).await.unwrap();

        assert_eq!(
            addresses,
            vec![addr("127.0.0.1:443"), addr("[::1]:443")],
            "override should preserving order and address family"
        );
    }

    #[tokio::test]
    async fn overrides_are_keyed_on_host_and_port() {
        let resolver = resolver(&[("test.invalid", 443, &["127.0.0.1:443", "[::1]:443"])]);
        let result = resolver.resolve("test.invalid", 8443).await;

        assert!(
            result.is_err(),
            "port mismatch should fall through to DNS, got {result:?}"
        );
    }

    #[tokio::test]
    async fn empty_resolver_falls_through_to_dns() {
        let resolver = Resolver::default();
        let result = resolver.resolve("test.invalid", 443).await;

        assert!(
            result.is_err(),
            "no overrides means system DNS, which cannot resolve .invalid, got {result:?}"
        );
    }

    #[tokio::test]
    async fn resolve_url_infers_port_from_scheme() {
        let resolver = resolver(&[
            ("test.invalid", 443, &["127.0.0.1:443"]),
            ("test2.invalid", 80, &["[::1]:80"]),
            ("test2.invalid", 8443, &["[::2]:8443"]),
        ]);

        for (url, expected) in [
            ("https://test.invalid/path?q=1", "127.0.0.1:443"),
            ("http://test2.invalid", "[::1]:80"),
            ("https://test2.invalid:8443", "[::2]:8443"),
        ] {
            let url = Url::parse(url).unwrap();
            assert_eq!(
                resolver.resolve_url(&url).await.unwrap(),
                vec![addr(expected)],
                "unexpected resolution for {url}"
            );
        }
    }

    #[tokio::test]
    async fn wildcard_override_matches() {
        let resolver = resolver(&[
            ("non-matching.invalid", 443, &["127.0.0.1:443"]),
            ("*", 443, &["10.0.0.1:443"]),
        ]);
        let addresses = resolver.resolve("test.invalid", 443).await.unwrap();

        assert_eq!(
            addresses,
            vec![addr("10.0.0.1:443")],
            "wildcard should be matched"
        );
    }

    #[tokio::test]
    async fn wildcard_override_matches_last() {
        let resolver = resolver(&[
            ("*", 443, &["10.0.0.1:443"]),
            ("test.invalid", 443, &["127.0.0.1:443"]),
        ]);
        let addresses = resolver.resolve("test.invalid", 443).await.unwrap();

        assert_eq!(
            addresses,
            vec![addr("127.0.0.1:443")],
            "specific override should have precendence"
        );
    }

    #[tokio::test]
    async fn wildcard_override_is_keyed_by_port() {
        let resolver = resolver(&[("*", 443, &["[::1]:443"])]);
        let result = resolver.resolve("test.invalid", 8443).await;

        assert!(
            result.is_err(),
            "port mismatch should fall through to DNS, got {result:?}"
        );
    }
}
