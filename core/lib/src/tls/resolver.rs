use std::sync::Arc;

pub use rustls::server::{ClientHello, ServerConfig};

use crate::{fairing, Build, Rocket};

/// A dynamic TLS configuration resolver.
#[crate::async_trait]
pub trait Resolver: Send + Sync + 'static {
    async fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<ServerConfig>>;

    async fn fairing(self) -> Fairing where Self: Sized {
        Fairing {
            resolver: Arc::new(self)
        }
    }
}

#[derive(Clone)]
pub struct Fairing {
    resolver: Arc<dyn Resolver>,
}

#[crate::async_trait]
impl fairing::Fairing for Fairing {
    fn info(&self) -> fairing::Info {
        fairing::Info {
            name: "TLS Resolver",
            kind: fairing::Kind::Ignite | fairing::Kind::Singleton
        }
    }

    async fn on_ignite(&self, rocket: Rocket<Build>) -> fairing::Result {
        Ok(rocket.manage(self.clone()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::collections::HashMap;
    use std::time::UNIX_EPOCH;
    use arc_swap::ArcSwap;
    use either::Either;
    use serde::Deserialize;
    use crate::http::uri::Host;
    use crate::tls::{TlsConfig, ServerConfig, Resolver, ClientHello};

    /// ```toml
    /// [sni."api.rocket.rs"]
    /// certs = "private/api_rocket_rs.rsa_sha256_cert.pem"
    /// key = "private/api_rocket_rs.rsa_sha256_key.pem"
    ///
    /// [sni."blob.rocket.rs"]
    /// certs = "private/blob_rsa_sha256_cert.pem"
    /// key = "private/blob_rsa_sha256_key.pem"
    /// ```
    #[derive(Deserialize)]
    struct SniConfig {
        sni: HashMap<Host<'static>, TlsConfig>,
    }

    struct SniResolver {
        sni_map: HashMap<Host<'static>, Arc<ServerConfig>>
    }

    #[crate::async_trait]
    impl Resolver for SniResolver {
        async fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<ServerConfig>> {
            let host = Host::parse(hello.server_name()?).ok()?;
            self.sni_map.get(&host).cloned()
        }
    }

    struct UpdatingResolver {
        timestamp: AtomicU64,
        tls_config: TlsConfig,
        server_config: ArcSwap<ServerConfig>
    }

    impl TryFrom<TlsConfig> for UpdatingResolver {
        type Error = crate::tls::Error;

        fn try_from(tls_config: TlsConfig) -> Result<Self, Self::Error> {
            Ok(UpdatingResolver {
                timestamp: AtomicU64::new(0),
                server_config: ArcSwap::new(Arc::new(tls_config.to_server_config()?)),
                tls_config,
            })
        }
    }

    #[crate::async_trait]
    impl Resolver for UpdatingResolver {
        async fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<ServerConfig>> {
            if let Either::Left(path) = self.tls_config.certs() {
                let metadata = tokio::fs::metadata(&path).await.ok()?;
                let modtime = metadata.modified().ok()?;
                let timestamp = modtime.duration_since(UNIX_EPOCH).ok()?.as_secs();
                let old_timestamp = self.timestamp.load(Ordering::Acquire);
                if timestamp > old_timestamp {
                    let new_config = self.tls_config.to_server_config().ok()?;
                    self.server_config.store(Arc::new(new_config));
                    self.timestamp.store(timestamp, Ordering::Release);
                }
            }

            Some(self.server_config.load_full())
        }
    }

    #[test]
    fn test_config() {
        figment::Jail::expect_with(|jail| {
            use crate::fs::relative;
            use figment::Figment;
            use figment::providers::{Toml, Format};

            let cert_path = relative!("../../examples/tls/private/rsa_sha256_cert.pem");
            let key_path = relative!("../../examples/tls/private/rsa_sha256_key.pem");

            jail.create_file("Rocket.toml", &format!(r#"
                [default.sni."api.rocket.rs"]
                certs = "{cert_path}"
                key = "{key_path}"

                [default.sni."blob.rocket.rs"]
                certs = "{cert_path}"
                key = "{key_path}"
            "#))?;

            let toml = Toml::file("Rocket.toml").nested();
            let config: SniConfig = Figment::from(toml).extract().unwrap();
            assert!(config.sni.contains_key(&Host::parse("api.rocket.rs").unwrap()));
            assert!(config.sni.contains_key(&Host::parse("blob.rocket.rs").unwrap()));
            Ok(())
        });
    }
}
