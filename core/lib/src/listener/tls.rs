use std::io;
use std::sync::Arc;

use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::LazyConfigAcceptor;
use rustls::server::{Acceptor, ServerConfig};

use crate::tls::{Error, Resolver, TlsConfig};
use crate::listener::{Listener, Bindable, Connection, Certificates, Endpoint};

#[doc(inline)]
pub use tokio_rustls::server::TlsStream;

/// A TLS listener over some listener interface L.
pub struct TlsListener<L> {
    listener: L,
    resolver: Option<Arc<dyn Resolver>>,
    default: Arc<ServerConfig>,
    config: TlsConfig,
}

#[derive(Clone)]
pub struct TlsBindable<I> {
    pub inner: I,
    pub tls: TlsConfig,
}

impl<I: Bindable> Bindable for TlsBindable<I>
    where I::Listener: Listener<Accept = <I::Listener as Listener>::Connection>,
          <I::Listener as Listener>::Connection: AsyncRead + AsyncWrite
{
    type Listener = TlsListener<I::Listener>;

    type Error = Error;

    async fn bind(self) -> Result<Self::Listener, Self::Error> {
        Ok(TlsListener {
            default: Arc::new(self.tls.to_server_config()?),
            resolver: None,
            listener: self.inner.bind().await.map_err(|e| Error::Bind(Box::new(e)))?,
            config: self.tls,
        })
    }

    fn bind_endpoint(&self) -> io::Result<Endpoint> {
        let inner = self.inner.bind_endpoint()?;
        Ok(inner.with_tls(&self.tls))
    }
}

impl<L> Listener for TlsListener<L>
    where L: Listener<Accept = <L as Listener>::Connection>,
          L::Connection: AsyncRead + AsyncWrite
{
    type Accept = L::Connection;

    type Connection = TlsStream<L::Connection>;

    async fn accept(&self) -> io::Result<Self::Accept> {
        self.listener.accept().await
    }

    async fn connect(&self, conn: L::Connection) -> io::Result<Self::Connection> {
        let acceptor = LazyConfigAcceptor::new(Acceptor::default(), conn);
        let handshake = acceptor.await?;
        let hello = handshake.client_hello();
        let config = match &self.resolver {
            Some(r) => r.resolve(hello).await.unwrap_or_else(|| self.default.clone()),
            None => self.default.clone(),
        };

        handshake.into_stream(config).await
    }

    fn endpoint(&self) -> io::Result<Endpoint> {
        Ok(self.listener.endpoint()?.with_tls(&self.config))
    }
}

impl<C: Connection> Connection for TlsStream<C> {
    fn endpoint(&self) -> io::Result<Endpoint> {
        Ok(self.get_ref().0.endpoint()?.assume_tls())
    }

    #[cfg(feature = "mtls")]
    fn certificates(&self) -> Option<Certificates<'_>> {
        let cert_chain = self.get_ref().1.peer_certificates()?;
        Some(Certificates::from(cert_chain))
    }
}
