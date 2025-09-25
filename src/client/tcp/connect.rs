use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use http::Uri;
use tokio::net::TcpStream;
use tower::Service;

use super::stream::TcpTlsStream;
use crate::{
    dns::DynResolver,
    error::{BoxError, TimedOut},
    tls::{
        TlsOptions,
        conn::{TlsConnector, TlsConnectorBuilder},
    },
};

type TcpConnecting =
    Pin<Box<dyn Future<Output = Result<TcpTlsStream<TcpStream>, BoxError>> + Send>>;

/// Configuration for the TCP connector service.
#[derive(Clone)]
struct Config {
    tls_info: bool,
    timeout: Option<Duration>,
}

/// Builder for `TcpConnector`.
pub struct TcpConnectorBuilder {
    config: Config,
    resolver: DynResolver,
    tls_options: TlsOptions,
    tls_builder: TlsConnectorBuilder,
}

/// TCP connector service that establishes raw TCP + TLS connections.
#[derive(Clone)]
pub struct TcpConnector {
    config: Config,
    resolver: DynResolver,
    tls: TlsConnector,
    tls_builder: Arc<TlsConnectorBuilder>,
}

// ===== impl TcpConnectorBuilder =====

impl TcpConnectorBuilder {
    /// Creates a new `TcpConnectorBuilder` with the given resolver.
    pub fn new(resolver: DynResolver) -> Self {
        Self {
            config: Config {
                tls_info: false,
                timeout: None,
            },
            resolver,
            tls_options: TlsOptions::default(),
            tls_builder: TlsConnector::builder(),
        }
    }

    /// Set the TLS connector builder to use.
    #[inline]
    pub fn with_tls<F>(mut self, call: F) -> TcpConnectorBuilder
    where
        F: FnOnce(TlsConnectorBuilder) -> TlsConnectorBuilder,
    {
        self.tls_builder = call(self.tls_builder);
        self
    }

    /// Set the connect timeout.
    #[inline]
    pub fn timeout(mut self, timeout: Option<Duration>) -> TcpConnectorBuilder {
        self.config.timeout = timeout;
        self
    }

    /// Sets the TLS info flag.
    #[inline]
    pub fn tls_info(mut self, enabled: bool) -> TcpConnectorBuilder {
        self.config.tls_info = enabled;
        self
    }

    /// Sets the TLS options to use.
    #[inline]
    pub fn tls_options(mut self, opts: Option<TlsOptions>) -> TcpConnectorBuilder {
        if let Some(opts) = opts {
            self.tls_options = opts;
        }
        self
    }

    /// Build the `TcpConnector`.
    pub fn build(self) -> crate::Result<TcpConnector> {
        let tls = self.tls_builder.build(&self.tls_options)?;

        Ok(TcpConnector {
            config: self.config,
            resolver: self.resolver,
            tls,
            tls_builder: Arc::new(self.tls_builder),
        })
    }
}

// ===== impl TcpConnector =====

impl TcpConnector {
    /// Creates a new `TcpConnectorBuilder` with the given resolver.
    pub fn builder(resolver: DynResolver) -> TcpConnectorBuilder {
        TcpConnectorBuilder::new(resolver)
    }

    /// Establishes a direct TLS connection to the target address.
    async fn connect_tls(self, uri: Uri) -> Result<TcpTlsStream<TcpStream>, BoxError> {
        use crate::dns::resolve::Name;

        // Resolve the hostname to IP addresses
        let host = uri.host().ok_or("URI missing host")?;
        let _port = uri.port_u16().unwrap_or(443); // Default TLS port

        let name = Name::from(host);
        let mut resolver = self.resolver.clone();
        let addrs = resolver.call(name).await?;

        // Try to connect to each resolved address
        let mut last_err = None;
        for addr in addrs {
            match self.try_connect_to_addr(&uri, addr).await {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            }
        }

        Err(last_err.unwrap_or_else(|| "Failed to connect to any address".into()))
    }

    /// Try to connect to a specific socket address.
    async fn try_connect_to_addr(
        &self,
        uri: &Uri,
        addr: SocketAddr,
    ) -> Result<TcpTlsStream<TcpStream>, BoxError> {
        // Establish TCP connection
        let tcp_stream = if let Some(timeout) = self.config.timeout {
            tokio::time::timeout(timeout, TcpStream::connect(addr))
                .await
                .map_err(|_| TimedOut)?
                .map_err(BoxError::from)?
        } else {
            TcpStream::connect(addr).await.map_err(BoxError::from)?
        };

        // Perform TLS handshake directly
        let host = uri.host().ok_or("URI missing host")?;
        let tls_stream = self.perform_tls_handshake(tcp_stream, host).await?;

        Ok(TcpTlsStream::new(tls_stream, self.config.tls_info))
    }

    /// Perform TLS handshake on the TCP stream.
    async fn perform_tls_handshake(
        &self,
        tcp_stream: TcpStream,
        host: &str,
    ) -> Result<tokio_boring2::SslStream<TcpStream>, BoxError> {
        use boring2::ssl::{SslConnector, SslMethod};
        use tokio_boring2::SslStreamBuilder;

        // Create SSL context
        let connector = SslConnector::builder(SslMethod::tls_client())
            .map_err(|e| format!("Failed to create SSL connector: {}", e))?
            .build();

        // Setup SSL configuration
        let config = connector
            .configure()
            .map_err(|e| format!("Failed to configure SSL: {}", e))?;
        let ssl = config
            .into_ssl(host)
            .map_err(|e| format!("Failed to create SSL: {}", e))?;

        // Perform handshake
        let tls_stream = SslStreamBuilder::new(ssl, tcp_stream)
            .connect()
            .await
            .map_err(|e| format!("TLS handshake failed: {}", e))?;

        Ok(tls_stream)
    }
}

impl Service<Uri> for TcpConnector {
    type Response = TcpTlsStream<TcpStream>;
    type Error = BoxError;
    type Future = TcpConnecting;

    #[inline(always)]
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    #[inline(always)]
    fn call(&mut self, uri: Uri) -> Self::Future {
        let connector = self.clone();
        let timeout = self.config.timeout;

        Box::pin(async move {
            let fut = connector.connect_tls(uri);

            if let Some(to) = timeout {
                tokio::time::timeout(to, fut)
                    .await
                    .map_err(|_| BoxError::from(TimedOut))?
            } else {
                fut.await
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::GaiResolver;

    #[tokio::test]
    async fn test_tcp_connector_creation() {
        let resolver = DynResolver::new(Arc::new(GaiResolver::new()));
        let _connector = TcpConnector::builder(resolver)
            .timeout(Some(Duration::from_secs(5)))
            .tls_info(true)
            .build()
            .expect("Failed to build TcpConnector");
    }
}
