use std::{sync::Arc, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tower::Service;

use super::{connect::TcpConnector, stream::TcpTlsStream};
use crate::{
    IntoUri,
    dns::{DynResolver, GaiResolver},
    error::BoxError,
    tls::{CertStore, Identity, KeyLog, TlsOptions, TlsVersion},
};

/// A client for establishing raw TCP + TLS connections.
///
/// The `TcpClient` provides a high-level interface for connecting to servers
/// using TLS-encrypted TCP connections without HTTP protocol overhead.
///
/// This is useful for custom protocols that need encrypted transport but
/// don't use HTTP.
#[derive(Clone)]
pub struct TcpClient {
    connector: TcpConnector,
}

/// A builder for configuring a `TcpClient`.
#[must_use]
pub struct TcpClientBuilder {
    config: Config,
}

struct Config {
    error: Option<crate::Error>,
    connect_timeout: Option<Duration>,
    tls_info: bool,
    tls_sni: bool,
    verify_hostname: bool,
    identity: Option<Identity>,
    cert_store: CertStore,
    cert_verification: bool,
    min_tls_version: Option<TlsVersion>,
    max_tls_version: Option<TlsVersion>,
    keylog: Option<KeyLog>,
    dns_resolver: Option<Arc<dyn crate::dns::Resolve>>,
    tls_options: TlsOptions,
}

// ===== impl TcpClient =====

impl TcpClient {
    /// Constructs a new `TcpClient`.
    ///
    /// # Panics
    ///
    /// This method panics if a TLS backend cannot be initialized, or the resolver
    /// cannot load the system configuration.
    #[inline]
    pub fn new() -> TcpClient {
        TcpClient::builder().build().expect("TcpClient::new()")
    }

    /// Creates a `TcpClientBuilder` to configure a `TcpClient`.
    #[inline]
    pub fn builder() -> TcpClientBuilder {
        TcpClientBuilder {
            config: Config {
                error: None,
                connect_timeout: None,
                tls_info: false,
                tls_sni: true,
                verify_hostname: true,
                identity: None,
                cert_store: CertStore::default(),
                cert_verification: true,
                min_tls_version: None,
                max_tls_version: None,
                keylog: None,
                dns_resolver: None,
                tls_options: TlsOptions::default(),
            },
        }
    }

    /// Connect to a server using TLS.
    ///
    /// # Errors
    ///
    /// This method fails if the URI cannot be parsed, DNS resolution fails,
    /// TCP connection fails, or TLS handshake fails.
    pub async fn connect<U: IntoUri>(&self, uri: U) -> Result<TcpConnection, BoxError> {
        let uri = uri.into_uri().map_err(BoxError::from)?;

        let mut connector = self.connector.clone();
        let stream = connector.call(uri).await?;

        Ok(TcpConnection { stream })
    }
}

impl Default for TcpClient {
    fn default() -> Self {
        Self::new()
    }
}

// ===== impl TcpClientBuilder =====

impl TcpClientBuilder {
    /// Returns a `TcpClient` that uses this `TcpClientBuilder` configuration.
    ///
    /// # Errors
    ///
    /// This method fails if a TLS backend cannot be initialized, or the resolver
    /// cannot load the system configuration.
    pub fn build(self) -> crate::Result<TcpClient> {
        let config = self.config;

        if let Some(err) = config.error {
            return Err(err);
        }

        // Create DNS resolver
        let resolver = {
            let resolver: Arc<dyn crate::dns::Resolve> = match config.dns_resolver {
                Some(dns_resolver) => dns_resolver,
                None => Arc::new(GaiResolver::new()),
            };
            DynResolver::new(resolver)
        };

        // Build TCP connector
        let connector = TcpConnector::builder(resolver)
            .timeout(config.connect_timeout)
            .tls_info(config.tls_info)
            .tls_options(Some(config.tls_options))
            .with_tls(|builder| {
                builder
                    .tls_sni(config.tls_sni)
                    .verify_hostname(config.verify_hostname)
                    .cert_verification(config.cert_verification)
                    .cert_store(config.cert_store)
                    .identity(config.identity)
                    .keylog(config.keylog)
                    .min_version(config.min_tls_version)
                    .max_version(config.max_tls_version)
            })
            .build()?;

        Ok(TcpClient { connector })
    }

    /// Set a timeout for the connect phase.
    ///
    /// Default is `None`.
    #[inline]
    pub fn connect_timeout(mut self, timeout: Duration) -> TcpClientBuilder {
        self.config.connect_timeout = Some(timeout);
        self
    }

    /// Add TLS information as extension to the connection.
    #[inline]
    pub fn tls_info(mut self, tls_info: bool) -> TcpClientBuilder {
        self.config.tls_info = tls_info;
        self
    }

    /// Sets the identity to be used for client certificate authentication.
    #[inline]
    pub fn identity(mut self, identity: Identity) -> TcpClientBuilder {
        self.config.identity = Some(identity);
        self
    }

    /// Sets the verify certificate store for the client.
    #[inline]
    pub fn cert_store(mut self, store: CertStore) -> TcpClientBuilder {
        self.config.cert_store = store;
        self
    }

    /// Controls the use of certificate validation.
    ///
    /// Defaults to `true`.
    ///
    /// # Warning
    ///
    /// You should think very carefully before using this method.
    #[inline]
    pub fn cert_verification(mut self, cert_verification: bool) -> TcpClientBuilder {
        self.config.cert_verification = cert_verification;
        self
    }

    /// Configures the use of hostname verification when connecting.
    ///
    /// Defaults to `true`.
    #[inline]
    pub fn verify_hostname(mut self, verify_hostname: bool) -> TcpClientBuilder {
        self.config.verify_hostname = verify_hostname;
        self
    }

    /// Configures the use of Server Name Indication (SNI) when connecting.
    ///
    /// Defaults to `true`.
    #[inline]
    pub fn tls_sni(mut self, tls_sni: bool) -> TcpClientBuilder {
        self.config.tls_sni = tls_sni;
        self
    }

    /// Configures TLS key logging for the client.
    #[inline]
    pub fn keylog(mut self, keylog: KeyLog) -> TcpClientBuilder {
        self.config.keylog = Some(keylog);
        self
    }

    /// Set the minimum required TLS version for connections.
    #[inline]
    pub fn min_tls_version(mut self, version: TlsVersion) -> TcpClientBuilder {
        self.config.min_tls_version = Some(version);
        self
    }

    /// Set the maximum allowed TLS version for connections.
    #[inline]
    pub fn max_tls_version(mut self, version: TlsVersion) -> TcpClientBuilder {
        self.config.max_tls_version = Some(version);
        self
    }

    /// Override the DNS resolver implementation.
    #[inline]
    pub fn dns_resolver<R>(mut self, resolver: R) -> TcpClientBuilder
    where
        R: crate::dns::IntoResolve,
    {
        self.config.dns_resolver = Some(resolver.into_resolve());
        self
    }

    /// Sets the TLS options for the client.
    #[inline]
    pub fn tls_options(mut self, options: TlsOptions) -> TcpClientBuilder {
        self.config.tls_options = options;
        self
    }
}

/// A TLS-encrypted TCP connection.
///
/// This represents an established connection that can be used to send and
/// receive raw encrypted data over TCP.
pub struct TcpConnection {
    stream: TcpTlsStream<TcpStream>,
}

impl TcpConnection {
    /// Returns a reference to the underlying TLS stream.
    #[inline]
    pub fn stream(&self) -> &TcpTlsStream<TcpStream> {
        &self.stream
    }

    /// Returns a mutable reference to the underlying TLS stream.
    #[inline]
    pub fn stream_mut(&mut self) -> &mut TcpTlsStream<TcpStream> {
        &mut self.stream
    }

    /// Consumes this connection and returns the underlying TLS stream.
    #[inline]
    pub fn into_stream(self) -> TcpTlsStream<TcpStream> {
        self.stream
    }

    /// Send raw bytes over the encrypted connection.
    pub async fn send(&mut self, data: &[u8]) -> Result<(), BoxError> {
        self.stream.write_all(data).await.map_err(BoxError::from)
    }

    /// Receive raw bytes from the encrypted connection.
    ///
    /// Returns the number of bytes read.
    pub async fn receive(&mut self, buf: &mut [u8]) -> Result<usize, BoxError> {
        tokio::io::AsyncReadExt::read(&mut self.stream, buf)
            .await
            .map_err(BoxError::from)
    }

    /// Receive exactly the specified number of bytes.
    pub async fn receive_exact(&mut self, buf: &mut [u8]) -> Result<(), BoxError> {
        // TODO: Fix this method - there's a type mismatch issue
        // <TcpTlsStream<TcpStream> as tokio::io::AsyncReadExt>::read_exact(&mut self.stream, buf).await.map_err(BoxError::from)

        // Temporary workaround: read in a loop until we get all bytes
        let mut remaining = buf.len();
        let mut offset = 0;
        while remaining > 0 {
            let n = tokio::io::AsyncReadExt::read(&mut self.stream, &mut buf[offset..])
                .await
                .map_err(BoxError::from)?;
            if n == 0 {
                return Err("Unexpected EOF".into());
            }
            offset += n;
            remaining -= n;
        }
        Ok(())
    }

    /// Shutdown the connection.
    pub async fn shutdown(&mut self) -> Result<(), BoxError> {
        self.stream.shutdown().await.map_err(BoxError::from)
    }
}

impl AsyncRead for TcpConnection {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpConnection {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tcp_client_creation() {
        let _client = TcpClient::builder()
            .connect_timeout(Duration::from_secs(5))
            .tls_info(true)
            .build()
            .expect("Failed to build TcpClient");
    }

    #[tokio::test]
    async fn test_tcp_client_default() {
        let _client = TcpClient::default();
    }
}
