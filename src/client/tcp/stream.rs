use std::{
    io::{self, IoSlice},
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_boring2::SslStream;

use crate::{
    core::client::connect::{Connected, Connection},
    tls::TlsInfo,
};

/// A trait for extracting TLS information from a connection.
pub trait TlsInfoFactory {
    fn tls_info(&self) -> Option<TlsInfo>;
}

// Implement TlsInfoFactory for SslStream
impl<T> TlsInfoFactory for SslStream<T> {
    fn tls_info(&self) -> Option<TlsInfo> {
        self.ssl().peer_certificate().map(|c| TlsInfo {
            peer_certificate: c.to_der().ok(),
        })
    }
}

pin_project! {
    /// A TLS-encrypted TCP stream for raw TCP communication.
    ///
    /// This stream provides direct TLS-over-TCP communication without HTTP protocol layers.
    /// It can be used to send and receive raw encrypted messages over a TCP connection.
    pub struct TcpTlsStream<T> {
        #[pin]
        inner: SslStream<T>,
        tls_info: bool,
    }
}

impl<T> TcpTlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Creates a new `TcpTlsStream` wrapping the provided `SslStream`.
    #[inline(always)]
    pub fn new(inner: SslStream<T>, tls_info: bool) -> Self {
        Self { inner, tls_info }
    }

    /// Returns a reference to the underlying SSL stream.
    #[inline]
    pub fn get_ref(&self) -> &SslStream<T> {
        &self.inner
    }

    /// Returns a mutable reference to the underlying SSL stream.
    #[inline]
    pub fn get_mut(&mut self) -> &mut SslStream<T> {
        &mut self.inner
    }

    /// Consumes this stream and returns the underlying SSL stream.
    #[inline]
    pub fn into_inner(self) -> SslStream<T> {
        self.inner
    }
}

impl<T> Connection for TcpTlsStream<T>
where
    T: Connection,
{
    fn connected(&self) -> Connected {
        let mut connected = self.inner.get_ref().connected();

        // Add TLS info if enabled
        if self.tls_info {
            if let Some(tls_info) = self.tls_info() {
                connected = connected.extra(crate::Extension(tls_info));
            }
        }

        connected
    }
}

impl<T> AsyncRead for TcpTlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self.project().inner, cx, buf)
    }
}

impl<T> AsyncWrite for TcpTlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        AsyncWrite::poll_write(self.project().inner, cx, buf)
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        AsyncWrite::poll_write_vectored(self.project().inner, cx, bufs)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        AsyncWrite::poll_flush(self.project().inner, cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        AsyncWrite::poll_shutdown(self.project().inner, cx)
    }
}

impl<T> TlsInfoFactory for TcpTlsStream<T>
where
    SslStream<T>: TlsInfoFactory,
{
    fn tls_info(&self) -> Option<TlsInfo> {
        self.inner.tls_info()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_tcp_tls_stream_creation() {
        // This is a basic compile test to ensure the types work correctly
        // In practice, you'd need a real SSL stream for testing
    }
}
