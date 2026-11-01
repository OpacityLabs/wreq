pub use upgrade::Upgraded;
use wreq_proto::upgrade;

use super::response::Response;
use crate::Error;

impl Response {
    /// Consumes the [`Response`] and returns a future for a possible HTTP upgrade.
    ///
    /// # Preconnected stream
    ///
    /// A client built with [`ClientBuilder::tcp_stream`](crate::ClientBuilder::tcp_stream) refuses
    /// HTTP/1 upgrades: the socket stays with the client and is closed, this method fails with an
    /// upgrade error, and every later request on that client fails with a connect error.
    #[inline]
    pub async fn upgrade(self) -> crate::Result<Upgraded> {
        upgrade::on(http::Response::from(self))
            .await
            .map_err(Error::upgrade)
    }
}
