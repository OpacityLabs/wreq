//! Support for `ClientBuilder::tcp_stream`: one caller-supplied TCP stream, one connection.
//!
//! The slot gives the stream a single owner and closes it if no connect happens.
//!
//! The wait, `destination` and the `closed` channel cover a connect that starts while the one
//! connection is still in use. A same-host redirect over HTTP/1.1 can start before the pool gets
//! the connection back, so wreq calls the connector again; the wait lets the pool win instead of
//! failing the redirect. A connect to another destination can never reuse the stream, so it fails
//! at once. Over HTTP/2 the connection goes back to the pool at once, so a redirect does not reach
//! the wait.
//!
//! The `Lease` lives with the pooled connection, not with the socket. It drops when the pool can
//! no longer hand the connection out: the server closes it, the pool evicts it after
//! `pool_idle_timeout`, the pool is disabled, or the server answers `101 Switching Protocols`
//! (the client refuses the upgrade and closes the connection). `closed` then ends every wait
//! with an error at once, instead of leaving requests parked for as long as the socket happens
//! to live.

use std::{error::Error as StdError, fmt, net::TcpStream};

use tokio::sync::watch;

use crate::{
    client::http::{ConnectExtra, ConnectRequest},
    error::BoxError,
    sync::Mutex,
};

/// A caller's connected TCP stream, which carries the client's only connection.
///
/// The first connect takes the stream. A later connect to the same destination waits until the
/// pool can no longer hand that connection out, then fails. While it waits, the pool can give the
/// request the connection when it becomes idle. A connect to another destination fails at once.
pub(crate) struct Preconnected {
    slot: Mutex<Slot>,
    closed: watch::Receiver<()>,
}

struct Slot {
    unused: Option<(TcpStream, watch::Sender<()>)>,
    destination: Option<ConnectExtra>,
}

/// Held by the pooled connection that uses the stream. Dropping it marks that connection gone.
#[derive(Debug)]
pub struct Lease {
    _closed: watch::Sender<()>,
}

#[derive(Debug)]
enum PreconnectedError {
    OtherDestination,
    Closed,
}

impl Preconnected {
    pub(crate) fn new(stream: TcpStream) -> Preconnected {
        let (closed_tx, closed) = watch::channel(());
        Preconnected {
            slot: Mutex::new(Slot {
                unused: Some((stream, closed_tx)),
                destination: None,
            }),
            closed,
        }
    }

    /// Returns the stream on the first call, together with the lease for its connection.
    ///
    /// Later calls for the same destination wait for the lease to drop and then fail.
    pub(crate) async fn acquire(
        &self,
        req: &ConnectRequest,
    ) -> Result<(TcpStream, Lease), BoxError> {
        let mut closed = {
            let mut slot = self.slot.lock();
            match &slot.destination {
                Some(destination) if destination != req.extra() => {
                    return Err(PreconnectedError::OtherDestination.into());
                }
                Some(_) => {}
                None => slot.destination = Some(req.extra().clone()),
            }

            if let Some((stream, closed)) = slot.unused.take() {
                return Ok((stream, Lease { _closed: closed }));
            }

            self.closed.clone()
        };

        // Nothing sends on the channel, so `changed` returns only when the lease drops. The
        // waiting request is usually dropped before that, once the pool hands it the connection.
        let _ = closed.changed().await;
        Err(PreconnectedError::Closed.into())
    }
}

impl fmt::Display for PreconnectedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PreconnectedError::OtherDestination => {
                "the preconnected stream carries a connection to another destination"
            }
            PreconnectedError::Closed => "the connection on the preconnected stream is closed",
        })
    }
}

impl StdError for PreconnectedError {}
