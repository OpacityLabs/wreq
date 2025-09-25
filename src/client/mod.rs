mod emulation;
mod http;
mod request;
mod response;
mod tcp;

pub mod body;
pub mod layer;
#[cfg(feature = "multipart")]
pub mod multipart;
#[cfg(feature = "ws")]
pub mod ws;

pub use self::{
    body::Body,
    emulation::{Emulation, EmulationBuilder, EmulationFactory},
    http::{Client, ClientBuilder},
    request::{Request, RequestBuilder},
    response::Response,
};

// Re-export TCP client components
pub use crate::core::client::{
    options::{http1, http2},
    upgrade::Upgraded,
};
#[allow(unused_imports)]
pub use tcp::{TcpClient, TcpClientBuilder, TcpConnection, TcpConnector, TcpTlsStream};
