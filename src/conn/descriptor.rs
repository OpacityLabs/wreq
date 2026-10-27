use std::{
    hash::{BuildHasher, Hash, Hasher},
    num::NonZeroU64,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU64, Ordering},
    },
};

use http::{Uri, Version, uri::PathAndQuery};
use lru::DefaultHasher;
use url::Url;

use crate::{conn::net::SocketBindOptions, group::Group, proxy::Matcher, tls::TlsOptions};

/// A key that uniquely identifies a group of interchangeable connections for pooling.
///
/// This ID is derived from all parameters that define a connection endpoint,
/// such as URI, proxy, and local socket bindings. Connections with the same
/// ID are considered equivalent and can be reused.
#[derive(Debug, Clone)]
pub(crate) struct ConnectionId(Arc<(Group, AtomicU64)>);

/// A blueprint for creating a new client connection, containing all necessary parameters.
///
/// This descriptor bundles the target `Uri`, HTTP version, `TlsOptions`, proxy settings,
/// and other configurations needed to establish a connection.
#[must_use]
#[derive(Clone)]
pub(crate) struct ConnectionDescriptor {
    uri: Uri,
    version: Option<Version>,
    proxy: Option<Matcher>,
    tls_options: Option<TlsOptions>,
    socket_bind: Option<SocketBindOptions>,
    connection_id: ConnectionId,
}

// ===== impl ConnectionId =====

impl Hash for ConnectionId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let hash = self.0.1.load(Ordering::Relaxed);
        if hash != 0 {
            state.write_u64(hash);
            return;
        }

        static HASHER: LazyLock<DefaultHasher> = LazyLock::new(DefaultHasher::default);
        let computed_hash = NonZeroU64::new(HASHER.hash_one(&self.0.0))
            .map(NonZeroU64::get)
            .unwrap_or(1);

        let _ = self.0.1.compare_exchange(
            u64::MIN,
            computed_hash,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        state.write_u64(computed_hash);
    }
}

impl PartialEq for ConnectionId {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0.0.eq(&other.0.0)
    }
}

impl Eq for ConnectionId {}

/// The origin as `url::Url` writes it: lowercase scheme and host, IP literals in canonical form,
/// no default port. Userinfo stays as written.
///
/// A redirect target is resolved through `url::Url`, while the first request keeps the URI as
/// the caller wrote it. Keying the pool on this form makes `https://host:443/a` and the redirect's
/// `https://host/b` one destination. A URI the parser rejects is keyed as written.
pub(crate) fn canonical_origin(uri: &Uri) -> Uri {
    let (Some(scheme), Some(authority)) = (uri.scheme(), uri.authority()) else {
        return uri.clone();
    };
    let Ok(url) = Url::parse(&format!("{scheme}://{authority}/")) else {
        return uri.clone();
    };
    let Some(host) = url.host_str() else {
        return uri.clone();
    };
    let userinfo = authority
        .as_str()
        .rsplit_once('@')
        .map_or(String::new(), |(userinfo, _)| format!("{userinfo}@"));
    let port = url.port().map_or(String::new(), |port| format!(":{port}"));
    Uri::builder()
        .scheme(url.scheme())
        .authority(format!("{userinfo}{host}{port}"))
        .path_and_query(PathAndQuery::from_static("/"))
        .build()
        .unwrap_or_else(|_| uri.clone())
}

// ===== impl ConnectionDescriptor =====

impl ConnectionDescriptor {
    /// Create a new [`ConnectionDescriptor`].
    pub(crate) fn new(
        uri: Uri,
        mut group: Group,
        proxy: Option<Matcher>,
        version: Option<Version>,
        tls_options: Option<TlsOptions>,
        socket_bind: Option<SocketBindOptions>,
    ) -> ConnectionDescriptor {
        let connection_id = {
            // The key is the canonical origin, so a URI as written and a redirect's resolved
            // target share a connection. The URI dialled stays as written.
            group
                .uri(canonical_origin(&uri))
                .version(version)
                .proxy(proxy.clone())
                .socket_bind(socket_bind.clone());
            ConnectionId(Arc::new((group, AtomicU64::new(u64::MIN))))
        };

        ConnectionDescriptor {
            uri,
            proxy,
            version,
            tls_options,
            socket_bind,
            connection_id,
        }
    }

    /// Returns a [`ConnectionId`] group ID for this descriptor.
    #[inline]
    pub(crate) fn id(&self) -> ConnectionId {
        self.connection_id.clone()
    }

    /// Returns a reference to the [`Uri`].
    #[inline]
    pub(crate) fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Returns a mutable reference to the [`Uri`].
    #[inline]
    pub(crate) fn uri_mut(&mut self) -> &mut Uri {
        &mut self.uri
    }

    /// Return the negotiated HTTP version, if any.
    pub(crate) fn version(&self) -> Option<Version> {
        self.version
    }

    /// Return a reference to the [`TlsOptions`].
    #[inline]
    pub(crate) fn tls_options(&self) -> Option<&TlsOptions> {
        self.tls_options.as_ref()
    }

    /// Return a reference to the [`Matcher`].
    #[inline]
    pub(crate) fn proxy(&self) -> Option<&Matcher> {
        self.proxy.as_ref()
    }

    /// Return a reference to the [`SocketBindOptions`].
    #[inline]
    pub(crate) fn socket_bind_options(&self) -> Option<&SocketBindOptions> {
        self.socket_bind.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use http::Uri;

    use super::canonical_origin;

    #[test]
    fn canonical_origin_matches_what_a_redirect_resolves_to() {
        let cases = [
            ("https://Example.com:443/a?b", "https://example.com/"),
            ("http://example.com:80/", "http://example.com/"),
            ("http://example.com:8080/", "http://example.com:8080/"),
            ("https://example.com:80/", "https://example.com:80/"),
            ("http://127.000.000.001:1234/same", "http://127.0.0.1:1234/"),
            ("http://[::1]:1234/", "http://[::1]:1234/"),
            ("http://[0:0:0:0:0:0:0:1]:1234/", "http://[::1]:1234/"),
            (
                "http://user:pw@Example.com:80/",
                "http://user:pw@example.com/",
            ),
        ];
        for (written, expected) in cases {
            let uri: Uri = written.parse().unwrap();
            assert_eq!(canonical_origin(&uri).to_string(), expected, "{written}");
        }
    }

    #[test]
    fn canonical_origin_keeps_a_uri_without_an_origin() {
        let uri: Uri = "/only/a/path".parse().unwrap();
        assert_eq!(canonical_origin(&uri), uri);
    }
}
