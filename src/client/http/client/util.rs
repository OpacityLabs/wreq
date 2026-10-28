use http::{
    Request, Uri,
    uri::{Authority, PathAndQuery, Scheme},
};
use url::Url;

use super::error::{Error, ErrorKind};

pub(super) fn origin_form(uri: &mut Uri) {
    let path = match uri.path_and_query() {
        Some(path) if path.as_str() != "/" => {
            let mut parts = ::http::uri::Parts::default();
            parts.path_and_query.replace(path.clone());
            Uri::from_parts(parts).expect("path is valid uri")
        }
        _none_or_just_slash => {
            debug_assert!(Uri::default() == "/");
            Uri::default()
        }
    };
    *uri = path
}

pub(super) fn absolute_form(uri: &mut Uri) {
    debug_assert!(uri.scheme().is_some(), "absolute_form needs a scheme");
    debug_assert!(
        uri.authority().is_some(),
        "absolute_form needs an authority"
    );
}

pub(super) fn authority_form(uri: &mut Uri) {
    if let Some(path) = uri.path_and_query() {
        // `https://hyper.rs` would parse with `/` path, don't
        // annoy people about that...
        if path != "/" {
            warn!("HTTP/1.1 CONNECT request stripping path: {:?}", path);
        }
    }
    *uri = match uri.authority() {
        Some(auth) => {
            let mut parts = ::http::uri::Parts::default();
            parts.authority = Some(auth.clone());
            Uri::from_parts(parts).expect("authority is valid")
        }
        None => {
            unreachable!("authority_form with relative uri");
        }
    };
}

pub(super) fn normalize_uri<B>(req: &mut Request<B>, is_http_connect: bool) -> Result<Uri, Error> {
    let uri = req.uri().clone();

    let build_base_uri = |scheme: Scheme, authority: Authority| {
        Uri::builder()
            .scheme(scheme)
            .authority(authority)
            .path_and_query(PathAndQuery::from_static("/"))
            .build()
            .expect("valid base URI")
    };

    match (uri.scheme(), uri.authority()) {
        (Some(scheme), Some(auth)) => Ok(build_base_uri(scheme.clone(), auth.clone())),
        (None, Some(auth)) if is_http_connect => {
            let scheme = match auth.port_u16() {
                Some(443) => Scheme::HTTPS,
                _ => Scheme::HTTP,
            };
            set_scheme(req.uri_mut(), scheme.clone());
            Ok(build_base_uri(scheme, auth.clone()))
        }
        _ => {
            debug!("Client requires absolute-form URIs, received: {:?}", uri);
            Err(Error::new_kind(ErrorKind::UserAbsoluteUriRequired))
        }
    }
}

/// The origin as `url::Url` writes it: lowercase scheme and host, IP literals in canonical form,
/// no default port. Userinfo stays as written.
///
/// A redirect target is resolved through `url::Url`, while the first request keeps the URI as
/// the caller wrote it. Keying the pool on this form makes `https://host:443/a` and the redirect's
/// `https://host/b` one destination. A URI the parser rejects is keyed as written.
pub(super) fn canonical_origin(uri: &Uri) -> Uri {
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

pub(super) fn get_non_default_port(uri: &Uri) -> Option<http::uri::Port<&str>> {
    match (uri.port().map(|p| p.as_u16()), is_schema_secure(uri)) {
        (Some(443), true) => None,
        (Some(80), false) => None,
        _ => uri.port(),
    }
}

fn set_scheme(uri: &mut Uri, scheme: Scheme) {
    debug_assert!(
        uri.scheme().is_none(),
        "set_scheme expects no existing scheme"
    );
    let old = std::mem::take(uri);
    let mut parts: ::http::uri::Parts = old.into();
    parts.scheme = Some(scheme);
    parts.path_and_query = Some("/".parse().expect("slash is a valid path"));
    *uri = Uri::from_parts(parts).expect("scheme is valid");
}

fn is_schema_secure(uri: &Uri) -> bool {
    uri.scheme_str()
        .map(|scheme_str| matches!(scheme_str, "wss" | "https"))
        .unwrap_or_default()
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
