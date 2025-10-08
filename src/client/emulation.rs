use http::HeaderMap;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{MapAccess, Visitor},
    ser::SerializeStruct,
};

use crate::{
    core::client::options::TransportOptions,
    header::{OrigHeaderMap, OrigHeaderName},
    http1::Http1Options,
    http2::Http2Options,
    tls::TlsOptions,
};

/// Factory trait for creating emulation configurations.
///
/// This trait allows different types (enums, structs, etc.) to provide
/// their own emulation configurations. It's particularly useful for:
/// - Predefined browser profiles
/// - Dynamic configuration based on runtime conditions
/// - User-defined custom emulation strategies
pub trait EmulationFactory {
    /// Creates an [`Emulation`] instance from this factory.
    fn emulation(self) -> Emulation;
}

/// Builder for creating an [`Emulation`] configuration.
#[derive(Debug)]
#[must_use]
pub struct EmulationBuilder {
    emulation: Emulation,
}

/// HTTP emulation configuration for mimicking different HTTP clients.
///
/// This struct combines transport-layer options (HTTP/1, HTTP/2, TLS) with
/// request-level settings (headers, header case preservation) to provide
/// a complete emulation profile for web browsers, mobile applications,
/// API clients, and other HTTP implementations.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Emulation {
    headers: HeaderMap,
    orig_headers: OrigHeaderMap,
    transport: TransportOptions,
}

impl Serialize for Emulation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("Emulation", 3)?;

        let mut headers_map = Vec::with_capacity(self.headers.len());
        let mut last_header_name = None;
        for (header_name, header_value) in self.headers.clone().into_iter() {
            let header_name = match header_name {
                Some(k) => {
                    last_header_name = Some(k.clone());
                    k
                }
                None => {
                    // TODO: should we throw an error here?
                    //       we get no HeaderName if the header name has multiple values associated
                    //       i.e. Set-Cookie (but when having it sent from the SERVER to the CLIENT - sent to us)
                    //       I don't think we'll ever send a header name with multiple values associated
                    match last_header_name {
                        Some(ref name) => name.clone(),
                        // This should be some, since we have a header name with multiple values associated
                        None => return Err(serde::ser::Error::custom("invalid header")),
                    }
                }
            };

            let mut val: Vec<Vec<u8>> = Vec::new();
            val.push(header_name.as_str().as_bytes().to_vec());
            val.push(header_value.as_bytes().to_vec());
            headers_map.push(val);
        }
        s.serialize_field("headers", &headers_map)?;

        let mut orig_headers_map = Vec::with_capacity(self.orig_headers.len());
        for (_, header_value) in self.orig_headers.clone().into_iter() {
            let mut header_val_vec: Vec<u8> = Vec::with_capacity(header_value.as_ref().len() + 1);

            match header_value {
                crate::header::OrigHeaderName::Cased(bytes) => {
                    // first enum value, stored in the first byte
                    header_val_vec.push(0);
                    header_val_vec.extend_from_slice(bytes.as_ref());
                }
                crate::header::OrigHeaderName::Standard(header_name) => {
                    // second enum value, stored in the first byte
                    header_val_vec.push(1);
                    header_val_vec.extend_from_slice(header_name.as_str().as_bytes());
                }
            }

            orig_headers_map.push(header_val_vec);
        }
        s.serialize_field("orig_headers", &orig_headers_map)?;

        s.serialize_field("transport", &self.transport)?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for Emulation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EmulationVisitor;

        impl<'de> Visitor<'de> for EmulationVisitor {
            type Value = Emulation;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct Emulation")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Emulation, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut headers = HeaderMap::new();
                let mut orig_headers = OrigHeaderMap::new();
                let mut transport = TransportOptions::default();

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "headers" => {
                            let headers_map: Vec<Vec<Vec<u8>>> = map.next_value()?;

                            for header in headers_map {
                                let header_name_as_bytes = header
                                    .get(0)
                                    .ok_or(serde::de::Error::custom("invalid header"))?;
                                let header_value_as_bytes = header
                                    .get(1)
                                    .ok_or(serde::de::Error::custom("invalid header"))?;

                                headers.append(
                                    http::HeaderName::from_bytes(header_name_as_bytes)
                                        .map_err(serde::de::Error::custom)?,
                                    http::HeaderValue::from_bytes(header_value_as_bytes)
                                        .map_err(serde::de::Error::custom)?,
                                );
                            }
                        }
                        "orig_headers" => {
                            let orig_headers_map: Vec<Vec<u8>> = map.next_value()?;

                            for header in orig_headers_map {
                                let header_name_orig_ty = header
                                    .get(0)
                                    .ok_or(serde::de::Error::custom("invalid header"))?;

                                let orig_header_name = match *header_name_orig_ty {
                                    0 => OrigHeaderName::Cased(bytes::Bytes::copy_from_slice(
                                        &header[1..],
                                    )),
                                    1 => OrigHeaderName::Standard(
                                        http::HeaderName::from_bytes(&header[1..])
                                            .map_err(serde::de::Error::custom)?,
                                    ),
                                    _ => return Err(serde::de::Error::custom("invalid header")),
                                };

                                orig_headers.insert(orig_header_name);
                            }
                        }
                        "transport" => transport = map.next_value()?,
                        _ => return Err(serde::de::Error::custom("invalid key")),
                    }
                }

                Ok(Emulation {
                    headers,
                    orig_headers,
                    transport,
                })
            }
        }

        deserializer.deserialize_struct(
            "Emulation",
            &["headers", "orig_headers", "transport"],
            EmulationVisitor,
        )
    }
}

// ==== impl EmulationBuilder ====

impl EmulationBuilder {
    /// Sets the  HTTP/1 options configuration.
    #[inline]
    pub fn http1_options(mut self, opts: Http1Options) -> Self {
        *self.emulation.http1_options_mut() = Some(opts);
        self
    }

    /// Sets the HTTP/2 options configuration.
    #[inline]
    pub fn http2_options(mut self, opts: Http2Options) -> Self {
        *self.emulation.http2_options_mut() = Some(opts);
        self
    }

    /// Sets the  TLS options configuration.
    #[inline]
    pub fn tls_options(mut self, opts: TlsOptions) -> Self {
        *self.emulation.tls_options_mut() = Some(opts);
        self
    }

    /// Sets the default headers.
    #[inline]
    pub fn headers(mut self, src: HeaderMap) -> Self {
        crate::util::replace_headers(&mut self.emulation.headers, src);
        self
    }

    /// Sets the original headers.
    #[inline]
    pub fn orig_headers(mut self, src: OrigHeaderMap) -> Self {
        self.emulation.orig_headers.extend(src);
        self
    }

    /// Builds the [`Emulation`] instance.
    #[inline]
    pub fn build(self) -> Emulation {
        self.emulation
    }
}

// ==== impl Emulation ====

impl Emulation {
    /// Creates a new [`EmulationBuilder`].
    #[inline]
    pub fn builder() -> EmulationBuilder {
        EmulationBuilder {
            emulation: Emulation::default(),
        }
    }

    /// Returns a mutable reference to the TLS options, if set.
    #[inline]
    pub fn tls_options_mut(&mut self) -> &mut Option<TlsOptions> {
        self.transport.tls_options_mut()
    }

    /// Returns a mutable reference to the HTTP/1 options, if set.
    #[inline]
    pub fn http1_options_mut(&mut self) -> &mut Option<Http1Options> {
        self.transport.http1_options_mut()
    }

    /// Returns a mutable reference to the HTTP/2 options, if set.
    #[inline]
    pub fn http2_options_mut(&mut self) -> &mut Option<Http2Options> {
        self.transport.http2_options_mut()
    }

    /// Returns a mutable reference to the emulation headers, if set.
    #[inline]
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    /// Returns a mutable reference to the original headers, if set.
    #[inline]
    pub fn orig_headers_mut(&mut self) -> &mut OrigHeaderMap {
        &mut self.orig_headers
    }

    /// Decomposes the [`Emulation`] into its components.
    #[inline]
    pub(crate) fn into_parts(self) -> (TransportOptions, HeaderMap, OrigHeaderMap) {
        (self.transport, self.headers, self.orig_headers)
    }
}

impl EmulationFactory for Emulation {
    #[inline]
    fn emulation(self) -> Emulation {
        self
    }
}

impl EmulationFactory for Http1Options {
    #[inline]
    fn emulation(self) -> Emulation {
        Emulation::builder().http1_options(self).build()
    }
}

impl EmulationFactory for Http2Options {
    #[inline]
    fn emulation(self) -> Emulation {
        Emulation::builder().http2_options(self).build()
    }
}

impl EmulationFactory for TlsOptions {
    #[inline]
    fn emulation(self) -> Emulation {
        Emulation::builder().tls_options(self).build()
    }
}
