use std::borrow::Cow;

use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeStruct};

use super::{
    AlpnProtocol, AlpsProtocol, CertificateCompressionAlgorithm, ExtensionType, TlsVersion,
};

/// Builder for `[`TlsOptions`]`.
#[must_use]
#[derive(Debug, Clone)]
pub struct TlsOptionsBuilder {
    config: TlsOptions,
}

/// TLS connection configuration options.
///
/// This struct provides fine-grained control over the behavior of TLS
/// connections, including:
/// - **Protocol negotiation** (ALPN, ALPS, TLS versions)
/// - **Session management** (tickets, PSK, key shares)
/// - **Security & privacy** (OCSP, GREASE, ECH, delegated credentials)
/// - **Performance tuning** (record size, cipher preferences, hardware overrides)
///
/// All fields are optional or have defaults. See each field for details.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub struct TlsOptions {
    /// Application-Layer Protocol Negotiation ([RFC 7301](https://datatracker.ietf.org/doc/html/rfc7301)).
    ///
    /// Specifies which application protocols (e.g., HTTP/2, HTTP/1.1) may be negotiated
    /// over a single TLS connection.
    ///
    /// **Default:** `Some([HTTP/2, HTTP/1.1])`
    pub alpn_protocols: Option<Cow<'static, [AlpnProtocol]>>,

    /// Application-Layer Protocol Settings (ALPS).
    ///
    /// Enables exchanging application-layer settings during the handshake
    /// for protocols negotiated via ALPN.
    ///
    /// **Default:** `None`
    pub alps_protocols: Option<Cow<'static, [AlpsProtocol]>>,

    /// Whether to use an alternative ALPS codepoint for compatibility.
    ///
    /// Useful when larger ALPS payloads are required.
    ///
    /// **Default:** `false`
    pub alps_use_new_codepoint: bool,

    /// Enables TLS Session Tickets ([RFC 5077](https://tools.ietf.org/html/rfc5077)).
    ///
    /// Allows session resumption without requiring server-side state.
    ///
    /// **Default:** `true`
    pub session_ticket: bool,

    /// Minimum TLS version allowed for the connection.
    ///
    /// **Default:** `None` (library default applied)
    pub min_tls_version: Option<TlsVersion>,

    /// Maximum TLS version allowed for the connection.
    ///
    /// **Default:** `None` (library default applied)
    pub max_tls_version: Option<TlsVersion>,

    /// Enables Pre-Shared Key (PSK) cipher suites ([RFC 4279](https://datatracker.ietf.org/doc/html/rfc4279)).
    ///
    /// Authentication relies on out-of-band pre-shared keys instead of certificates.
    ///
    /// **Default:** `false`
    pub pre_shared_key: bool,

    /// Controls whether to send a GREASE Encrypted ClientHello (ECH) extension
    /// when no supported ECH configuration is available.
    ///
    /// GREASE prevents protocol ossification by sending unknown extensions.
    ///
    /// **Default:** `false`
    pub enable_ech_grease: bool,

    /// Controls whether ClientHello extensions should be permuted.
    ///
    /// **Default:** `None` (implementation default)
    pub permute_extensions: Option<bool>,

    /// Controls whether GREASE extensions ([RFC 8701](https://datatracker.ietf.org/doc/html/rfc8701))
    /// are enabled in general.
    ///
    /// **Default:** `None` (implementation default)
    pub grease_enabled: Option<bool>,

    /// Enables OCSP stapling for the connection.
    ///
    /// **Default:** `false`
    pub enable_ocsp_stapling: bool,

    /// Enables Signed Certificate Timestamps (SCT).
    ///
    /// **Default:** `false`
    pub enable_signed_cert_timestamps: bool,

    /// Sets the maximum TLS record size.
    ///
    /// **Default:** `None`
    pub record_size_limit: Option<u16>,

    /// Whether to skip session tickets when using PSK.
    ///
    /// **Default:** `false`
    pub psk_skip_session_ticket: bool,

    /// Maximum number of key shares to include in ClientHello.
    ///
    /// **Default:** `None`
    pub key_shares_limit: Option<u8>,

    /// Enables PSK with (EC)DHE key establishment (`psk_dhe_ke`).
    ///
    /// **Default:** `true`
    pub psk_dhe_ke: bool,

    /// Enables TLS renegotiation by sending the `renegotiation_info` extension.
    ///
    /// **Default:** `true`
    pub renegotiation: bool,

    /// Delegated Credentials ([RFC 9345](https://datatracker.ietf.org/doc/html/rfc9345)).
    ///
    /// Allows TLS 1.3 endpoints to use temporary delegated credentials
    /// for authentication with reduced long-term key exposure.
    ///
    /// **Default:** `None`
    pub delegated_credentials: Option<Cow<'static, str>>,

    /// List of supported elliptic curves.
    ///
    /// **Default:** `None`
    pub curves_list: Option<Cow<'static, str>>,

    /// Cipher suite configuration string.
    ///
    /// Uses BoringSSL's mini-language to select, enable, and prioritize ciphers.
    ///
    /// **Default:** `None`
    pub cipher_list: Option<Cow<'static, str>>,

    /// List of supported signature algorithms.
    ///
    /// **Default:** `None`
    pub sigalgs_list: Option<Cow<'static, str>>,

    /// Supported certificate compression algorithms ([RFC 8879](https://datatracker.ietf.org/doc/html/rfc8879)).
    ///
    /// **Default:** `None`
    pub certificate_compression_algorithms: Option<Cow<'static, [CertificateCompressionAlgorithm]>>,

    /// Supported TLS extensions, used for extension ordering/permutation.
    ///
    /// **Default:** `None`
    pub extension_permutation: Option<Cow<'static, [ExtensionType]>>,

    /// Overrides AES hardware acceleration.
    ///
    /// **Default:** `None`
    pub aes_hw_override: Option<bool>,

    /// Sets whether to preserve the TLS 1.3 cipher list as configured by [`Self::cipher_list`].
    ///
    /// **Default:** `None`
    pub preserve_tls13_cipher_list: Option<bool>,

    /// Overrides the random AES hardware acceleration.
    ///
    /// **Default:** `false`
    pub random_aes_hw_override: bool,
}

impl Serialize for TlsOptions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tls_options = serializer.serialize_struct("TlsOptions", 26)?;
        tls_options.serialize_field("alpn_protocols", &self.alpn_protocols)?;
        tls_options.serialize_field("alps_protocols", &self.alps_protocols)?;
        tls_options.serialize_field("alps_use_new_codepoint", &self.alps_use_new_codepoint)?;
        tls_options.serialize_field("session_ticket", &self.session_ticket)?;
        tls_options.serialize_field("min_tls_version", &self.min_tls_version)?;
        tls_options.serialize_field("max_tls_version", &self.max_tls_version)?;
        tls_options.serialize_field("pre_shared_key", &self.pre_shared_key)?;
        tls_options.serialize_field("enable_ech_grease", &self.enable_ech_grease)?;
        tls_options.serialize_field("permute_extensions", &self.permute_extensions)?;
        tls_options.serialize_field("grease_enabled", &self.grease_enabled)?;
        tls_options.serialize_field("enable_ocsp_stapling", &self.enable_ocsp_stapling)?;
        tls_options.serialize_field(
            "enable_signed_cert_timestamps",
            &self.enable_signed_cert_timestamps,
        )?;
        tls_options.serialize_field("record_size_limit", &self.record_size_limit)?;
        tls_options.serialize_field("psk_skip_session_ticket", &self.psk_skip_session_ticket)?;
        tls_options.serialize_field("key_shares_limit", &self.key_shares_limit)?;
        tls_options.serialize_field("psk_dhe_ke", &self.psk_dhe_ke)?;
        tls_options.serialize_field("renegotiation", &self.renegotiation)?;
        tls_options.serialize_field("delegated_credentials", &self.delegated_credentials)?;
        tls_options.serialize_field("curves_list", &self.curves_list)?;
        tls_options.serialize_field("cipher_list", &self.cipher_list)?;
        tls_options.serialize_field("sigalgs_list", &self.sigalgs_list)?;

        match self.certificate_compression_algorithms.as_ref() {
            Some(algorithms) => {
                let binding = algorithms
                    .iter()
                    .map(|algorithm| {
                        match *algorithm {
                            CertificateCompressionAlgorithm::ZLIB => "zlib",
                            CertificateCompressionAlgorithm::BROTLI => "brotli",
                            CertificateCompressionAlgorithm::ZSTD => "zstd",
                            _ => unreachable!(),
                        }
                        .to_owned()
                    })
                    .collect::<Vec<_>>();

                tls_options
                    .serialize_field("certificate_compression_algorithms", &Some(&binding))?;
            }
            None => tls_options
                .serialize_field("certificate_compression_algorithms", &None::<Vec<String>>)?,
        };

        match self.extension_permutation.as_ref() {
            Some(ext_permutation) => {
                let perm_vec = ext_permutation
                    .iter()
                    .map(|extension| {
                        match *extension {
                            ExtensionType::SERVER_NAME => "SERVER_NAME",
                            ExtensionType::STATUS_REQUEST => "STATUS_REQUEST",
                            ExtensionType::EC_POINT_FORMATS => "EC_POINT_FORMATS",
                            ExtensionType::SIGNATURE_ALGORITHMS => "SIGNATURE_ALGORITHMS",
                            ExtensionType::SRTP => "SRTP",
                            ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => {
                                "APPLICATION_LAYER_PROTOCOL_NEGOTIATION"
                            }
                            ExtensionType::PADDING => "PADDING",
                            ExtensionType::EXTENDED_MASTER_SECRET => "EXTENDED_MASTER_SECRET",
                            ExtensionType::QUIC_TRANSPORT_PARAMETERS_LEGACY => {
                                "QUIC_TRANSPORT_PARAMETERS_LEGACY"
                            }
                            ExtensionType::QUIC_TRANSPORT_PARAMETERS_STANDARD => {
                                "QUIC_TRANSPORT_PARAMETERS_STANDARD"
                            }
                            ExtensionType::CERT_COMPRESSION => "CERT_COMPRESSION",
                            ExtensionType::SESSION_TICKET => "SESSION_TICKET",
                            ExtensionType::SUPPORTED_GROUPS => "SUPPORTED_GROUPS",
                            ExtensionType::PRE_SHARED_KEY => "PRE_SHARED_KEY",
                            ExtensionType::EARLY_DATA => "EARLY_DATA",
                            ExtensionType::SUPPORTED_VERSIONS => "SUPPORTED_VERSIONS",
                            ExtensionType::COOKIE => "COOKIE",
                            ExtensionType::PSK_KEY_EXCHANGE_MODES => "PSK_KEY_EXCHANGE_MODES",
                            ExtensionType::CERTIFICATE_AUTHORITIES => "CERTIFICATE_AUTHORITIES",
                            ExtensionType::SIGNATURE_ALGORITHMS_CERT => "SIGNATURE_ALGORITHMS_CERT",
                            ExtensionType::KEY_SHARE => "KEY_SHARE",
                            ExtensionType::RENEGOTIATE => "RENEGOTIATE",
                            ExtensionType::DELEGATED_CREDENTIAL => "DELEGATED_CREDENTIAL",
                            ExtensionType::APPLICATION_SETTINGS => "APPLICATION_SETTINGS",
                            ExtensionType::APPLICATION_SETTINGS_NEW => "APPLICATION_SETTINGS_NEW",
                            ExtensionType::ENCRYPTED_CLIENT_HELLO => "ENCRYPTED_CLIENT_HELLO",
                            ExtensionType::CERTIFICATE_TIMESTAMP => "CERTIFICATE_TIMESTAMP",
                            ExtensionType::NEXT_PROTO_NEG => "NEXT_PROTO_NEG",
                            ExtensionType::CHANNEL_ID => "CHANNEL_ID",
                            ExtensionType::RECORD_SIZE_LIMIT => "RECORD_SIZE_LIMIT",
                            _ => unreachable!(),
                        }
                        .to_string()
                    })
                    .collect::<Vec<_>>();

                tls_options.serialize_field("extension_permutation", &perm_vec)?;
            }
            None => tls_options.serialize_field("extension_permutation", &None::<Vec<String>>)?,
        };

        tls_options.serialize_field("aes_hw_override", &self.aes_hw_override)?;
        tls_options.serialize_field(
            "preserve_tls13_cipher_list",
            &self.preserve_tls13_cipher_list,
        )?;
        tls_options.serialize_field("random_aes_hw_override", &self.random_aes_hw_override)?;
        tls_options.end()
    }
}

impl<'de> Deserialize<'de> for TlsOptions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;
        struct TlsOptionsVisitor;

        impl<'de> Visitor<'de> for TlsOptionsVisitor {
            type Value = TlsOptions;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct TlsOptions")
            }

            fn visit_map<V>(self, mut map: V) -> Result<TlsOptions, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut alpn_protocols = None;
                let mut alps_protocols = None;
                let mut alps_use_new_codepoint = false;
                let mut session_ticket = true;
                let mut min_tls_version = None;
                let mut max_tls_version = None;
                let mut pre_shared_key = false;
                let mut enable_ech_grease = false;
                let mut permute_extensions = None;
                let mut grease_enabled = None;
                let mut enable_ocsp_stapling = false;
                let mut enable_signed_cert_timestamps = false;
                let mut record_size_limit = None;
                let mut psk_skip_session_ticket = false;
                let mut key_shares_limit = None;
                let mut psk_dhe_ke = true;
                let mut renegotiation = true;
                let mut delegated_credentials = None;
                let mut curves_list = None;
                let mut cipher_list = None;
                let mut sigalgs_list = None;
                let mut certificate_compression_algorithms = None;
                let mut extension_permutation = None;
                let mut aes_hw_override = None;
                let mut preserve_tls13_cipher_list = None;
                let mut random_aes_hw_override = false;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "alpn_protocols" => alpn_protocols = map.next_value()?,
                        "alps_protocols" => alps_protocols = map.next_value()?,
                        "alps_use_new_codepoint" => {
                            alps_use_new_codepoint =
                                map.next_value::<Option<bool>>()?.unwrap_or(false);
                        }
                        "session_ticket" => {
                            session_ticket = map.next_value::<Option<bool>>()?.unwrap_or(true)
                        }
                        "min_tls_version" => min_tls_version = map.next_value()?,
                        "max_tls_version" => max_tls_version = map.next_value()?,
                        "pre_shared_key" => {
                            pre_shared_key = map.next_value::<Option<bool>>()?.unwrap_or(false)
                        }
                        "enable_ech_grease" => {
                            enable_ech_grease = map.next_value::<Option<bool>>()?.unwrap_or(false)
                        }
                        "permute_extensions" => permute_extensions = map.next_value()?,
                        "grease_enabled" => grease_enabled = map.next_value()?,
                        "enable_ocsp_stapling" => {
                            enable_ocsp_stapling =
                                map.next_value::<Option<bool>>()?.unwrap_or(false)
                        }
                        "enable_signed_cert_timestamps" => {
                            enable_signed_cert_timestamps =
                                map.next_value::<Option<bool>>()?.unwrap_or(false)
                        }
                        "record_size_limit" => record_size_limit = map.next_value()?,
                        "psk_skip_session_ticket" => {
                            psk_skip_session_ticket =
                                map.next_value::<Option<bool>>()?.unwrap_or(false)
                        }
                        "key_shares_limit" => key_shares_limit = map.next_value()?,
                        "psk_dhe_ke" => {
                            psk_dhe_ke = map.next_value::<Option<bool>>()?.unwrap_or(true)
                        }
                        "renegotiation" => {
                            renegotiation = map.next_value::<Option<bool>>()?.unwrap_or(true)
                        }
                        "delegated_credentials" => delegated_credentials = map.next_value()?,
                        "curves_list" => curves_list = map.next_value()?,
                        "cipher_list" => cipher_list = map.next_value()?,
                        "sigalgs_list" => sigalgs_list = map.next_value()?,
                        "certificate_compression_algorithms" => {
                            let algs: Option<Vec<&str>> = map.next_value()?;
                            if let Some(algs) = algs {
                                let mut parsed_algs = vec![];
                                for s in algs {
                                    match s {
                                        "zlib" => parsed_algs
                                            .push(CertificateCompressionAlgorithm::ZLIB.to_owned()),
                                        "brotli" => parsed_algs.push(
                                            CertificateCompressionAlgorithm::BROTLI.to_owned(),
                                        ),
                                        "zstd" => parsed_algs
                                            .push(CertificateCompressionAlgorithm::ZSTD.to_owned()),
                                        _ => {
                                            return Err(de::Error::unknown_variant(
                                                s,
                                                &["zlib", "brotli", "zstd"],
                                            ));
                                        }
                                    }
                                }
                                certificate_compression_algorithms = Some(parsed_algs.into());
                            }
                        }
                        "extension_permutation" => {
                            let exts: Option<Vec<&str>> = map.next_value()?;
                            if let Some(exts) = exts {
                                let mut parsed_exts = vec![];
                                for s in exts {
                                    parsed_exts.push(match s {
                                        "SERVER_NAME" => ExtensionType::SERVER_NAME,
                                        "STATUS_REQUEST" => ExtensionType::STATUS_REQUEST,
                                        "EC_POINT_FORMATS" => ExtensionType::EC_POINT_FORMATS,
                                        "SIGNATURE_ALGORITHMS" => {
                                            ExtensionType::SIGNATURE_ALGORITHMS
                                        }
                                        "SRTP" => ExtensionType::SRTP,
                                        "APPLICATION_LAYER_PROTOCOL_NEGOTIATION" => {
                                            ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
                                        }
                                        "PADDING" => ExtensionType::PADDING,
                                        "EXTENDED_MASTER_SECRET" => {
                                            ExtensionType::EXTENDED_MASTER_SECRET
                                        }
                                        "QUIC_TRANSPORT_PARAMETERS_LEGACY" => {
                                            ExtensionType::QUIC_TRANSPORT_PARAMETERS_LEGACY
                                        }
                                        "QUIC_TRANSPORT_PARAMETERS_STANDARD" => {
                                            ExtensionType::QUIC_TRANSPORT_PARAMETERS_STANDARD
                                        }
                                        "CERT_COMPRESSION" => ExtensionType::CERT_COMPRESSION,
                                        "SESSION_TICKET" => ExtensionType::SESSION_TICKET,
                                        "SUPPORTED_GROUPS" => ExtensionType::SUPPORTED_GROUPS,
                                        "PRE_SHARED_KEY" => ExtensionType::PRE_SHARED_KEY,
                                        "EARLY_DATA" => ExtensionType::EARLY_DATA,
                                        "SUPPORTED_VERSIONS" => ExtensionType::SUPPORTED_VERSIONS,
                                        "COOKIE" => ExtensionType::COOKIE,
                                        "PSK_KEY_EXCHANGE_MODES" => {
                                            ExtensionType::PSK_KEY_EXCHANGE_MODES
                                        }
                                        "CERTIFICATE_AUTHORITIES" => {
                                            ExtensionType::CERTIFICATE_AUTHORITIES
                                        }
                                        "SIGNATURE_ALGORITHMS_CERT" => {
                                            ExtensionType::SIGNATURE_ALGORITHMS_CERT
                                        }
                                        "KEY_SHARE" => ExtensionType::KEY_SHARE,
                                        "RENEGOTIATE" => ExtensionType::RENEGOTIATE,
                                        "DELEGATED_CREDENTIAL" => {
                                            ExtensionType::DELEGATED_CREDENTIAL
                                        }
                                        "APPLICATION_SETTINGS" => {
                                            ExtensionType::APPLICATION_SETTINGS
                                        }
                                        "APPLICATION_SETTINGS_NEW" => {
                                            ExtensionType::APPLICATION_SETTINGS_NEW
                                        }
                                        "ENCRYPTED_CLIENT_HELLO" => {
                                            ExtensionType::ENCRYPTED_CLIENT_HELLO
                                        }
                                        "CERTIFICATE_TIMESTAMP" => {
                                            ExtensionType::CERTIFICATE_TIMESTAMP
                                        }
                                        "NEXT_PROTO_NEG" => ExtensionType::NEXT_PROTO_NEG,
                                        "CHANNEL_ID" => ExtensionType::CHANNEL_ID,
                                        "RECORD_SIZE_LIMIT" => ExtensionType::RECORD_SIZE_LIMIT,
                                        _ => Err(de::Error::unknown_variant(
                                            s,
                                            &[
                                                "SERVER_NAME",
                                                "STATUS_REQUEST",
                                                "EC_POINT_FORMATS",
                                                "SIGNATURE_ALGORITHMS",
                                                "SRTP",
                                                "APPLICATION_LAYER_PROTOCOL_NEGOTIATION",
                                                "PADDING",
                                                "EXTENDED_MASTER_SECRET",
                                                "QUIC_TRANSPORT_PARAMETERS_LEGACY",
                                                "QUIC_TRANSPORT_PARAMETERS_STANDARD",
                                                "CERT_COMPRESSION",
                                                "SESSION_TICKET",
                                                "SUPPORTED_GROUPS",
                                                "PRE_SHARED_KEY",
                                                "EARLY_DATA",
                                                "SUPPORTED_VERSIONS",
                                                "COOKIE",
                                                "PSK_KEY_EXCHANGE_MODES",
                                                "CERTIFICATE_AUTHORITIES",
                                                "SIGNATURE_ALGORITHMS_CERT",
                                                "KEY_SHARE",
                                                "RENEGOTIATE",
                                                "DELEGATED_CREDENTIAL",
                                                "APPLICATION_SETTINGS",
                                                "APPLICATION_SETTINGS_NEW",
                                                "ENCRYPTED_CLIENT_HELLO",
                                                "CERTIFICATE_TIMESTAMP",
                                                "NEXT_PROTO_NEG",
                                                "CHANNEL_ID",
                                                "RECORD_SIZE_LIMIT",
                                            ],
                                        ))?,
                                    });
                                }
                                extension_permutation = Some(parsed_exts.into());
                            }
                        }
                        "aes_hw_override" => aes_hw_override = map.next_value()?,
                        "preserve_tls13_cipher_list" => {
                            preserve_tls13_cipher_list = map.next_value()?
                        }
                        "random_aes_hw_override" => {
                            random_aes_hw_override =
                                map.next_value::<Option<bool>>()?.unwrap_or(false)
                        }
                        _ => {
                            let _: de::IgnoredAny = map.next_value()?;
                        }
                    }
                }

                Ok(TlsOptions {
                    alpn_protocols,
                    alps_protocols,
                    alps_use_new_codepoint,
                    session_ticket,
                    min_tls_version,
                    max_tls_version,
                    pre_shared_key,
                    enable_ech_grease,
                    permute_extensions,
                    grease_enabled,
                    enable_ocsp_stapling,
                    enable_signed_cert_timestamps,
                    record_size_limit,
                    psk_skip_session_ticket,
                    key_shares_limit,
                    psk_dhe_ke,
                    renegotiation,
                    delegated_credentials,
                    curves_list,
                    cipher_list,
                    sigalgs_list,
                    certificate_compression_algorithms: certificate_compression_algorithms
                        .map(|alg_vec| std::borrow::Cow::Owned(alg_vec)),
                    extension_permutation,
                    aes_hw_override,
                    preserve_tls13_cipher_list,
                    random_aes_hw_override,
                })
            }
        }

        deserializer.deserialize_struct(
            "TlsOptions",
            &[
                "alpn_protocols",
                "alps_protocols",
                "alps_use_new_codepoint",
                "session_ticket",
                "min_tls_version",
                "max_tls_version",
                "pre_shared_key",
                "enable_ech_grease",
                "permute_extensions",
                "grease_enabled",
                "enable_ocsp_stapling",
                "enable_signed_cert_timestamps",
                "record_size_limit",
                "psk_skip_session_ticket",
                "key_shares_limit",
                "psk_dhe_ke",
                "renegotiation",
                "delegated_credentials",
                "curves_list",
                "cipher_list",
                "sigalgs_list",
                "certificate_compression_algorithms",
                "extension_permutation",
                "aes_hw_override",
                "prefer_chacha20",
                "random_aes_hw_override",
            ],
            TlsOptionsVisitor,
        )
    }
}

impl TlsOptionsBuilder {
    /// Sets the ALPN protocols to use.
    #[inline]
    pub fn alpn_protocols<I>(mut self, alpn: I) -> Self
    where
        I: IntoIterator<Item = AlpnProtocol>,
    {
        self.config.alpn_protocols = Some(Cow::Owned(alpn.into_iter().collect()));
        self
    }

    /// Sets the ALPS protocols to use.
    #[inline]
    pub fn alps_protocols<I>(mut self, alps: I) -> Self
    where
        I: IntoIterator<Item = AlpsProtocol>,
    {
        self.config.alps_protocols = Some(Cow::Owned(alps.into_iter().collect()));
        self
    }

    /// Sets whether to use a new codepoint for ALPS.
    #[inline]
    pub fn alps_use_new_codepoint(mut self, enabled: bool) -> Self {
        self.config.alps_use_new_codepoint = enabled;
        self
    }
    /// Sets the session ticket flag.
    #[inline]
    pub fn session_ticket(mut self, enabled: bool) -> Self {
        self.config.session_ticket = enabled;
        self
    }

    /// Sets the minimum TLS version to use.
    #[inline]
    pub fn min_tls_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.config.min_tls_version = version.into();
        self
    }

    /// Sets the maximum TLS version to use.
    #[inline]
    pub fn max_tls_version<T>(mut self, version: T) -> Self
    where
        T: Into<Option<TlsVersion>>,
    {
        self.config.max_tls_version = version.into();
        self
    }

    /// Sets the pre-shared key flag.
    #[inline]
    pub fn pre_shared_key(mut self, enabled: bool) -> Self {
        self.config.pre_shared_key = enabled;
        self
    }

    /// Sets the GREASE ECH extension flag.
    #[inline]
    pub fn enable_ech_grease(mut self, enabled: bool) -> Self {
        self.config.enable_ech_grease = enabled;
        self
    }

    /// Sets whether to permute ClientHello extensions.
    #[inline]
    pub fn permute_extensions<T>(mut self, permute: T) -> Self
    where
        T: Into<Option<bool>>,
    {
        self.config.permute_extensions = permute.into();
        self
    }

    /// Sets the GREASE enabled flag.
    #[inline]
    pub fn grease_enabled<T>(mut self, enabled: T) -> Self
    where
        T: Into<Option<bool>>,
    {
        self.config.grease_enabled = enabled.into();
        self
    }

    /// Sets the OCSP stapling flag.
    #[inline]
    pub fn enable_ocsp_stapling(mut self, enabled: bool) -> Self {
        self.config.enable_ocsp_stapling = enabled;
        self
    }

    /// Sets the signed certificate timestamps flag.
    #[inline]
    pub fn enable_signed_cert_timestamps(mut self, enabled: bool) -> Self {
        self.config.enable_signed_cert_timestamps = enabled;
        self
    }

    /// Sets the record size limit.
    #[inline]
    pub fn record_size_limit<U: Into<Option<u16>>>(mut self, limit: U) -> Self {
        self.config.record_size_limit = limit.into();
        self
    }

    /// Sets the PSK skip session ticket flag.
    #[inline]
    pub fn psk_skip_session_ticket(mut self, skip: bool) -> Self {
        self.config.psk_skip_session_ticket = skip;
        self
    }

    /// Sets the key shares length limit.
    #[inline]
    pub fn key_shares_limit<T>(mut self, limit: T) -> Self
    where
        T: Into<Option<u8>>,
    {
        self.config.key_shares_limit = limit.into();
        self
    }

    /// Sets the PSK DHE key establishment flag.
    #[inline]
    pub fn psk_dhe_ke(mut self, enabled: bool) -> Self {
        self.config.psk_dhe_ke = enabled;
        self
    }

    /// Sets the renegotiation flag.
    #[inline]
    pub fn renegotiation(mut self, enabled: bool) -> Self {
        self.config.renegotiation = enabled;
        self
    }

    /// Sets the delegated credentials.
    #[inline]
    pub fn delegated_credentials<T>(mut self, creds: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.config.delegated_credentials = Some(creds.into());
        self
    }

    /// Sets the supported curves list.
    #[inline]
    pub fn curves_list<T>(mut self, curves: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.config.curves_list = Some(curves.into());
        self
    }

    /// Sets the cipher list.
    #[inline]
    pub fn cipher_list<T>(mut self, ciphers: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.config.cipher_list = Some(ciphers.into());
        self
    }

    /// Sets the supported signature algorithms.
    #[inline]
    pub fn sigalgs_list<T>(mut self, sigalgs: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        self.config.sigalgs_list = Some(sigalgs.into());
        self
    }

    /// Sets the certificate compression algorithms.
    #[inline]
    pub fn certificate_compression_algorithms<T>(mut self, algs: T) -> Self
    where
        T: Into<Cow<'static, [CertificateCompressionAlgorithm]>>,
    {
        self.config.certificate_compression_algorithms = Some(algs.into());
        self
    }

    /// Sets the extension permutation.
    #[inline]
    pub fn extension_permutation<T>(mut self, permutation: T) -> Self
    where
        T: Into<Cow<'static, [ExtensionType]>>,
    {
        self.config.extension_permutation = Some(permutation.into());
        self
    }

    /// Sets the AES hardware override flag.
    #[inline]
    pub fn aes_hw_override<T>(mut self, enabled: T) -> Self
    where
        T: Into<Option<bool>>,
    {
        self.config.aes_hw_override = enabled.into();
        self
    }

    /// Sets the random AES hardware override flag.
    #[inline]
    pub fn random_aes_hw_override(mut self, enabled: bool) -> Self {
        self.config.random_aes_hw_override = enabled;
        self
    }

    /// Sets whether to preserve the TLS 1.3 cipher list as configured by [`Self::cipher_list`].
    ///
    /// By default, BoringSSL does not preserve the TLS 1.3 cipher list. When this option is
    /// disabled (the default), BoringSSL uses its internal default TLS 1.3 cipher suites in its
    /// default order, regardless of what is set via [`Self::cipher_list`].
    ///
    /// When enabled, this option ensures that the TLS 1.3 cipher suites explicitly set via
    /// [`Self::cipher_list`] are retained in their original order, without being reordered or
    /// modified by BoringSSL's internal logic. This is useful for maintaining specific cipher suite
    /// priorities for TLS 1.3. Note that if [`Self::cipher_list`] does not include any TLS 1.3
    /// cipher suites, BoringSSL will still fall back to its default TLS 1.3 cipher suites and
    /// order.
    #[inline]
    pub fn preserve_tls13_cipher_list<T>(mut self, enabled: T) -> Self
    where
        T: Into<Option<bool>>,
    {
        self.config.preserve_tls13_cipher_list = enabled.into();
        self
    }

    /// Builds the `TlsOptions` from the builder.
    #[inline]
    pub fn build(self) -> TlsOptions {
        self.config
    }
}

impl TlsOptions {
    /// Creates a new `TlsOptionsBuilder` instance.
    pub fn builder() -> TlsOptionsBuilder {
        TlsOptionsBuilder {
            config: TlsOptions::default(),
        }
    }
}

impl Default for TlsOptions {
    fn default() -> Self {
        TlsOptions {
            alpn_protocols: Some(Cow::Borrowed(&[AlpnProtocol::HTTP2, AlpnProtocol::HTTP1])),
            alps_protocols: None,
            alps_use_new_codepoint: false,
            session_ticket: true,
            min_tls_version: None,
            max_tls_version: None,
            pre_shared_key: false,
            enable_ech_grease: false,
            permute_extensions: None,
            grease_enabled: None,
            enable_ocsp_stapling: false,
            enable_signed_cert_timestamps: false,
            record_size_limit: None,
            psk_skip_session_ticket: false,
            key_shares_limit: None,
            psk_dhe_ke: true,
            renegotiation: true,
            delegated_credentials: None,
            curves_list: None,
            cipher_list: None,
            sigalgs_list: None,
            certificate_compression_algorithms: None,
            extension_permutation: None,
            aes_hw_override: None,
            preserve_tls13_cipher_list: None,
            random_aes_hw_override: false,
        }
    }
}
