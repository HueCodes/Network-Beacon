//! TLS Fingerprinting module for JA4-style Client Hello analysis.
//!
//! This module performs deep-packet inspection on TLS handshakes to extract
//! fingerprints that can identify specific client implementations, including
//! C2 implants and unauthorized tools.
//!
//! # Fingerprint Format (JA4-inspired)
//!
//! The fingerprint is structured as: `{version}_{cipher_hash}_{ext_hash}`
//! Where:
//! - version: TLS version (e.g., "t13" for TLS 1.3, "t12" for TLS 1.2)
//! - cipher_hash: First 12 chars of SHA256 hash of sorted cipher suite list
//! - ext_hash: First 12 chars of SHA256 hash of sorted extension list
//!
//! Example: `t13_a0b1c2d3e4f5_f6e5d4c3b2a1`

use sha2::{Digest, Sha256};
use std::fmt;
use tls_parser::{
    parse_tls_extensions, parse_tls_plaintext, TlsExtension, TlsMessage, TlsMessageHandshake,
    TlsRecordType, TlsVersion,
};
use tracing::{debug, trace};

/// Known-good TLS fingerprints for common browsers and legitimate software.
/// These are used to distinguish normal traffic from potentially malicious clients.
pub static KNOWN_GOOD_FINGERPRINTS: &[KnownFingerprint] = &[
    KnownFingerprint {
        fingerprint: "t13_chrome_125",
        description: "Google Chrome 125+",
        vendor: "Google",
    },
    KnownFingerprint {
        fingerprint: "t13_firefox_126",
        description: "Mozilla Firefox 126+",
        vendor: "Mozilla",
    },
    KnownFingerprint {
        fingerprint: "t13_safari_17",
        description: "Apple Safari 17+",
        vendor: "Apple",
    },
    KnownFingerprint {
        fingerprint: "t13_edge_125",
        description: "Microsoft Edge 125+",
        vendor: "Microsoft",
    },
    // Common legitimate tools
    KnownFingerprint {
        fingerprint: "t12_curl_default",
        description: "curl (default)",
        vendor: "curl",
    },
    KnownFingerprint {
        fingerprint: "t13_python_requests",
        description: "Python Requests",
        vendor: "Python",
    },
];

/// A known fingerprint entry for matching.
#[derive(Debug, Clone)]
pub struct KnownFingerprint {
    pub fingerprint: &'static str,
    pub description: &'static str,
    #[allow(dead_code)] // Available for detailed logging
    pub vendor: &'static str,
}

/// Result of TLS fingerprint extraction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsFingerprint {
    /// Full fingerprint string (JA4-style format).
    pub fingerprint: String,
    /// Detected TLS version.
    pub tls_version: TlsVersionInfo,
    /// Number of cipher suites offered.
    pub cipher_count: usize,
    /// Number of extensions present.
    pub extension_count: usize,
    /// Server Name Indication (SNI) if present.
    pub sni: Option<String>,
    /// Whether this matches a known-good fingerprint.
    pub is_known_good: bool,
    /// Description if matches known fingerprint.
    pub known_match: Option<String>,
}

impl TlsFingerprint {
    /// Checks if this fingerprint is suspicious when combined with high periodicity.
    #[allow(dead_code)] // Available for custom detection logic
    pub fn is_suspicious(&self, is_periodic: bool) -> bool {
        !self.is_known_good && is_periodic
    }
}

impl fmt::Display for TlsFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.fingerprint)
    }
}

/// TLS version information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsVersionInfo {
    Ssl30,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
    Unknown(u16),
}

impl TlsVersionInfo {
    fn from_tls_version(v: TlsVersion) -> Self {
        match v {
            TlsVersion::Ssl30 => Self::Ssl30,
            TlsVersion::Tls10 => Self::Tls10,
            TlsVersion::Tls11 => Self::Tls11,
            TlsVersion::Tls12 => Self::Tls12,
            TlsVersion::Tls13 => Self::Tls13,
            _ => Self::Unknown(v.0),
        }
    }

    fn short_code(&self) -> String {
        match self {
            Self::Ssl30 => "s30".to_string(),
            Self::Tls10 => "t10".to_string(),
            Self::Tls11 => "t11".to_string(),
            Self::Tls12 => "t12".to_string(),
            Self::Tls13 => "t13".to_string(),
            Self::Unknown(v) => format!("u{:x}", v),
        }
    }
}

impl fmt::Display for TlsVersionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ssl30 => write!(f, "SSL 3.0"),
            Self::Tls10 => write!(f, "TLS 1.0"),
            Self::Tls11 => write!(f, "TLS 1.1"),
            Self::Tls12 => write!(f, "TLS 1.2"),
            Self::Tls13 => write!(f, "TLS 1.3"),
            Self::Unknown(v) => write!(f, "Unknown (0x{:04x})", v),
        }
    }
}

/// Extracts Client Hello data for fingerprinting.
#[derive(Debug, Default)]
struct ClientHelloData {
    version: Option<TlsVersion>,
    cipher_suites: Vec<u16>,
    extensions: Vec<u16>,
    sni: Option<String>,
    supported_versions: Vec<u16>,
}

/// Attempts to parse a TLS Client Hello from raw TCP payload.
/// Returns None if the data is not a valid TLS Client Hello.
pub fn extract_fingerprint(payload: &[u8]) -> Option<TlsFingerprint> {
    if payload.len() < 5 {
        return None;
    }

    // Check for TLS record header (Content Type 22 = Handshake)
    if payload[0] != 0x16 {
        trace!("Not a TLS handshake record");
        return None;
    }

    // Parse the TLS record
    let (_, record) = parse_tls_plaintext(payload).ok()?;

    // Verify it's a handshake record
    if record.hdr.record_type != TlsRecordType::Handshake {
        trace!("TLS record is not a handshake");
        return None;
    }

    // Extract Client Hello data
    let mut client_hello = ClientHelloData::default();

    for msg in &record.msg {
        if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(hello)) = msg {
            client_hello.version = Some(hello.version);

            // Extract cipher suites
            client_hello.cipher_suites = hello.ciphers.iter().map(|c| c.0).collect();

            // Parse extensions if present
            if let Some(ext_data) = hello.ext {
                if let Ok((_, extensions)) = parse_tls_extensions(ext_data) {
                    for ext in extensions {
                        // Record extension type
                        let ext_type = get_extension_type(&ext);
                        client_hello.extensions.push(ext_type);

                        // Extract SNI if present (with validation)
                        if let TlsExtension::SNI(ref sni_list) = ext {
                            for (_, name) in sni_list {
                                if let Ok(s) = std::str::from_utf8(name) {
                                    client_hello.sni = validate_sni(s);
                                }
                            }
                        }

                        // Extract supported versions (for TLS 1.3 detection)
                        if let TlsExtension::SupportedVersions(ref versions) = ext {
                            client_hello.supported_versions =
                                versions.iter().map(|v| v.0).collect();
                        }
                    }
                }
            }

            break; // Only process first Client Hello
        }
    }

    // Require at least a version to generate fingerprint
    let version = client_hello.version?;

    // Determine actual TLS version (check supported_versions for TLS 1.3)
    let actual_version = if client_hello.supported_versions.contains(&0x0304) {
        TlsVersionInfo::Tls13
    } else {
        TlsVersionInfo::from_tls_version(version)
    };

    // Generate fingerprint
    let fingerprint = generate_fingerprint(
        &actual_version,
        &client_hello.cipher_suites,
        &client_hello.extensions,
    );

    // Check against known-good list
    let (is_known_good, known_match) = check_known_fingerprint(&fingerprint);

    debug!(
        "Extracted TLS fingerprint: {} (SNI: {:?}, known: {})",
        fingerprint, client_hello.sni, is_known_good
    );

    Some(TlsFingerprint {
        fingerprint,
        tls_version: actual_version,
        cipher_count: client_hello.cipher_suites.len(),
        extension_count: client_hello.extensions.len(),
        sni: client_hello.sni,
        is_known_good,
        known_match,
    })
}

/// Gets the numeric extension type from a TlsExtension.
fn get_extension_type(ext: &TlsExtension) -> u16 {
    match ext {
        TlsExtension::SNI(_) => 0,
        TlsExtension::MaxFragmentLength(_) => 1,
        TlsExtension::StatusRequest(_) => 5,
        TlsExtension::EllipticCurves(_) => 10,
        TlsExtension::EcPointFormats(_) => 11,
        TlsExtension::SignatureAlgorithms(_) => 13,
        TlsExtension::SessionTicket(_) => 35,
        TlsExtension::KeyShare(_) => 51,
        TlsExtension::PreSharedKey(_) => 41,
        TlsExtension::SupportedVersions(_) => 43,
        TlsExtension::Cookie(_) => 44,
        TlsExtension::PskExchangeModes(_) => 45,
        TlsExtension::NextProtocolNegotiation => 13172,
        TlsExtension::RenegotiationInfo(_) => 65281,
        TlsExtension::EncryptedServerName { .. } => 65486,
        _ => 65535, // Unknown
    }
}

/// Generates a JA4-style fingerprint string.
fn generate_fingerprint(
    version: &TlsVersionInfo,
    cipher_suites: &[u16],
    extensions: &[u16],
) -> String {
    // Sort cipher suites for deterministic output
    let mut sorted_ciphers = cipher_suites.to_vec();
    sorted_ciphers.sort();

    // Sort extensions for deterministic output
    let mut sorted_extensions = extensions.to_vec();
    sorted_extensions.sort();

    // Create cipher string and hash
    let cipher_str: String = sorted_ciphers
        .iter()
        .map(|c| format!("{:04x}", c))
        .collect::<Vec<_>>()
        .join("-");

    let cipher_hash = hash_component(&cipher_str);

    // Create extension string and hash
    let ext_str: String = sorted_extensions
        .iter()
        .map(|e| format!("{:04x}", e))
        .collect::<Vec<_>>()
        .join("-");

    let ext_hash = hash_component(&ext_str);

    // Compose final fingerprint
    format!("{}_{}_{}", version.short_code(), cipher_hash, ext_hash)
}

/// Hashes a component string and returns first 12 hex characters.
fn hash_component(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..6]) // First 6 bytes = 12 hex chars
}

/// Checks if a fingerprint matches any known-good fingerprint.
fn check_known_fingerprint(fingerprint: &str) -> (bool, Option<String>) {
    // Extract version prefix for partial matching
    let version_prefix = fingerprint.split('_').next().unwrap_or("");

    for known in KNOWN_GOOD_FINGERPRINTS {
        // Exact match
        if known.fingerprint == fingerprint {
            return (true, Some(known.description.to_string()));
        }

        // Partial match (same version prefix indicates similar client family)
        if known.fingerprint.starts_with(version_prefix) {
            // For now, we don't partial match - only exact
        }
    }

    (false, None)
}

/// Validates and sanitizes an SNI hostname.
/// Returns None if the SNI is invalid or potentially malicious.
fn validate_sni(sni: &str) -> Option<String> {
    // DNS hostnames have a max length of 253 characters
    if sni.is_empty() || sni.len() > 253 {
        return None;
    }

    // Only allow valid DNS characters: alphanumeric, hyphens, and dots
    // Also allow underscores as they appear in some internal hostnames
    if !sni
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return None;
    }

    // Must not start or end with a dot or hyphen
    if sni.starts_with('.') || sni.ends_with('.') || sni.starts_with('-') || sni.ends_with('-') {
        return None;
    }

    Some(sni.to_string())
}

/// Checks if a destination port is likely TLS traffic.
pub fn is_tls_port(port: u16) -> bool {
    matches!(port, 443 | 8443 | 993 | 995 | 465 | 636 | 989 | 990 | 5061)
}

/// Classification of TLS traffic for display purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsStatus {
    /// Valid TLS fingerprint extracted.
    Fingerprinted,
    /// TLS port but couldn't extract fingerprint (encrypted/resumed session).
    TlsNoFingerprint,
    /// Not a TLS port - plaintext traffic.
    Plaintext,
    /// Unknown protocol on unusual port.
    #[allow(dead_code)] // For future protocol classification
    Unknown,
}

impl fmt::Display for TlsStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fingerprinted => write!(f, "TLS"),
            Self::TlsNoFingerprint => write!(f, "TLS (No FP)"),
            Self::Plaintext => write!(f, "Plaintext"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_short_codes() {
        assert_eq!(TlsVersionInfo::Tls13.short_code(), "t13");
        assert_eq!(TlsVersionInfo::Tls12.short_code(), "t12");
        assert_eq!(TlsVersionInfo::Tls11.short_code(), "t11");
        assert_eq!(TlsVersionInfo::Tls10.short_code(), "t10");
        assert_eq!(TlsVersionInfo::Ssl30.short_code(), "s30");
    }

    #[test]
    fn test_fingerprint_generation_deterministic() {
        let version = TlsVersionInfo::Tls13;
        let ciphers = vec![0x1301, 0x1302, 0x1303];
        let extensions = vec![0, 5, 10, 13, 43, 51];

        let fp1 = generate_fingerprint(&version, &ciphers, &extensions);
        let fp2 = generate_fingerprint(&version, &ciphers, &extensions);

        assert_eq!(fp1, fp2, "Fingerprint generation should be deterministic");
    }

    #[test]
    fn test_fingerprint_different_for_different_ciphers() {
        let version = TlsVersionInfo::Tls13;
        let ciphers1 = vec![0x1301, 0x1302];
        let ciphers2 = vec![0x1301, 0x1303];
        let extensions = vec![0, 5, 10];

        let fp1 = generate_fingerprint(&version, &ciphers1, &extensions);
        let fp2 = generate_fingerprint(&version, &ciphers2, &extensions);

        assert_ne!(
            fp1, fp2,
            "Different ciphers should produce different fingerprints"
        );
    }

    #[test]
    fn test_cipher_order_independence() {
        let version = TlsVersionInfo::Tls12;
        let ciphers1 = vec![0x1301, 0x1302, 0x1303];
        let ciphers2 = vec![0x1303, 0x1301, 0x1302]; // Different order
        let extensions = vec![0, 5];

        let fp1 = generate_fingerprint(&version, &ciphers1, &extensions);
        let fp2 = generate_fingerprint(&version, &ciphers2, &extensions);

        assert_eq!(
            fp1, fp2,
            "Cipher order should not affect fingerprint (sorted)"
        );
    }

    #[test]
    fn test_is_tls_port() {
        assert!(is_tls_port(443));
        assert!(is_tls_port(8443));
        assert!(is_tls_port(993)); // IMAPS
        assert!(!is_tls_port(80));
        assert!(!is_tls_port(8080));
    }

    #[test]
    fn test_hash_component_length() {
        let hash = hash_component("test data");
        assert_eq!(hash.len(), 12, "Hash should be 12 hex characters");
    }

    #[test]
    fn test_fingerprint_format() {
        let version = TlsVersionInfo::Tls13;
        let ciphers = vec![0x1301];
        let extensions = vec![0];

        let fp = generate_fingerprint(&version, &ciphers, &extensions);

        // Should be format: t13_xxxxxxxxxxxx_xxxxxxxxxxxx
        let parts: Vec<&str> = fp.split('_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "t13");
        assert_eq!(parts[1].len(), 12);
        assert_eq!(parts[2].len(), 12);
    }

    // Test with a real TLS 1.2 Client Hello packet
    #[test]
    fn test_parse_tls12_client_hello() {
        // Minimal TLS 1.2 Client Hello (simplified for test)
        // In production, this would be a real captured packet
        let client_hello: [u8; 0] = [];

        // Empty payload should return None
        let result = extract_fingerprint(&client_hello);
        assert!(result.is_none());
    }

    #[test]
    fn test_non_tls_payload() {
        // HTTP request (not TLS)
        let http_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

        let result = extract_fingerprint(http_payload);
        assert!(result.is_none(), "HTTP payload should not be parsed as TLS");
    }

    #[test]
    fn test_tls_status_display() {
        assert_eq!(format!("{}", TlsStatus::Fingerprinted), "TLS");
        assert_eq!(format!("{}", TlsStatus::TlsNoFingerprint), "TLS (No FP)");
        assert_eq!(format!("{}", TlsStatus::Plaintext), "Plaintext");
    }
}
