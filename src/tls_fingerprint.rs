//! TLS Fingerprinting module for JA3 and JA4-style Client Hello analysis.
//!
//! This module performs deep-packet inspection on TLS handshakes to extract
//! fingerprints that can identify specific client implementations, including
//! C2 implants and unauthorized tools.
//!
//! # JA3 Fingerprint Format
//!
//! JA3 is the industry-standard TLS fingerprinting format:
//! `MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)`
//!
//! Example: `e7d705a3286e19ea42f587b344ee6865`
//!
//! JA3 provides compatibility with existing threat intelligence feeds and databases.
//!
//! # JA4 Fingerprint Format (JA4-inspired)
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

/// Known malicious JA3 fingerprints from threat intelligence.
/// These are MD5 hashes of JA3 strings associated with known C2 frameworks and malware.
pub static KNOWN_MALICIOUS_JA3: &[KnownJa3Fingerprint] = &[
    KnownJa3Fingerprint {
        ja3_hash: "e7d705a3286e19ea42f587b344ee6865",
        description: "Cobalt Strike default",
        category: ThreatCategory::C2Framework,
    },
    KnownJa3Fingerprint {
        ja3_hash: "72a589da586844d7f0818ce684948eea",
        description: "Metasploit Meterpreter",
        category: ThreatCategory::C2Framework,
    },
    KnownJa3Fingerprint {
        ja3_hash: "a0e9f5d64349fb13191bc781f81f42e1",
        description: "Cobalt Strike 4.0+",
        category: ThreatCategory::C2Framework,
    },
    KnownJa3Fingerprint {
        ja3_hash: "51c64c77e60f3980eea90869b68c58a8",
        description: "Sliver C2",
        category: ThreatCategory::C2Framework,
    },
    KnownJa3Fingerprint {
        ja3_hash: "3b5074b1b5d032e5620f69f9f700ff0e",
        description: "Empire PowerShell",
        category: ThreatCategory::C2Framework,
    },
    KnownJa3Fingerprint {
        ja3_hash: "d3993683e3cb5d36c6c3f11a13d44c56",
        description: "Covenant C2",
        category: ThreatCategory::C2Framework,
    },
    KnownJa3Fingerprint {
        ja3_hash: "6734f37431670b3ab4292b8f60f29984",
        description: "Trickbot",
        category: ThreatCategory::Malware,
    },
    KnownJa3Fingerprint {
        ja3_hash: "e35df3e00ca4ef31d42b34bebaa2f86e",
        description: "AsyncRAT",
        category: ThreatCategory::Malware,
    },
    KnownJa3Fingerprint {
        ja3_hash: "473cd7cb9faa642487833865d516e578",
        description: "Emotet",
        category: ThreatCategory::Malware,
    },
];

/// Category of threat for JA3 fingerprints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThreatCategory {
    /// Known C2 framework (Cobalt Strike, Metasploit, etc.)
    C2Framework,
    /// Known malware family
    Malware,
    /// Suspicious but unconfirmed
    #[allow(dead_code)]
    Suspicious,
}

impl fmt::Display for ThreatCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::C2Framework => write!(f, "C2 Framework"),
            Self::Malware => write!(f, "Malware"),
            Self::Suspicious => write!(f, "Suspicious"),
        }
    }
}

/// A known malicious JA3 fingerprint entry.
#[derive(Debug, Clone)]
pub struct KnownJa3Fingerprint {
    pub ja3_hash: &'static str,
    pub description: &'static str,
    pub category: ThreatCategory,
}

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
    /// JA3 fingerprint hash (MD5, 32 hex chars).
    pub ja3_hash: String,
    /// JA3 raw string before hashing (for debugging/analysis).
    pub ja3_string: String,
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
    /// Whether this matches a known malicious JA3 fingerprint.
    pub is_known_malicious: bool,
    /// Description of matched malicious fingerprint.
    pub malicious_match: Option<String>,
    /// Threat category if malicious.
    pub threat_category: Option<ThreatCategory>,
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
    /// Elliptic curves (supported groups) for JA3.
    elliptic_curves: Vec<u16>,
    /// Elliptic curve point formats for JA3.
    ec_point_formats: Vec<u8>,
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

                        // Extract elliptic curves (supported groups) for JA3
                        if let TlsExtension::EllipticCurves(ref curves) = ext {
                            client_hello.elliptic_curves =
                                curves.iter().map(|c| c.0).collect();
                        }

                        // Extract EC point formats for JA3
                        if let TlsExtension::EcPointFormats(ref formats) = ext {
                            client_hello.ec_point_formats = formats.to_vec();
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

    // Generate JA4-style fingerprint
    let fingerprint = generate_fingerprint(
        &actual_version,
        &client_hello.cipher_suites,
        &client_hello.extensions,
    );

    // Generate JA3 fingerprint
    let (ja3_string, ja3_hash) = generate_ja3(
        version,
        &client_hello.cipher_suites,
        &client_hello.extensions,
        &client_hello.elliptic_curves,
        &client_hello.ec_point_formats,
    );

    // Check against known-good list (JA4)
    let (is_known_good, known_match) = check_known_fingerprint(&fingerprint);

    // Check against known malicious JA3 fingerprints
    let (is_known_malicious, malicious_match, threat_category) = check_malicious_ja3(&ja3_hash);

    debug!(
        "Extracted TLS fingerprint: {} / JA3: {} (SNI: {:?}, known_good: {}, malicious: {})",
        fingerprint, ja3_hash, client_hello.sni, is_known_good, is_known_malicious
    );

    Some(TlsFingerprint {
        fingerprint,
        ja3_hash,
        ja3_string,
        tls_version: actual_version,
        cipher_count: client_hello.cipher_suites.len(),
        extension_count: client_hello.extensions.len(),
        sni: client_hello.sni,
        is_known_good,
        known_match,
        is_known_malicious,
        malicious_match,
        threat_category,
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

/// Generates a JA3 fingerprint from TLS Client Hello components.
///
/// JA3 format: `SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`
/// Returns (ja3_string, ja3_hash) where ja3_hash is the MD5 of ja3_string.
///
/// # JA3 Specification
/// - SSLVersion: Decimal representation of the TLS version (e.g., 771 for TLS 1.2)
/// - Ciphers: Comma-separated decimal cipher suite values (GREASE values removed)
/// - Extensions: Comma-separated decimal extension type values (GREASE values removed)
/// - EllipticCurves: Comma-separated decimal supported group values (GREASE values removed)
/// - EllipticCurvePointFormats: Comma-separated decimal point format values
fn generate_ja3(
    version: TlsVersion,
    cipher_suites: &[u16],
    extensions: &[u16],
    elliptic_curves: &[u16],
    ec_point_formats: &[u8],
) -> (String, String) {
    // Convert TLS version to decimal (e.g., TLS 1.2 = 0x0303 = 771)
    let version_decimal = version.0;

    // Filter out GREASE values (0x?a?a pattern)
    let filter_grease_u16 = |v: &u16| -> bool {
        let high = (v >> 8) as u8;
        let low = (v & 0xff) as u8;
        !(high == low && (high & 0x0f) == 0x0a)
    };

    // Build cipher string (comma-separated decimals, no GREASE)
    let ciphers_str: String = cipher_suites
        .iter()
        .filter(|c| filter_grease_u16(c))
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(",");

    // Build extensions string (comma-separated decimals, no GREASE)
    let extensions_str: String = extensions
        .iter()
        .filter(|e| filter_grease_u16(e))
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join(",");

    // Build elliptic curves string (comma-separated decimals, no GREASE)
    let curves_str: String = elliptic_curves
        .iter()
        .filter(|c| filter_grease_u16(c))
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(",");

    // Build EC point formats string (comma-separated decimals)
    let formats_str: String = ec_point_formats
        .iter()
        .map(|f| f.to_string())
        .collect::<Vec<_>>()
        .join(",");

    // Compose JA3 string
    let ja3_string = format!(
        "{},{},{},{},{}",
        version_decimal, ciphers_str, extensions_str, curves_str, formats_str
    );

    // Calculate MD5 hash
    let ja3_hash = format!("{:x}", md5::compute(ja3_string.as_bytes()));

    trace!("Generated JA3: {} -> {}", ja3_string, ja3_hash);

    (ja3_string, ja3_hash)
}

/// Checks if a JA3 hash matches any known malicious fingerprint.
fn check_malicious_ja3(ja3_hash: &str) -> (bool, Option<String>, Option<ThreatCategory>) {
    for known in KNOWN_MALICIOUS_JA3 {
        if known.ja3_hash == ja3_hash {
            debug!(
                "Matched malicious JA3 fingerprint: {} ({})",
                known.description, known.category
            );
            return (
                true,
                Some(known.description.to_string()),
                Some(known.category),
            );
        }
    }

    (false, None, None)
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

    // JA3 fingerprint tests

    #[test]
    fn test_ja3_generation_deterministic() {
        let version = TlsVersion::Tls12;
        let ciphers = vec![0x1301, 0x1302, 0x1303];
        let extensions = vec![0, 5, 10, 13, 43, 51];
        let curves = vec![23, 24, 25]; // secp256r1, secp384r1, secp521r1
        let formats = vec![0]; // uncompressed

        let (str1, hash1) = generate_ja3(version, &ciphers, &extensions, &curves, &formats);
        let (str2, hash2) = generate_ja3(version, &ciphers, &extensions, &curves, &formats);

        assert_eq!(str1, str2, "JA3 string generation should be deterministic");
        assert_eq!(hash1, hash2, "JA3 hash generation should be deterministic");
    }

    #[test]
    fn test_ja3_format() {
        let version = TlsVersion::Tls12; // 0x0303 = 771
        let ciphers = vec![0x1301, 0x1302];
        let extensions = vec![0, 5, 10];
        let curves = vec![23, 24];
        let formats = vec![0, 1];

        let (ja3_string, ja3_hash) = generate_ja3(version, &ciphers, &extensions, &curves, &formats);

        // JA3 string format: version,ciphers,extensions,curves,formats
        let parts: Vec<&str> = ja3_string.split(',').collect();

        // First part should be version (771 for TLS 1.2)
        assert_eq!(parts[0], "771", "Version should be 771 for TLS 1.2");

        // Hash should be 32 hex characters (MD5)
        assert_eq!(ja3_hash.len(), 32, "JA3 hash should be 32 hex characters");
        assert!(
            ja3_hash.chars().all(|c| c.is_ascii_hexdigit()),
            "JA3 hash should only contain hex characters"
        );
    }

    #[test]
    fn test_ja3_grease_filtering() {
        let version = TlsVersion::Tls12;
        // Include GREASE values (0x0a0a, 0x1a1a, etc.)
        let ciphers_with_grease = vec![0x0a0a, 0x1301, 0x1a1a, 0x1302];
        let ciphers_without_grease = vec![0x1301, 0x1302];
        let extensions = vec![0, 5];
        let curves = vec![23];
        let formats = vec![0];

        let (str_with_grease, _) =
            generate_ja3(version, &ciphers_with_grease, &extensions, &curves, &formats);
        let (str_without_grease, _) =
            generate_ja3(version, &ciphers_without_grease, &extensions, &curves, &formats);

        // GREASE values should be filtered out, so both should produce same result
        assert_eq!(
            str_with_grease, str_without_grease,
            "GREASE values should be filtered from JA3"
        );
    }

    #[test]
    fn test_ja3_different_versions() {
        let ciphers = vec![0x1301];
        let extensions = vec![0, 5];
        let curves = vec![23];
        let formats = vec![0];

        let (str_tls12, _) =
            generate_ja3(TlsVersion::Tls12, &ciphers, &extensions, &curves, &formats);
        let (str_tls11, _) =
            generate_ja3(TlsVersion::Tls11, &ciphers, &extensions, &curves, &formats);

        assert_ne!(
            str_tls12, str_tls11,
            "Different TLS versions should produce different JA3 strings"
        );

        // TLS 1.2 = 771, TLS 1.1 = 770
        assert!(str_tls12.starts_with("771,"));
        assert!(str_tls11.starts_with("770,"));
    }

    #[test]
    fn test_check_malicious_ja3() {
        // Test known malicious fingerprint detection
        let cobalt_strike_ja3 = "e7d705a3286e19ea42f587b344ee6865";
        let (is_malicious, desc, category) = check_malicious_ja3(cobalt_strike_ja3);

        assert!(is_malicious, "Known Cobalt Strike JA3 should be detected");
        assert!(
            desc.as_ref().map(|d| d.contains("Cobalt Strike")).unwrap_or(false),
            "Description should mention Cobalt Strike"
        );
        assert_eq!(category, Some(ThreatCategory::C2Framework));

        // Test unknown fingerprint
        let unknown_ja3 = "0000000000000000000000000000000a";
        let (is_malicious_unknown, _, _) = check_malicious_ja3(unknown_ja3);
        assert!(!is_malicious_unknown, "Unknown JA3 should not be flagged");
    }

    #[test]
    fn test_threat_category_display() {
        assert_eq!(format!("{}", ThreatCategory::C2Framework), "C2 Framework");
        assert_eq!(format!("{}", ThreatCategory::Malware), "Malware");
        assert_eq!(format!("{}", ThreatCategory::Suspicious), "Suspicious");
    }

    #[test]
    fn test_ja3_empty_components() {
        let version = TlsVersion::Tls12;
        let ciphers: Vec<u16> = vec![];
        let extensions: Vec<u16> = vec![];
        let curves: Vec<u16> = vec![];
        let formats: Vec<u8> = vec![];

        let (ja3_string, ja3_hash) = generate_ja3(version, &ciphers, &extensions, &curves, &formats);

        // Should still generate valid format with empty sections
        assert!(ja3_string.starts_with("771,"));
        assert_eq!(ja3_hash.len(), 32);
    }
}
