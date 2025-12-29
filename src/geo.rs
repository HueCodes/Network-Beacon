//! GeoIP and ASN enrichment module.
//!
//! Provides geographic and network ownership information for IP addresses
//! using MaxMind GeoLite2 databases.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use maxminddb::{geoip2, Reader};
use serde::{Deserialize, Serialize};
use tracing::{debug, trace, warn};

/// Risk level for geographic destinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GeoRisk {
    /// No elevated risk.
    None,
    /// Elevated risk (suspicious ASN or nearby high-risk country).
    Elevated,
    /// High risk (high-risk country or known bulletproof hosting).
    High,
}

impl Default for GeoRisk {
    fn default() -> Self {
        Self::None
    }
}

impl std::fmt::Display for GeoRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Elevated => write!(f, "elevated"),
            Self::High => write!(f, "high"),
        }
    }
}

/// Result of a GeoIP lookup.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GeoInfo {
    /// ISO 3166-1 alpha-2 country code (e.g., "US", "RU").
    pub country_code: Option<String>,
    /// Country name (e.g., "United States", "Russia").
    pub country_name: Option<String>,
    /// Autonomous System Number.
    pub asn: Option<u32>,
    /// ASN organization name.
    pub asn_org: Option<String>,
    /// Calculated risk level.
    pub risk: GeoRisk,
}

impl GeoInfo {
    /// Returns a short display string for the country.
    pub fn country_display(&self) -> String {
        self.country_code
            .clone()
            .unwrap_or_else(|| "??".to_string())
    }

    /// Returns a display string for the ASN.
    pub fn asn_display(&self) -> String {
        match (&self.asn, &self.asn_org) {
            (Some(asn), Some(org)) => format!("AS{} ({})", asn, truncate_org(org, 20)),
            (Some(asn), None) => format!("AS{}", asn),
            _ => "Unknown".to_string(),
        }
    }
}

/// Truncates an organization name for display.
fn truncate_org(org: &str, max_len: usize) -> String {
    if org.len() <= max_len {
        org.to_string()
    } else {
        format!("{}...", &org[..max_len - 3])
    }
}

/// Configuration for a suspicious ASN.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousAsn {
    pub asn: u32,
    pub name: String,
}

/// Configuration for the GeoIP enrichment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeoConfig {
    /// Enable GeoIP enrichment.
    pub enabled: bool,
    /// Path to GeoLite2-Country.mmdb file.
    pub geoip_db: Option<String>,
    /// Path to GeoLite2-ASN.mmdb file.
    pub asn_db: Option<String>,
    /// ISO country codes considered high-risk.
    pub high_risk_countries: Vec<String>,
    /// ASNs considered suspicious (bulletproof hosting, etc.).
    pub suspicious_asns: Vec<SuspiciousAsn>,
}

impl Default for GeoConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            geoip_db: None,
            asn_db: None,
            high_risk_countries: vec![
                "KP".to_string(), // North Korea
                "IR".to_string(), // Iran
                "SY".to_string(), // Syria
                "CU".to_string(), // Cuba
            ],
            suspicious_asns: vec![],
        }
    }
}

/// GeoIP lookup service.
pub struct GeoLookup {
    country_reader: Option<Reader<Vec<u8>>>,
    asn_reader: Option<Reader<Vec<u8>>>,
    high_risk_countries: HashSet<String>,
    suspicious_asns: HashSet<u32>,
}

impl GeoLookup {
    /// Creates a new GeoLookup from configuration.
    pub fn new(config: &GeoConfig) -> Self {
        if !config.enabled {
            debug!("GeoIP enrichment disabled");
            return Self {
                country_reader: None,
                asn_reader: None,
                high_risk_countries: HashSet::new(),
                suspicious_asns: HashSet::new(),
            };
        }

        let country_reader = config.geoip_db.as_ref().and_then(|path| {
            match Reader::open_readfile(Path::new(path)) {
                Ok(reader) => {
                    debug!("Loaded GeoIP country database from {}", path);
                    Some(reader)
                }
                Err(e) => {
                    warn!("Failed to load GeoIP country database {}: {}", path, e);
                    None
                }
            }
        });

        let asn_reader = config.asn_db.as_ref().and_then(|path| {
            match Reader::open_readfile(Path::new(path)) {
                Ok(reader) => {
                    debug!("Loaded GeoIP ASN database from {}", path);
                    Some(reader)
                }
                Err(e) => {
                    warn!("Failed to load GeoIP ASN database {}: {}", path, e);
                    None
                }
            }
        });

        let high_risk_countries: HashSet<String> = config
            .high_risk_countries
            .iter()
            .map(|s| s.to_uppercase())
            .collect();

        let suspicious_asns: HashSet<u32> =
            config.suspicious_asns.iter().map(|a| a.asn).collect();

        Self {
            country_reader,
            asn_reader,
            high_risk_countries,
            suspicious_asns,
        }
    }

    /// Returns true if GeoIP lookups are available.
    pub fn is_available(&self) -> bool {
        self.country_reader.is_some() || self.asn_reader.is_some()
    }

    /// Looks up geographic information for an IP address.
    pub fn lookup(&self, ip: IpAddr) -> GeoInfo {
        // Skip private/local IPs
        if is_private_ip(&ip) {
            return GeoInfo::default();
        }

        let mut info = GeoInfo::default();

        // Country lookup
        if let Some(ref reader) = self.country_reader {
            match reader.lookup::<geoip2::Country>(ip) {
                Ok(country) => {
                    if let Some(c) = country.country {
                        info.country_code = c.iso_code.map(|s| s.to_string());
                        if let Some(names) = c.names {
                            info.country_name = names.get("en").map(|s| s.to_string());
                        }
                    }
                }
                Err(e) => {
                    trace!("Country lookup failed for {}: {}", ip, e);
                }
            }
        }

        // ASN lookup
        if let Some(ref reader) = self.asn_reader {
            match reader.lookup::<geoip2::Asn>(ip) {
                Ok(asn) => {
                    info.asn = asn.autonomous_system_number;
                    info.asn_org = asn.autonomous_system_organization.map(|s| s.to_string());
                }
                Err(e) => {
                    trace!("ASN lookup failed for {}: {}", ip, e);
                }
            }
        }

        // Calculate risk level
        info.risk = self.calculate_risk(&info);

        info
    }

    /// Calculates the risk level based on country and ASN.
    fn calculate_risk(&self, info: &GeoInfo) -> GeoRisk {
        // Check for high-risk country
        if let Some(ref cc) = info.country_code {
            if self.high_risk_countries.contains(&cc.to_uppercase()) {
                return GeoRisk::High;
            }
        }

        // Check for suspicious ASN
        if let Some(asn) = info.asn {
            if self.suspicious_asns.contains(&asn) {
                return GeoRisk::High;
            }
        }

        GeoRisk::None
    }
}

/// Checks if an IP address is private/local.
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private()
                || ipv4.is_loopback()
                || ipv4.is_link_local()
                || ipv4.is_broadcast()
                || ipv4.is_unspecified()
        }
        IpAddr::V6(ipv6) => ipv6.is_loopback() || ipv6.is_unspecified(),
    }
}

/// Thread-safe shared GeoLookup.
pub type SharedGeoLookup = Arc<GeoLookup>;

/// Creates a shared GeoLookup instance.
pub fn new_shared_geo_lookup(config: &GeoConfig) -> SharedGeoLookup {
    Arc::new(GeoLookup::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_geo_risk_display() {
        assert_eq!(format!("{}", GeoRisk::None), "none");
        assert_eq!(format!("{}", GeoRisk::Elevated), "elevated");
        assert_eq!(format!("{}", GeoRisk::High), "high");
    }

    #[test]
    fn test_geo_info_country_display() {
        let info = GeoInfo {
            country_code: Some("US".to_string()),
            ..Default::default()
        };
        assert_eq!(info.country_display(), "US");

        let empty = GeoInfo::default();
        assert_eq!(empty.country_display(), "??");
    }

    #[test]
    fn test_geo_info_asn_display() {
        let info = GeoInfo {
            asn: Some(15169),
            asn_org: Some("Google LLC".to_string()),
            ..Default::default()
        };
        assert_eq!(info.asn_display(), "AS15169 (Google LLC)");

        let no_org = GeoInfo {
            asn: Some(15169),
            ..Default::default()
        };
        assert_eq!(no_org.asn_display(), "AS15169");

        let empty = GeoInfo::default();
        assert_eq!(empty.asn_display(), "Unknown");
    }

    #[test]
    fn test_is_private_ip() {
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn test_truncate_org() {
        assert_eq!(truncate_org("Short", 20), "Short");
        assert_eq!(
            truncate_org("This is a very long organization name", 20),
            "This is a very lo..."
        );
    }

    #[test]
    fn test_geo_lookup_disabled() {
        let config = GeoConfig::default();
        let lookup = GeoLookup::new(&config);
        assert!(!lookup.is_available());
    }

    #[test]
    fn test_geo_lookup_private_ip() {
        let config = GeoConfig {
            enabled: true,
            ..Default::default()
        };
        let lookup = GeoLookup::new(&config);
        let info = lookup.lookup(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(info.country_code.is_none());
        assert_eq!(info.risk, GeoRisk::None);
    }

    #[test]
    fn test_high_risk_country_detection() {
        let config = GeoConfig {
            enabled: true,
            high_risk_countries: vec!["KP".to_string(), "IR".to_string()],
            ..Default::default()
        };
        let lookup = GeoLookup::new(&config);

        // Simulate a lookup result with high-risk country
        let info = GeoInfo {
            country_code: Some("KP".to_string()),
            ..Default::default()
        };
        let risk = lookup.calculate_risk(&info);
        assert_eq!(risk, GeoRisk::High);
    }

    #[test]
    fn test_suspicious_asn_detection() {
        let config = GeoConfig {
            enabled: true,
            suspicious_asns: vec![SuspiciousAsn {
                asn: 44477,
                name: "Stark Industries".to_string(),
            }],
            ..Default::default()
        };
        let lookup = GeoLookup::new(&config);

        let info = GeoInfo {
            asn: Some(44477),
            ..Default::default()
        };
        let risk = lookup.calculate_risk(&info);
        assert_eq!(risk, GeoRisk::High);
    }
}
