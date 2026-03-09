//! Domain-specific error types for Network-Beacon.
//!
//! Uses `thiserror` for ergonomic error definitions that integrate
//! with the broader `anyhow` error handling strategy.

use thiserror::Error;

/// Errors that can occur during packet capture operations.
#[derive(Error, Debug)]
pub enum CaptureError {
    #[error("Failed to open capture device '{device}': {source}")]
    DeviceOpen {
        device: String,
        #[source]
        source: pcap::Error,
    },

    #[error("Failed to set capture filter '{filter}': {source}")]
    FilterSet {
        filter: String,
        #[source]
        source: pcap::Error,
    },

    #[error("Failed to read packet: {0}")]
    PacketRead(#[from] pcap::Error),

    #[allow(dead_code)]
    #[error("Channel closed unexpectedly")]
    ChannelClosed,

    #[error("No suitable capture device found")]
    NoDeviceFound,

    #[allow(dead_code)]
    #[error("PCAP file not found: {0}")]
    FileNotFound(String),
}

/// Result type alias using anyhow for application-level error handling.
pub type Result<T> = anyhow::Result<T>;
