//! Domain-specific error types for Network-Beacon.
//!
//! Uses `thiserror` for ergonomic error definitions that integrate
//! with the broader `anyhow` error handling strategy.

use thiserror::Error;

/// Errors that can occur during packet capture operations.
#[derive(Error, Debug)]
pub enum CaptureError {
    /// Failed to open a capture device (permissions, device not found, etc.).
    #[error("Failed to open capture device '{device}': {source}")]
    DeviceOpen {
        device: String,
        #[source]
        source: pcap::Error,
    },

    /// Failed to compile or apply a BPF filter expression.
    #[error("Failed to set capture filter '{filter}': {source}")]
    FilterSet {
        filter: String,
        #[source]
        source: pcap::Error,
    },

    /// Error reading a packet from the capture handle.
    #[error("Failed to read packet: {0}")]
    PacketRead(#[from] pcap::Error),

    /// The mpsc channel between capture and analyzer was closed unexpectedly.
    #[allow(dead_code)]
    #[error("Channel closed unexpectedly")]
    ChannelClosed,

    /// No suitable network interface could be found for capture.
    #[error("No suitable capture device found")]
    NoDeviceFound,

    /// A PCAP file path was specified but the file does not exist.
    #[allow(dead_code)]
    #[error("PCAP file not found: {0}")]
    FileNotFound(String),
}

/// Result type alias using anyhow for application-level error handling.
pub type Result<T> = anyhow::Result<T>;
