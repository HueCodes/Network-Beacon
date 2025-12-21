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

    #[allow(dead_code)] // For future async channel handling
    #[error("Channel closed unexpectedly")]
    ChannelClosed,

    #[error("No suitable capture device found")]
    NoDeviceFound,
}

/// Errors that can occur during flow analysis.
#[allow(dead_code)] // Defined for future typed error handling
#[derive(Error, Debug)]
pub enum AnalyzerError {
    #[error("Insufficient data points for analysis (need at least {required}, got {actual})")]
    InsufficientData { required: usize, actual: usize },

    #[error("Statistical calculation failed: {0}")]
    StatisticalError(String),

    #[error("Flow not found: {0}")]
    FlowNotFound(String),
}

/// Errors that can occur in the TUI layer.
#[allow(dead_code)] // Defined for future typed error handling
#[derive(Error, Debug)]
pub enum UiError {
    #[error("Terminal initialization failed: {0}")]
    TerminalInit(#[from] std::io::Error),

    #[error("Failed to render frame: {0}")]
    RenderError(String),
}

/// Result type alias using anyhow for application-level error handling.
pub type Result<T> = anyhow::Result<T>;
