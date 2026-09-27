use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub ip: String,
    pub cidr: u8,
    pub subnet: String,
    pub host_count: u32,
    /// Whether this interface carries the IPv4 default route.
    #[serde(default)]
    pub is_default_route: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub state: String,
    pub service: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub ip: String,
    pub name: Option<String>,
    pub reachable: bool,
    pub open_ports: Vec<PortInfo>,
    pub last_seen: String,
    pub fingerprint: Option<DeviceFingerprint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFingerprint {
    pub mac_address: Option<String>,
    pub oui: Option<String>,
    pub vendor: Option<String>,
    pub manufacturer: Option<String>,
    pub model_guess: Option<String>,
    pub device_type: Option<String>,
    pub os_guess: Option<String>,
    pub confidence: u8,
    pub sources: Vec<String>,
    pub notes: Vec<String>,
    pub discovered_services: Vec<String>,
    pub last_updated: String,
}

/// What Fingerbank said about a MAC address. Cached per MAC so an online
/// lookup isn't repeated on every scan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FingerbankResult {
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub device_type: Option<String>,
    pub os_guess: Option<String>,
    pub confidence: Option<u8>,
    /// RFC 3339 UTC timestamp (`Utc::now().to_rfc3339()`); cache expiry is
    /// computed from it.
    pub fetched_at: String,
}

impl FingerbankResult {
    /// A remembered "Fingerbank doesn't know this device", so unknown MACs are
    /// not queried again on every scan.
    pub fn no_match(fetched_at: String) -> Self {
        Self {
            vendor: None,
            model: None,
            device_type: None,
            os_guess: None,
            confidence: None,
            fetched_at,
        }
    }

    pub fn is_no_match(&self) -> bool {
        self.vendor.is_none()
            && self.model.is_none()
            && self.device_type.is_none()
            && self.os_guess.is_none()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortProfile {
    Quick,
    Standard,
    Deep,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DiscoveryMode {
    Tcp,
    Hybrid,
}

fn default_discovery_mode() -> DiscoveryMode {
    DiscoveryMode::Hybrid
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    pub interface_name: String,
    pub subnet: Option<String>,
    pub port_profile: PortProfile,
    #[serde(default = "default_discovery_mode")]
    pub discovery_mode: DiscoveryMode,
    pub timeout_ms: Option<u64>,
    pub max_hosts: Option<usize>,
}

/// Stage of a scan. For a network scan, `scanned`/`total` in [`ScanProgress`]
/// count addresses during `Discovery`, quiet addresses during `Ping`, live
/// hosts during `Ports`, and hosts during `Fingerprint`. A single-host Deep
/// Scan (`scan_host_ports`) reports `Ports` with `scanned`/`total` counting
/// that host's ports instead.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ScanPhase {
    #[default]
    Discovery,
    Ping,
    Ports,
    Fingerprint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    #[serde(default)]
    pub phase: ScanPhase,
    pub scanned: usize,
    pub total: usize,
    pub found: usize,
    pub running: bool,
    pub current_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub started_at: String,
    pub completed_at: Option<String>,
    #[serde(default)]
    pub cancelled: bool,
    pub hosts: Vec<Host>,
    pub options: ScanOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanErrorPayload {
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemColors {
    pub accent_color: Option<String>,
    pub accent_text_color: Option<String>,
    pub highlight_color: Option<String>,
    pub highlight_text_color: Option<String>,
}
