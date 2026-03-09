use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub ip: String,
    pub cidr: u8,
    pub subnet: String,
    pub host_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub state: String,
    pub service: Option<String>,
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
    pub last_updated: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortProfile {
    Quick,
    Standard,
    Deep,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    pub interface_name: String,
    pub subnet: Option<String>,
    pub port_profile: PortProfile,
    pub timeout_ms: Option<u64>,
    pub max_hosts: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
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
    pub hosts: Vec<Host>,
    pub options: ScanOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanErrorPayload {
    pub message: String,
}
