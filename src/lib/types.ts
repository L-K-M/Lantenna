export type PortProfile = 'quick' | 'standard' | 'deep';
export type DiscoveryMode = 'tcp' | 'hybrid';
export type ScanApproach = 'fast' | 'balanced' | 'thorough';

export interface NetworkInterface {
  name: string;
  ip: string;
  cidr: number;
  subnet: string;
  host_count: number;
}

export interface PortInfo {
  port: number;
  state: 'open';
  service: string | null;
}

export interface DeviceFingerprint {
  mac_address: string | null;
  oui: string | null;
  vendor: string | null;
  manufacturer: string | null;
  model_guess: string | null;
  device_type: string | null;
  os_guess: string | null;
  confidence: number;
  sources: string[];
  notes: string[];
  last_updated: string;
}

export interface Host {
  ip: string;
  name: string | null;
  reachable: boolean;
  open_ports: PortInfo[];
  last_seen: string;
  fingerprint: DeviceFingerprint | null;
}

export interface ScanOptions {
  interface_name: string;
  subnet: string | null;
  port_profile: PortProfile;
  discovery_mode: DiscoveryMode;
  timeout_ms: number | null;
  max_hosts: number | null;
}

export interface ScanProgress {
  scanned: number;
  total: number;
  found: number;
  running: boolean;
  current_ip: string | null;
}

export interface ScanResult {
  started_at: string;
  completed_at: string | null;
  cancelled: boolean;
  hosts: Host[];
  options: ScanOptions;
}

export interface ScanErrorPayload {
  message: string;
}
