export type PortProfile = 'quick' | 'standard' | 'deep';

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

export interface Host {
  ip: string;
  name: string | null;
  reachable: boolean;
  open_ports: PortInfo[];
  last_seen: string;
}

export interface ScanOptions {
  interface_name: string;
  subnet: string | null;
  port_profile: PortProfile;
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
  hosts: Host[];
  options: ScanOptions;
}

export interface ScanErrorPayload {
  message: string;
}
