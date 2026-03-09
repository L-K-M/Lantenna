import { invoke } from '@tauri-apps/api/core';
import type { Host, NetworkInterface, PortProfile, ScanOptions, ScanResult } from './types';

export class TauriService {
  static async getNetworkInterfaces(): Promise<NetworkInterface[]> {
    return await invoke('get_network_interfaces');
  }

  static async startScan(options: ScanOptions): Promise<void> {
    await invoke('start_scan', { options });
  }

  static async cancelScan(): Promise<void> {
    await invoke('cancel_scan');
  }

  static async getScanResults(): Promise<ScanResult | null> {
    return await invoke('get_scan_results');
  }

  static async scanHostPorts(ip: string, profile: PortProfile): Promise<Host> {
    return await invoke('scan_host_ports', { ip, profile });
  }
}
