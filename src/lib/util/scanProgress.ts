import type { ScanProgress } from '$lib/types';

function countHosts(count: number): string {
  return `${count} ${count === 1 ? 'host' : 'hosts'}`;
}

/** Status line for a network scan, worded for the phase it is in. */
export function describeScanProgress(progress: ScanProgress | null): string {
  if (!progress) {
    return 'Starting scan...';
  }

  const { scanned, total, found } = progress;

  switch (progress.phase) {
    case 'ping':
      return `Pinging quiet addresses: ${scanned}/${total}, ${countHosts(found)} found`;
    case 'ports':
      return `Probing ports: ${scanned}/${total} hosts`;
    case 'fingerprint':
      return total > 0 ? `Identifying ${countHosts(total)}...` : 'Finishing scan...';
    case 'discovery':
    default:
      if (total === 0) {
        return 'Starting scan...';
      }
      return `Looking for hosts: ${scanned}/${total} addresses, ${countHosts(found)} found`;
  }
}

/** Fingerprinting reports no per-host progress, so its bar is indeterminate. */
export function isIndeterminatePhase(progress: ScanProgress | null): boolean {
  return progress?.phase === 'fingerprint';
}
