import type { Host } from '$lib/types';
import cameraIcon from '$lib/assets/host-icons/camera.svg';
import iotIcon from '$lib/assets/host-icons/iot.svg';
import kvmIcon from '$lib/assets/host-icons/kvm.svg';
import mediaIcon from '$lib/assets/host-icons/media.svg';
import mobileIcon from '$lib/assets/host-icons/mobile.svg';
import pcGenericIcon from '$lib/assets/host-icons/pc-generic.svg';
import pcLinuxIcon from '$lib/assets/host-icons/pc-linux.svg';
import pcMacIcon from '$lib/assets/host-icons/pc-mac.svg';
import pcWindowsIcon from '$lib/assets/host-icons/pc-windows.svg';
import printerIcon from '$lib/assets/host-icons/printer.svg';
import routerIcon from '$lib/assets/host-icons/router.svg';
import serverIcon from '$lib/assets/host-icons/server.svg';

export interface IconInfo {
  src: string;
  label: string;
}

function includesAny(haystack: string, needles: string[]): boolean {
  return needles.some((needle) => haystack.includes(needle));
}

function normalizeHintText(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
}

function isWindowsLike(os: string): boolean {
  return includesAny(os, ['windows', 'microsoft', 'win32', 'win64']);
}

function isMacLike(os: string): boolean {
  return includesAny(os, ['mac', 'darwin', 'os x', 'ios']);
}

function isLinuxLike(os: string): boolean {
  return includesAny(os, ['linux', 'ubuntu', 'debian', 'fedora', 'centos', 'arch', 'red hat', 'unix', 'bsd']);
}

/**
 * Picks the pixel-art icon for a host from its name, fingerprint and open
 * ports. Shared by the list and icon views so both show the same device kind.
 */
export function getHostIcon(host: Host, customName: string): IconInfo {
  const fp = host.fingerprint;
  const nameHints = normalizeHintText(`${customName} ${host.name || ''}`);
  const deviceType = normalizeHintText(fp?.device_type || '');
  const modelHints = normalizeHintText(`${fp?.model_guess || ''} ${fp?.vendor || ''} ${fp?.manufacturer || ''}`);
  const os = normalizeHintText(fp?.os_guess || '');
  const allHints = `${nameHints} ${deviceType} ${modelHints} ${os}`;

  const hasRtspLikePort = host.open_ports.some(
    (port) =>
      port.port === 554 ||
      port.port === 8554 ||
      (port.service || '').toLowerCase().includes('rtsp') ||
      (port.service || '').toLowerCase().includes('onvif')
  );

  const hasKvmLikePort = host.open_ports.some(
    (port) =>
      [5900, 5901, 5902, 623].includes(port.port) ||
      (port.service || '').toLowerCase().includes('vnc') ||
      (port.service || '').toLowerCase().includes('ipmi')
  );

  if (
    /\bcam\b/.test(nameHints) ||
    includesAny(allHints, ['camera', 'webcam', 'ipcam', 'cctv', 'hikvision', 'reolink', 'dahua', 'axis', 'onvif']) ||
    hasRtspLikePort
  ) {
    return { src: cameraIcon, label: 'Camera' };
  }

  if (includesAny(allHints, ['kvm', 'pikvm', 'ipkvm', 'ipmi', 'idrac', 'ilo', 'bmc']) || hasKvmLikePort) {
    return { src: kvmIcon, label: 'KVM device' };
  }

  if (
    includesAny(allHints, [
      'rt ax',
      'rt ac',
      'rt be',
      'router',
      'gateway',
      'access point',
      'wifi',
      'wi fi',
      'wlan',
      'mesh',
      'fritzbox',
      'unifi',
      'openwrt',
      'dd wrt',
      'modem',
      'firewall',
      'switch'
    ])
  ) {
    return { src: routerIcon, label: 'Network device' };
  }

  if (includesAny(allHints, ['phone', 'mobile', 'tablet', 'iphone', 'ipad', 'pixel', 'galaxy'])) {
    return { src: mobileIcon, label: 'Mobile device' };
  }

  if (includesAny(allHints, ['printer', 'laserjet', 'deskjet', 'officejet', 'epson', 'brother'])) {
    return { src: printerIcon, label: 'Printer' };
  }

  if (includesAny(allHints, ['tv', 'appletv', 'apple tv', 'chromecast', 'roku', 'fire tv', 'media'])) {
    return { src: mediaIcon, label: 'TV / media device' };
  }

  if (includesAny(nameHints, ['macbook', 'imac', 'mac mini', 'mac studio']) || /\bmac\b/.test(nameHints)) {
    return { src: pcMacIcon, label: 'Apple host' };
  }

  if (
    (includesAny(deviceType, ['workstation', 'server']) || includesAny(allHints, ['workstation', 'server'])) &&
    isWindowsLike(os)
  ) {
    return { src: pcWindowsIcon, label: 'Windows workstation/server' };
  }

  if (includesAny(allHints, ['nas', 'synology', 'qnap', 'truenas', 'freenas', 'storage'])) {
    return { src: serverIcon, label: 'Server / storage' };
  }

  if (includesAny(allHints, ['iot', 'smart', 'esphome', 'tasmota', 'shelly', 'zigbee', 'zwave'])) {
    return { src: iotIcon, label: 'IoT device' };
  }

  if (isWindowsLike(os)) {
    return { src: pcWindowsIcon, label: 'Windows host' };
  }

  if (isMacLike(os)) {
    return { src: pcMacIcon, label: 'Apple host' };
  }

  if (isLinuxLike(os)) {
    return { src: pcLinuxIcon, label: 'Linux host' };
  }

  if (includesAny(os, ['android'])) {
    return { src: mobileIcon, label: 'Android host' };
  }

  return { src: pcGenericIcon, label: 'Unknown host' };
}
