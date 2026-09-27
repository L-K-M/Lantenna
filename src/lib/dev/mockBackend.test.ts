// Owner: unit G. The mock backend of spec 8.6: scenario parameters, the
// capability check, the app commands, the window and menu plugins, and
// the scripted scans (event order and payloads as the real backend
// sends them). mockBoot.test.ts boots the page on it.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { clearMocks, mockIPC, mockWindows } from '@tauri-apps/api/mocks';
import { CheckMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu } from '@tauri-apps/api/menu';
import type { Platform } from '$lib/app/platform';
import type { Host, ScanOptions, ScanProgress, ScanResult } from '$lib/types';
import { HOME_HOSTS, interfacesFor, userData } from './fixtures';
import {
  MockBackend,
  PANIC_MESSAGE,
  allowedPluginCommands,
  parseScenario,
  seedStorage,
  storeMatchesSeed
} from './mockBackend';

const NOW = Date.parse('2026-09-27T15:42:00Z');

interface Sent {
  event: string;
  payload: unknown;
}

function setup(search = '', platform: Platform = 'mac') {
  const sent: Sent[] = [];
  const scenario = parseScenario(search, platform);
  const backend = new MockBackend(scenario, {
    now: () => NOW,
    emit: (event, payload) => sent.push({ event, payload: JSON.parse(JSON.stringify(payload)) }),
    viewport: { width: 1200, height: 760, scale: 2 }
  });
  const of = <T>(event: string) => sent.filter((item) => item.event === event).map((item) => item.payload as T);
  return { backend, sent, of, scenario };
}

const home = (platform: Platform = 'mac') => interfacesFor(platform).find((item) => item.cidr === 24 && item.is_default_route)!;

function balanced(platform: Platform = 'mac'): ScanOptions {
  const iface = home(platform);
  return {
    interface_name: iface.name,
    subnet: iface.subnet,
    port_profile: 'standard',
    discovery_mode: 'hybrid',
    timeout_ms: 450,
    max_hosts: 254
  };
}

async function scanUntilDone(sent: Sent[]): Promise<void> {
  await vi.waitFor(() => expect(sent.some((item) => item.event === 'scan-complete' || item.event === 'scan-error')).toBe(true));
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('parseScenario', () => {
  it('defaults to idle, held, seeded and checked against the capability', () => {
    expect(parseScenario('', 'mac')).toMatchObject({
      name: 'idle',
      platform: 'mac',
      shaded: false,
      inactive: false,
      balloons: null,
      view: null,
      pane: null,
      tab: null,
      select: null,
      error: 'scan',
      update: false,
      accent: '#007AFF',
      speed: 1,
      hold: true,
      seed: true,
      acl: true
    });
  });

  it('reads every parameter of spec 8.6 and the extras', () => {
    const scenario = parseScenario(
      '?scenario=stopping&platform=linux&shaded=1&inactive=1&balloons=1&view=icons&pane=0&tab=ports' +
        '&select=192.168.1.31&fail=open,wake&update=1&accent=ffc600&speed=4&hold=0&seed=0&acl=0',
      'linux'
    );

    expect(scenario).toMatchObject({
      name: 'stopping',
      shaded: true,
      inactive: true,
      balloons: true,
      view: 'icons',
      pane: false,
      tab: 'ports',
      select: '192.168.1.31',
      update: true,
      accent: '#FFC600',
      speed: 4,
      hold: false,
      seed: false,
      acl: false
    });
    expect([...scenario.fail]).toEqual(['open', 'wake']);
  });

  it('runs the rescan instantly and deep-scans the printer by default', () => {
    expect(parseScenario('?scenario=rescanned', 'mac').speed).toBe(0);
    expect(parseScenario('?scenario=deep-scan', 'mac').select).toBe('192.168.1.31');
  });

  it('reports unknown values and falls back to the defaults', () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});

    const scenario = parseScenario('?scenario=idel&view=grid&fail=everything&speed=-1&shaded=yes', 'mac');

    expect(scenario).toMatchObject({ name: 'idle', view: null, speed: 1, shaded: false });
    expect(scenario.fail.size).toBe(0);
    expect(error).toHaveBeenCalledOnce();
    expect(error.mock.calls[0][0]).toContain('scenario=idel');
    expect(error.mock.calls[0][0]).toContain('view=grid');
  });
});

describe('capability check', () => {
  it('expands core:default and explicit grants, minus denials', () => {
    const allowed = allowedPluginCommands([
      'core:default',
      'core:window:allow-set-size',
      'core:window:deny-inner-position',
      { identifier: 'core:window:allow-start-resize-dragging' }
    ]);

    expect(allowed.has('plugin:window|inner_size')).toBe(true);
    expect(allowed.has('plugin:window|set_size')).toBe(true);
    expect(allowed.has('plugin:window|start_resize_dragging')).toBe(true);
    expect(allowed.has('plugin:window|inner_position')).toBe(false);
    expect(allowed.has('plugin:window|set_min_size')).toBe(false);
    expect(allowed.has('plugin:menu|set_as_help_menu_for_nsapp')).toBe(true);
    expect(allowed.has('plugin:app|version')).toBe(true);
  });

  it('refuses a plugin command the window capability does not grant, as Tauri does', async () => {
    const { backend } = setup();

    await expect(backend.handle('plugin:window|set_fullscreen', { value: true })).rejects.toBe(
      'core:window.set_fullscreen not allowed. Permissions associated with this command: core:window:allow-set-fullscreen'
    );
    await expect(backend.handle('plugin:window|inner_size', { label: 'main' })).resolves.toEqual({ width: 2400, height: 1520 });
  });

  it('can be switched off', async () => {
    const { backend } = setup('?acl=0');

    await expect(backend.handle('plugin:window|set_fullscreen', { value: true })).resolves.toBeNull();
  });
});

describe('app commands (inventory 4)', () => {
  it('lists the interfaces, or none', async () => {
    await expect(setup().backend.handle('get_network_interfaces')).resolves.toEqual(interfacesFor('mac'));
    await expect(setup('', 'linux').backend.handle('get_network_interfaces')).resolves.toEqual(interfacesFor('linux'));
    await expect(setup('?scenario=no-interfaces').backend.handle('get_network_interfaces')).resolves.toEqual([]);
    await expect(setup('?scenario=error&error=init').backend.handle('get_network_interfaces')).rejects.toBe(
      'Failed to list network interfaces'
    );
  });

  it('returns the stored scan per scenario, and never answers while loading', async () => {
    const idle = (await setup('?speed=0').backend.handle('get_scan_results')) as ScanResult;
    expect(idle.hosts.map((host) => host.ip)).toEqual(HOME_HOSTS.filter((host) => host.inLastScan).map((host) => host.ip));

    await expect(setup('?scenario=first-run&speed=0').backend.handle('get_scan_results')).resolves.toBeNull();
    const empty = (await setup('?scenario=empty&speed=0').backend.handle('get_scan_results')) as ScanResult;
    expect(empty.hosts).toEqual([]);
    const many = (await setup('?scenario=many&speed=0').backend.handle('get_scan_results')) as ScanResult;
    expect(many.hosts).toHaveLength(1500);
    expect(many.options.subnet).toBe('10.20.0.0/16');

    let settled = false;
    void setup('?scenario=loading').backend.handle('get_scan_results').then(() => (settled = true));
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(settled).toBe(false);
  });

  it('gives macOS an accent and Linux no colors', async () => {
    await expect(setup('?accent=ffc600').backend.handle('get_system_colors')).resolves.toEqual({
      accent_color: '#FFC600',
      accent_text_color: '#FFFFFF',
      highlight_color: '#FFC600',
      highlight_text_color: '#FFFFFF'
    });
    await expect(setup('', 'linux').backend.handle('get_system_colors')).resolves.toEqual({
      accent_color: null,
      accent_text_color: null,
      highlight_color: null,
      highlight_text_color: null
    });
  });

  it('opens only allowed schemes, and can fail', async () => {
    const info = vi.spyOn(console, 'info').mockImplementation(() => {});
    const { backend } = setup();

    await expect(backend.handle('open_external_url', { url: 'http://192.168.1.31' })).resolves.toBeNull();
    await expect(backend.handle('open_external_url', { url: 'file:///etc/passwd' })).rejects.toBe('Unsupported URL scheme');
    await expect(backend.handle('open_release_url', { url: 'https://github.com/L-K-M/Lantenna' })).resolves.toBeNull();
    await expect(backend.handle('open_release_url', { url: 'smb://nas' })).rejects.toBe('Only http(s) URLs may be opened');
    expect(backend.opened).toEqual(['http://192.168.1.31', 'https://github.com/L-K-M/Lantenna']);
    expect(info).toHaveBeenCalledTimes(2);

    await expect(setup('?fail=open').backend.handle('open_external_url', { url: 'ssh://192.168.1.1' })).rejects.toContain(
      'xdg-open'
    );
  });

  it('wakes a valid MAC address, and can fail', async () => {
    await expect(setup('?speed=0').backend.handle('wake_host', { mac: '58:FD:B1:3C:77:0E' })).resolves.toBeNull();
    await expect(setup('?speed=0').backend.handle('wake_host', { mac: 'nope' })).rejects.toBe("Invalid MAC address 'nope'");
    await expect(setup('?speed=0&fail=wake').backend.handle('wake_host', { mac: '58-FD-B1-3C-77-0E' })).rejects.toBe(
      'Failed to enable UDP broadcast'
    );
  });

  it('reports no update, an update, or a failed check', async () => {
    await expect(setup('?speed=0').backend.handle('check_self_update')).resolves.toBeNull();
    await expect(setup('?speed=0&update=1').backend.handle('check_self_update')).resolves.toMatchObject({ version: '1.1.0' });
    await expect(setup('?speed=0&fail=update').backend.handle('check_self_update')).rejects.toContain('HTTP 503');
  });

  it('reports the window active unless told otherwise', async () => {
    await expect(setup().backend.handle('is_window_active')).resolves.toBe(true);
    await expect(setup('?inactive=1').backend.handle('is_window_active')).resolves.toBe(false);
  });

  it('refuses commands the backend does not register', async () => {
    await expect(setup().backend.handle('get_everything')).rejects.toBe('command get_everything not found');
  });

  it('records every call with its JSON arguments', async () => {
    const { backend } = setup();
    await backend.handle('is_window_active');
    await backend.handle('open_external_url', { url: 'bogus' }).catch(() => {});

    expect(backend.calls().map((call) => call.cmd)).toEqual(['is_window_active', 'open_external_url']);
    expect(backend.calls('open')[0].args).toEqual({ url: 'bogus' });
  });
});

describe('window plugin', () => {
  it('reports sizes and positions in physical pixels', async () => {
    const { backend } = setup();

    await expect(backend.handle('plugin:window|scale_factor', { label: 'main' })).resolves.toBe(2);
    await expect(backend.handle('plugin:window|outer_size', { label: 'main' })).resolves.toEqual({ width: 2400, height: 1520 });
    const monitor = (await backend.handle('plugin:window|current_monitor')) as { workArea: { size: { width: number } } };
    expect(monitor.workArea.size.width).toBe(1512 * 2);
    const position = (await backend.handle('plugin:window|outer_position', { label: 'main' })) as { x: number; y: number };
    expect(position.y).toBeGreaterThanOrEqual(38 * 2);
  });

  it('resizes, clamps to the minimum size and reports the resize', async () => {
    const { backend, of } = setup('?acl=0');

    await backend.handle('plugin:window|set_size', { label: 'main', value: { Logical: { width: 1200, height: 23 } } });
    expect(backend.windowSize()).toEqual({ width: 1200, height: 560 });

    await backend.handle('plugin:window|set_min_size', { label: 'main', value: null });
    await backend.handle('plugin:window|set_size', { label: 'main', value: { Logical: { width: 1200, height: 23 } } });
    expect(backend.windowSize()).toEqual({ width: 1200, height: 23 });
    await expect(backend.handle('plugin:window|inner_size', { label: 'main' })).resolves.toEqual({ width: 2400, height: 46 });

    await backend.handle('plugin:window|set_size', { label: 'main', value: { Physical: { width: 2000, height: 1400 } } });
    expect(backend.windowSize()).toEqual({ width: 1000, height: 700 });
    expect(of<{ width: number; height: number }>('tauri://resize')).toEqual([
      { width: 2400, height: 1120 },
      { width: 2400, height: 46 },
      { width: 2000, height: 1400 }
    ]);
  });

  it('moves the window and reports the move', async () => {
    const { backend, of } = setup('?acl=0');

    await backend.handle('plugin:window|set_position', { label: 'main', value: { Logical: { x: 10, y: 50 } } });

    expect(of('tauri://move')).toEqual([{ x: 20, y: 100 }]);
  });

  it('refuses a resize drag on macOS only, as tao does', async () => {
    await expect(
      setup('?acl=0', 'mac').backend.handle('plugin:window|start_resize_dragging', { label: 'main', value: 'SouthEast' })
    ).rejects.toContain('not supported');
    await expect(
      setup('?acl=0', 'linux').backend.handle('plugin:window|start_resize_dragging', { label: 'main', value: 'SouthEast' })
    ).resolves.toBeNull();
  });

  it('closes the window and reports activity changes', async () => {
    vi.spyOn(console, 'info').mockImplementation(() => {});
    const { backend, of } = setup();

    await backend.handle('plugin:window|close', { label: 'main' });
    backend.setActive(false);

    expect(backend.isClosed()).toBe(true);
    expect(of('window-activity-changed')).toEqual([false]);
    await expect(backend.handle('is_window_active')).resolves.toBe(false);
  });
});

describe('menu plugin, through @tauri-apps/api/menu', () => {
  let backend: MockBackend;

  beforeEach(() => {
    backend = setup().backend;
    mockWindows('main');
    mockIPC((cmd, args) => backend.handle(cmd, args), { shouldMockEvents: true });
  });

  afterEach(() => clearMocks());

  it('records the tree the page builds and fires item actions like muda', async () => {
    const scanAction = vi.fn();
    const fastAction = vi.fn();
    const helpAction = vi.fn();
    const scan = await MenuItem.new({ id: 'scan', text: 'Scan Network', accelerator: 'CmdOrCtrl+R', action: scanAction });
    const fast = await CheckMenuItem.new({ id: 'fast', text: 'Fast', checked: false, action: fastAction });
    const scanMenu = await Submenu.new({ text: 'Scan', items: [scan, await PredefinedMenuItem.new({ item: 'Separator' }), fast] });
    const helpMenu = await Submenu.new({ text: 'Help', items: [{ id: 'help', text: 'Lantenna Help', action: helpAction }] });
    const appMenu = await Submenu.new({
      text: 'Lantenna',
      items: [await PredefinedMenuItem.new({ item: 'Services' }), await PredefinedMenuItem.new({ item: 'Quit' })]
    });
    const menu = await Menu.new({ items: [appMenu, scanMenu, helpMenu] });

    expect(backend.menuTree()).toBeNull();
    await menu.setAsAppMenu();
    await helpMenu.setAsHelpMenuForNSApp();

    expect(backend.menuTree()).toEqual([
      {
        kind: 'Submenu',
        text: 'Lantenna',
        enabled: true,
        items: [
          { kind: 'Predefined', text: 'Services', enabled: true, predefined: 'Services' },
          { kind: 'Predefined', text: 'Quit Lantenna', enabled: true, predefined: 'Quit' }
        ]
      },
      {
        kind: 'Submenu',
        text: 'Scan',
        enabled: true,
        items: [
          { kind: 'MenuItem', text: 'Scan Network', enabled: true, accelerator: 'CmdOrCtrl+R' },
          { kind: 'Predefined', text: '', enabled: true, predefined: 'Separator' },
          { kind: 'Check', text: 'Fast', enabled: true, checked: false }
        ]
      },
      { kind: 'Submenu', text: 'Help', enabled: true, help: true, items: [{ kind: 'MenuItem', text: 'Lantenna Help', enabled: true }] }
    ]);

    await scan.setText('Stop Scan');
    await scan.setAccelerator('CmdOrCtrl+.');
    await scan.setEnabled(false);
    expect(backend.clickMenu(['Scan', 'Stop Scan'])).toBe(false);
    await scan.setEnabled(true);
    expect(backend.clickMenu(['Scan', 'Stop Scan'])).toBe(true);
    expect(scanAction).toHaveBeenCalledWith('scan');

    expect(backend.clickMenu(['Scan', 'Fast'])).toBe(true);
    expect(fastAction).toHaveBeenCalledWith('fast');
    await expect(fast.isChecked()).resolves.toBe(true);
    await fast.setChecked(false);

    expect(backend.clickMenu(['Help', 'Lantenna Help'])).toBe(true);
    expect(helpAction).toHaveBeenCalledWith('help');
    expect(backend.clickMenu(['View', 'as Icons'])).toBe(false);

    const scanTree = backend.menuTree()![1].items!;
    expect(scanTree[0]).toMatchObject({ text: 'Stop Scan', accelerator: 'CmdOrCtrl+.', enabled: true });
    expect(scanTree[2]).toMatchObject({ checked: false });
  });

  it('edits submenus in place (items, insert, remove, get)', async () => {
    const one = await MenuItem.new({ id: 'one', text: 'One' });
    const two = await MenuItem.new({ id: 'two', text: 'Two' });
    const favorites = await Submenu.new({ text: 'Favorites', items: [one] });

    await favorites.append(two);
    await favorites.insert(await MenuItem.new({ id: 'zero', text: 'Zero' }), 0);
    expect((await favorites.items()).map((item) => item.id)).toEqual(['zero', 'one', 'two']);

    const removed = await favorites.removeAt(0);
    expect(removed?.id).toBe('zero');
    await favorites.remove(one);
    expect((await favorites.items()).map((item) => item.id)).toEqual(['two']);
    expect((await favorites.get('two'))?.id).toBe('two');
    await expect(favorites.get('one')).resolves.toBeNull();
    await expect(two.text()).resolves.toBe('Two');
    await two.close();
  });
});

describe('scripted network scan', () => {
  it('sends every phase in order and finishes with the enriched hosts', async () => {
    const { backend, sent, of } = setup('?speed=0');

    await expect(backend.handle('start_scan', { options: balanced() })).resolves.toBeNull();
    await expect(backend.handle('start_scan', { options: balanced() })).rejects.toBe('A scan is already running');
    await scanUntilDone(sent);

    const progress = of<ScanProgress>('scan-progress');
    const phases = progress.map((item) => item.phase).filter((phase, i, all) => phase !== all[i - 1]);
    expect(phases).toEqual(['discovery', 'ping', 'ports', 'fingerprint']);
    expect(progress[0]).toEqual({ phase: 'discovery', scanned: 0, total: 253, found: 0, running: true, current_ip: null });
    expect(progress.filter((item) => item.phase === 'discovery').at(-1)).toMatchObject({ scanned: 253, running: true });
    expect(progress.every((item, i) => i === 0 || item.phase !== progress[i - 1].phase || item.scanned >= progress[i - 1].scanned)).toBe(
      true
    );

    // Found hosts arrive unfingerprinted, discovery ports only.
    const firstPing = sent.findIndex((item) => item.event === 'scan-progress' && (item.payload as ScanProgress).phase === 'ping');
    const discovered = sent.slice(0, firstPing).filter((item) => item.event === 'host-found').map((item) => item.payload as Host);
    expect(discovered.length).toBeGreaterThan(15);
    expect(discovered.every((host) => host.fingerprint === null)).toBe(true);
    expect(discovered.every((host) => host.open_ports.every((port) => [22, 80, 443, 445, 62078].includes(port.port)))).toBe(true);

    const [result] = of<ScanResult>('scan-complete');
    const awake = HOME_HOSTS.filter((host) => host.awake).map((host) => host.ip);
    expect(result.cancelled).toBe(false);
    expect(result.hosts.map((host) => host.ip)).toEqual(awake);
    expect(result.hosts.every((host) => host.fingerprint !== null)).toBe(true);
    expect(result.options.subnet).toBe('192.168.1.0/24');
    expect(of('host-found').map((host) => (host as Host).ip)).toEqual(expect.arrayContaining(awake));
    await expect(backend.handle('get_scan_results')).resolves.toEqual(result);
  });

  it('skips the ping phase in a Fast (TCP) scan and misses ping-only hosts', async () => {
    const { backend, sent, of } = setup('?speed=0');

    await backend.handle('start_scan', { options: { ...balanced(), port_profile: 'quick', discovery_mode: 'tcp' } });
    await scanUntilDone(sent);

    expect(of<ScanProgress>('scan-progress').some((item) => item.phase === 'ping')).toBe(false);
    expect(of<ScanResult>('scan-complete')[0].hosts.map((host) => host.ip)).not.toContain('192.168.1.82');
  });

  it('holds mid-discovery, then stops, fingerprints what it found and reports a cancelled scan', async () => {
    const { backend, sent, of } = setup('?scenario=scanning&speed=0');

    await backend.handle('start_scan', { options: balanced() });
    await backend.holdPoint();
    expect(of<ScanProgress>('scan-progress').at(-1)).toMatchObject({ phase: 'discovery', scanned: 112, total: 253, running: true });

    await backend.handle('cancel_scan');
    backend.resume();
    await scanUntilDone(sent);

    const progress = of<ScanProgress>('scan-progress');
    expect(progress.slice(-2)).toMatchObject([
      { phase: 'discovery', running: false },
      { phase: 'fingerprint', scanned: 0, running: false }
    ]);
    const [result] = of<ScanResult>('scan-complete');
    expect(result.cancelled).toBe(true);
    expect(result.hosts.length).toBeGreaterThan(0);
    expect(result.hosts.every((host) => Number(host.ip.split('.')[3]) <= 130)).toBe(true);
  });

  it('holds at "Probing ports: 4 of" for the stopping scenario', async () => {
    const { backend, of } = setup('?scenario=stopping&speed=0');

    await backend.handle('start_scan', { options: balanced() });
    await backend.holdPoint();

    expect(of<ScanProgress>('scan-progress').at(-1)).toMatchObject({ phase: 'ports', scanned: 4, running: true });
  });

  it('holds in the fingerprint phase', async () => {
    const { backend, of } = setup('?scenario=fingerprint&speed=0');

    await backend.handle('start_scan', { options: balanced() });
    await backend.holdPoint();

    expect(of<ScanProgress>('scan-progress').at(-1)).toMatchObject({ phase: 'fingerprint', scanned: 0, total: 28, running: true });
    expect(of('scan-complete')).toEqual([]);
  });

  it('fails mid-discovery with a panic message in the error scenario', async () => {
    const { backend, sent, of } = setup('?scenario=error&speed=0');

    await backend.handle('start_scan', { options: balanced() });
    await scanUntilDone(sent);

    expect(of('scan-error')).toEqual([{ message: PANIC_MESSAGE }]);
    expect(of<ScanProgress>('scan-progress').at(-1)).toMatchObject({ phase: 'discovery', scanned: 40 });
    await expect(backend.handle('start_scan', { options: balanced() })).resolves.toBeNull();
  });

  it('refuses to start in the error=start scenario', async () => {
    await expect(setup('?scenario=error&error=start').backend.handle('start_scan', { options: balanced() })).rejects.toBe(
      'A scan is already running'
    );
  });

  it('reports a missing interface and an empty /32 as the backend does', async () => {
    const missing = setup('?speed=0');
    await missing.backend.handle('start_scan', { options: { ...balanced(), interface_name: 'en9' } });
    await scanUntilDone(missing.sent);
    expect(missing.of('scan-error')).toEqual([{ message: "Interface 'en9' not found" }]);

    const vpn = setup('?speed=0');
    await vpn.backend.handle('start_scan', {
      options: { ...balanced(), interface_name: 'utun4', subnet: '10.8.0.2/32', max_hosts: null }
    });
    await scanUntilDone(vpn.sent);
    expect(vpn.of('scan-error')).toEqual([{ message: 'No target hosts found in subnet 10.8.0.2/32' }]);
  });

  it('samples 4,096 addresses of the /16', async () => {
    const { backend, sent, of } = setup('?speed=0');
    const office = interfacesFor('mac').find((item) => item.cidr === 16)!;

    await backend.handle('start_scan', {
      options: { ...balanced(), interface_name: office.name, subnet: office.subnet, max_hosts: 4096 }
    });
    await scanUntilDone(sent);

    expect(of<ScanProgress>('scan-progress')[0].total).toBe(4096);
    expect(of<ScanResult>('scan-complete')[0].hosts).toHaveLength(1500);
  });
});

describe('scripted deep scan', () => {
  it('streams port progress, then returns the enriched host', async () => {
    const { backend, of } = setup('?speed=0');

    const host = (await backend.handle('scan_host_ports', { ip: '192.168.1.31', profile: 'deep' })) as Host;

    const progress = of<ScanProgress>('host-scan-progress');
    expect(progress[0]).toEqual({ phase: 'ports', scanned: 0, total: 2087, found: 0, running: true, current_ip: '192.168.1.31' });
    expect(progress.at(-2)).toMatchObject({ scanned: 2087, found: 5, running: true });
    expect(progress.at(-1)).toEqual({ phase: 'ports', scanned: 1, total: 1, found: 5, running: false, current_ip: '192.168.1.31' });
    expect(host.open_ports.map((port) => port.port)).toEqual([80, 443, 515, 631, 9100]);
    expect(host.fingerprint?.mac_address).toBe('30:05:5C:12:34:56');
  });

  it('holds at 412 ports in the deep-scan scenario', async () => {
    const { backend, of } = setup('?scenario=deep-scan&speed=0');

    void backend.handle('scan_host_ports', { ip: '192.168.1.31', profile: 'deep' });
    await backend.holdPoint();

    expect(of<ScanProgress>('host-scan-progress').at(-1)).toMatchObject({ scanned: 412, total: 2087, found: 1, running: true });
  });

  it('finds nothing on a sleeping host but keeps what ARP knows', async () => {
    const host = (await setup('?speed=0').backend.handle('scan_host_ports', { ip: '192.168.1.61', profile: 'deep' })) as Host;

    expect(host.reachable).toBe(false);
    expect(host.open_ports).toEqual([]);
    expect(host.fingerprint?.mac_address).toBe('58:FD:B1:3C:77:0E');
  });

  it('refuses a bad address and can fail', async () => {
    await expect(setup('?speed=0').backend.handle('scan_host_ports', { ip: '999.1.1.1', profile: 'deep' })).rejects.toBe(
      "Invalid IPv4 address '999.1.1.1'"
    );

    const failing = setup('?speed=0&fail=deep');
    await expect(failing.backend.handle('scan_host_ports', { ip: '192.168.1.31', profile: 'deep' })).rejects.toBe(
      'Too many open files (os error 24)'
    );
    expect(failing.of<ScanProgress>('host-scan-progress').at(-1)).toMatchObject({ running: false });
  });
});

describe('seeding', () => {
  const iface = home();

  it('writes what scanStore reads and forgets the update throttle', () => {
    localStorage.setItem('updateChecker.lastCheck', String(NOW));
    localStorage.setItem('updateChecker.skippedVersion', '1.1.0');

    seedStorage(localStorage, userData('regular', NOW), iface);

    expect(JSON.parse(localStorage.getItem('lantenna.favoriteIps')!)).toEqual(['192.168.1.10', '192.168.1.31', '192.168.1.61']);
    expect(JSON.parse(localStorage.getItem('lantenna.favoriteHosts')!)['192.168.1.61'].fingerprint.mac_address).toBe(
      '58:FD:B1:3C:77:0E'
    );
    expect(JSON.parse(localStorage.getItem('lantenna.hiddenIps')!)).toEqual(['192.168.1.101', '192.168.1.120']);
    expect(JSON.parse(localStorage.getItem('lantenna.customNames')!)['192.168.1.31']).toBe('Office Printer');
    expect(localStorage.getItem('lantenna.selectedInterface')).toBe('en0|192.168.1.23');
    expect(localStorage.getItem('updateChecker.lastCheck')).toBeNull();
    expect(localStorage.getItem('updateChecker.skippedVersion')).toBeNull();

    seedStorage(localStorage, userData('fresh', NOW), null);
    expect(localStorage.getItem('lantenna.selectedInterface')).toBeNull();
    expect(localStorage.getItem('lantenna.favoriteIps')).toBe('[]');
  });

  it('tells whether scanStore read the seed', () => {
    const data = userData('regular', NOW);
    const state = {
      favoriteIps: [...data.favoriteIps],
      hiddenIps: [...data.hiddenIps],
      customNames: { ...data.customNames },
      selectedInterface: 'en0|192.168.1.23'
    };

    expect(storeMatchesSeed(state, data, iface)).toBe(true);
    expect(storeMatchesSeed({ ...state, favoriteIps: [] }, data, iface)).toBe(false);
    expect(storeMatchesSeed({ ...state, customNames: {} }, data, iface)).toBe(false);
    expect(storeMatchesSeed({ ...state, selectedInterface: 'en7|10.20.4.17' }, data, iface)).toBe(false);
    expect(storeMatchesSeed({ ...state, selectedInterface: 'en7|10.20.4.17' }, data, null)).toBe(true);
  });
});
