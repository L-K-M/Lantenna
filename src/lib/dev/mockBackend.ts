// Owner: unit G (spec 8.4). Spec: 8.6 (visual verification plan).
//
// A pretend Tauri backend for `vite dev --mode mock` (+layout.ts imports
// this module in that mode only; production builds never contain it).
// It calls mockWindows('main') and mockIPC(handler, { shouldMockEvents:
// true }) from @tauri-apps/api/mocks, then answers every command the app
// invokes: Lantenna's own (inventory 4) from fixtures.ts, and Tauri's
// window, menu, app and resources plugins, checked against the window
// capability in src-tauri/capabilities/default.json as real Tauri would.
// start_scan plays a scripted scan through every phase with the events a
// real one sends (scan-progress, host-found, scan-complete, scan-error);
// scan_host_ports sends host-scan-progress. The native menu is recorded,
// not drawn: window.__lantennaMock.menuTree() dumps it, clickMenu() fires
// an item.
//
// A scenario is chosen with query parameters (spec 8.6, plus extras;
// the whole list is in parseScenario and in scaffold-notes.md, "Mock
// backend (unit G)"). The mock seeds the user data scanStore reads at
// launch (favorites, snapshots, hidden hosts, custom names, interface)
// before scanStore loads, applies the view parameters through the `ui`
// setters, and then acts like the user to reach the scenario's picture
// (starts a scan and holds it mid-discovery, cancels it, and so on).
// window.__lantennaMock.ready turns true when that picture is on screen.

import { mockIPC, mockWindows } from '@tauri-apps/api/mocks';
import { emit } from '@tauri-apps/api/event';
import { get, type Readable } from 'svelte/store';

import capability from '../../../src-tauri/capabilities/default.json';
import tauriConf from '../../../src-tauri/tauri.conf.json';
import { platform as pagePlatform, type Platform } from '$lib/app/platform';
import { ui, type InfoTab } from '$lib/app/ui';
import { hostedWindow } from '$lib/app/views';
import type {
  Host,
  HostViewMode,
  NetworkInterface,
  PortProfile,
  ScanOptions,
  ScanProgress,
  ScanResult
} from '$lib/types';
import {
  DISCOVERY_PORTS,
  HOME_HOSTS,
  HOME_SUBNET,
  MAC_ACCENT,
  OFFICE_SUBNET,
  UPDATE_INFO,
  buildScanTargets,
  interfaceKeyOf,
  interfacesFor,
  ipToNumber,
  manyHosts,
  networkFor,
  openPorts,
  portsForProfile,
  reportedHost,
  storedScan,
  userData,
  type NetworkHost,
  type SeededUserData
} from './fixtures';

// ---------------------------------------------------------------------
// Scenarios

export const SCENARIOS = [
  // Spec 8.6.
  'idle',
  'first-run',
  'loading',
  'scanning',
  'fingerprint',
  'stopping',
  'error',
  'no-interfaces',
  'empty',
  'many',
  // Extras: idle after a finished rescan (New hosts), and a deep scan
  // held mid-way (header row 9, the host status line).
  'rescanned',
  'deep-scan'
] as const;
export type ScenarioName = (typeof SCENARIOS)[number];

/** Actions the mock can be told to fail (`&fail=open,wake`). */
export const FAILURES = ['open', 'wake', 'deep', 'cancel', 'update'] as const;
export type Failure = (typeof FAILURES)[number];

/** Which step fails in the error scenario (`&error=`). */
export type ErrorStep = 'init' | 'start' | 'scan';

export interface Scenario {
  readonly name: ScenarioName;
  readonly platform: Platform;
  /** Collapse the window once the page is up. */
  readonly shaded: boolean;
  /** Report the window inactive at launch. */
  readonly inactive: boolean;
  /** Balloon Help, the view, the pane and its tab: null keeps the
   * remembered setting. */
  readonly balloons: boolean | null;
  readonly view: HostViewMode | null;
  readonly pane: boolean | null;
  readonly tab: InfoTab | null;
  /** Host to select once the store is up. */
  readonly select: string | null;
  readonly error: ErrorStep;
  readonly fail: ReadonlySet<Failure>;
  /** check_self_update offers UPDATE_INFO. */
  readonly update: boolean;
  /** macOS accent color for get_system_colors (#RRGGBB). */
  readonly accent: string;
  /** Scripted time runs this many times faster; 0 removes every delay. */
  readonly speed: number;
  /** Hold scripted scans at the scenario's picture (`&hold=0` lets them
   * run to the end). */
  readonly hold: boolean;
  /** Reset the stored user data to the scenario's (`&seed=0` keeps
   * whatever localStorage holds). */
  readonly seed: boolean;
  /** Enforce the window capability on plugin commands (`&acl=0`). */
  readonly acl: boolean;
}

/** Parse the query string; unknown values are reported and replaced by
 * the default, so a typo shows up in the console instead of silently
 * picturing something else. */
export function parseScenario(search: string, platform: Platform): Scenario {
  const params = new URLSearchParams(search);
  const problems: string[] = [];

  const pick = <T extends string>(key: string, allowed: readonly T[], fallback: T): T => {
    const value = params.get(key);
    if (value === null) return fallback;
    if ((allowed as readonly string[]).includes(value)) return value as T;
    problems.push(`${key}=${value} (expected ${allowed.join(', ')})`);
    return fallback;
  };

  const flag = (key: string): boolean | null => {
    const value = params.get(key);
    if (value === null) return null;
    if (value === '1' || value === 'true') return true;
    if (value === '0' || value === 'false') return false;
    problems.push(`${key}=${value} (expected 1 or 0)`);
    return null;
  };

  const fail = new Set<Failure>();
  for (const item of (params.get('fail') ?? '').split(',').filter(Boolean)) {
    if ((FAILURES as readonly string[]).includes(item)) fail.add(item as Failure);
    else problems.push(`fail=${item} (expected ${FAILURES.join(', ')})`);
  }

  const name = pick<ScenarioName>('scenario', SCENARIOS, 'idle');
  // platform.ts reads it; checked here so a typo is reported.
  pick<Platform>('platform', ['mac', 'linux'], platform);

  // "rescanned" is about the picture after the scan, so its scan is
  // instant unless asked otherwise.
  let speed = name === 'rescanned' ? 0 : 1;
  const speedText = params.get('speed');
  if (speedText !== null) {
    const parsed = Number(speedText);
    if (Number.isFinite(parsed) && parsed >= 0) speed = parsed;
    else problems.push(`speed=${speedText} (expected a number >= 0)`);
  }

  let accent = MAC_ACCENT;
  const accentText = params.get('accent');
  if (accentText !== null) {
    if (/^#?[0-9a-f]{6}$/i.test(accentText)) accent = `#${accentText.replace('#', '').toUpperCase()}`;
    else problems.push(`accent=${accentText} (expected RRGGBB)`);
  }

  const select = params.get('select');
  const view = pick<HostViewMode | ''>('view', ['list', 'icons'], '');
  const tab = pick<InfoTab | ''>('tab', ['general', 'ports', 'fingerprint'], '');

  const scenario: Scenario = {
    name,
    platform,
    shaded: flag('shaded') ?? false,
    inactive: flag('inactive') ?? false,
    balloons: flag('balloons'),
    view: view === '' ? null : view,
    pane: flag('pane'),
    tab: tab === '' ? null : tab,
    select: select ?? (name === 'deep-scan' ? '192.168.1.31' : null),
    error: pick<ErrorStep>('error', ['init', 'start', 'scan'], 'scan'),
    fail,
    update: flag('update') ?? false,
    accent,
    speed,
    hold: flag('hold') ?? true,
    seed: flag('seed') ?? true,
    acl: flag('acl') ?? true
  };

  if (problems.length > 0) {
    console.error(`Lantenna mock: ignored query parameters: ${problems.join('; ')}.`);
  }

  return scenario;
}

// ---------------------------------------------------------------------
// Permissions (Tauri 2.10.3 core default sets, permissions/*/autogenerated)

const CORE_DEFAULTS: Readonly<Record<string, readonly string[]>> = {
  app: ['version', 'name', 'tauri_version', 'identifier', 'bundle_type', 'register_listener', 'remove_listener'],
  event: ['listen', 'unlisten', 'emit', 'emit_to'],
  menu: [
    'new',
    'append',
    'prepend',
    'insert',
    'remove',
    'remove_at',
    'items',
    'get',
    'popup',
    'create_default',
    'set_as_app_menu',
    'set_as_window_menu',
    'text',
    'set_text',
    'is_enabled',
    'set_enabled',
    'set_accelerator',
    'set_as_windows_menu_for_nsapp',
    'set_as_help_menu_for_nsapp',
    'is_checked',
    'set_checked',
    'set_icon'
  ],
  resources: ['close'],
  webview: ['get_all_webviews', 'webview_position', 'webview_size', 'internal_toggle_devtools'],
  window: [
    'get_all_windows',
    'scale_factor',
    'inner_position',
    'outer_position',
    'inner_size',
    'outer_size',
    'is_fullscreen',
    'is_minimized',
    'is_maximized',
    'is_focused',
    'is_decorated',
    'is_resizable',
    'is_maximizable',
    'is_minimizable',
    'is_closable',
    'is_visible',
    'is_enabled',
    'title',
    'current_monitor',
    'primary_monitor',
    'monitor_from_point',
    'available_monitors',
    'cursor_position',
    'theme',
    'is_always_on_top',
    'internal_toggle_maximize'
  ]
};

/** The plugin commands a capability's permission list allows, as
 * `plugin:<plugin>|<command>`. */
export function allowedPluginCommands(permissions: readonly unknown[]): Set<string> {
  const allowed = new Set<string>();
  const denied = new Set<string>();
  const addDefaults = (plugin: string) => {
    for (const command of CORE_DEFAULTS[plugin] ?? []) allowed.add(`plugin:${plugin}|${command}`);
  };

  for (const entry of permissions) {
    const id = typeof entry === 'string' ? entry : (entry as { identifier?: unknown }).identifier;
    if (typeof id !== 'string') continue;

    if (id === 'core:default') {
      for (const plugin of Object.keys(CORE_DEFAULTS)) addDefaults(plugin);
      continue;
    }

    const match = /^core:([a-z]+):(default|allow-([a-z-]+)|deny-([a-z-]+))$/.exec(id);
    if (!match) continue;
    const [, plugin, , allow, deny] = match;
    if (allow) allowed.add(`plugin:${plugin}|${allow.replaceAll('-', '_')}`);
    else if (deny) denied.add(`plugin:${plugin}|${deny.replaceAll('-', '_')}`);
    else addDefaults(plugin);
  }

  for (const command of denied) allowed.delete(command);
  return allowed;
}

/** Tauri's Error::BadResourceId. */
function badResourceId(rid: unknown): string {
  return `The resource id ${String(rid)} is invalid.`;
}

function permissionError(cmd: string): string {
  const [plugin, command] = cmd.slice('plugin:'.length).split('|');
  return (
    `core:${plugin}.${command} not allowed. Permissions associated with this command: ` +
    `core:${plugin}:allow-${command.replaceAll('_', '-')}`
  );
}

// ---------------------------------------------------------------------
// The backend

export interface RecordedCall {
  readonly cmd: string;
  readonly args: unknown;
  readonly at: number;
}

/** A native menu, submenu or item created through @tauri-apps/api/menu.
 * The page reaches it through resource ids (MockBackend.resources). */
interface NativeMenu {
  readonly id: string;
  readonly kind: 'Menu' | 'Submenu' | 'MenuItem' | 'Check' | 'Predefined' | 'Icon';
  text: string;
  enabled: boolean;
  checked: boolean;
  accelerator: string | null;
  items: NativeMenu[];
  readonly predefined: string | null;
  readonly channel: number | null;
}

/** The recorded native menu, for the harness (spec 8.6 step 5). */
export interface MenuNode {
  readonly kind: NativeMenu['kind'];
  readonly text: string;
  readonly enabled: boolean;
  readonly checked?: boolean;
  readonly accelerator?: string;
  readonly predefined?: string;
  readonly help?: boolean;
  readonly items?: readonly MenuNode[];
}

type HoldPhase = 'discovery' | 'ports' | 'fingerprint' | 'deep';

interface HoldPoint {
  readonly phase: HoldPhase;
  /** Hold once `scanned` reaches this (fingerprint: any). */
  readonly at: number;
}

interface Size {
  width: number;
  height: number;
}

interface Point {
  x: number;
  y: number;
}

export interface MockDeps {
  /** Wall clock in ms. */
  now(): number;
  /** Send a Tauri event to the page's listeners. */
  emit(event: string, payload: unknown): void;
  /** The page's viewport and device pixel ratio at launch. */
  viewport: { width: number; height: number; scale: number };
}

const MAX_RECORDED = 5000;
/** The backend emits at most one progress event per phase every 80 ms. */
const TICK_MS = 80;
/** A realistic panic message: the scan task's panics end up in
 * scan-error as "The scanner stopped unexpectedly: <detail>". */
export const PANIC_MESSAGE = 'The scanner stopped unexpectedly: index out of bounds: the len is 3 but the index is 3';

/** A reply that never comes (MockBackend.halt). */
const NEVER = new Promise<never>(() => {});

/** JSON round trip: what real IPC does to arguments and results. */
function wire<T>(value: T): T {
  return value === undefined ? value : (JSON.parse(JSON.stringify(value)) as T);
}

function channelId(handler: unknown): number | null {
  if (typeof handler === 'string') {
    const match = /^__CHANNEL__:(\d+)$/.exec(handler);
    return match ? Number(match[1]) : null;
  }

  return null;
}

function toLogical(value: unknown, scale: number): { x?: number; y?: number; width?: number; height?: number } {
  const v = value as Record<string, Record<string, number>> | null;
  if (!v) return {};
  if (v.Logical) return v.Logical;
  if (v.Physical) {
    const out: Record<string, number> = {};
    for (const [key, n] of Object.entries(v.Physical)) out[key] = n / scale;
    return out;
  }

  return v as unknown as Record<string, number>;
}

function isIpv4(ip: string): boolean {
  return /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(ip);
}

export class MockBackend {
  readonly scenario: Scenario;
  private readonly deps: MockDeps;
  private readonly allowed: Set<string>;
  private readonly recorded: RecordedCall[] = [];
  readonly opened: string[] = [];

  // Window: logical size and position, as tao keeps them.
  private size: Size;
  private position: Point;
  private minSize: Size | null;
  private readonly scale: number;
  private active: boolean;
  private closed = false;
  private halted = false;

  // Menus. `resources` is the webview's resource table: as in Tauri,
  // items(), get(), remove_at() and set_as_app_menu() add a new entry
  // for an item the page already holds, and closing an entry leaves the
  // item itself in its menus.
  private nextRid = 1;
  private nextMenuId = 1;
  private readonly resources = new Map<number, NativeMenu>();
  private readonly channelIndex = new Map<number, number>();
  private appMenu: NativeMenu | null = null;
  private helpMenu: NativeMenu | null = null;

  // Scans.
  private stored: ScanResult | null | 'never';
  private scanRunning = false;
  private cancelRequested = false;
  private hold: HoldPoint | null = null;
  private releaseHold: (() => void) | null = null;
  private holdWaiters: (() => void)[] = [];
  private holdReached = false;

  constructor(scenario: Scenario, deps: MockDeps) {
    this.scenario = scenario;
    this.deps = deps;
    this.allowed = allowedPluginCommands(capability.permissions);
    this.scale = deps.viewport.scale;
    this.size = { width: deps.viewport.width, height: deps.viewport.height };
    this.minSize = { width: tauriConf.app.windows[0].minWidth, height: tauriConf.app.windows[0].minHeight };
    const work = this.workArea();
    this.position = {
      x: work.x + Math.max(0, Math.round((work.width - this.size.width) / 2)),
      y: work.y + Math.max(0, Math.round((work.height - this.size.height) / 3))
    };
    this.active = !scenario.inactive;
    this.stored = this.initialScan();
    this.hold = scenario.hold ? holdFor(scenario.name) : null;
  }

  /** Every invoke the page made, oldest first (at most 5,000), except
   * the event plugin's: mockIPC answers those itself. */
  calls(prefix = ''): RecordedCall[] {
    return this.recorded.filter((call) => call.cmd.startsWith(prefix));
  }

  /** The interfaces get_network_interfaces reports. */
  interfaces(): NetworkInterface[] {
    return this.scenario.name === 'no-interfaces' ? [] : interfacesFor(this.scenario.platform);
  }

  /** The interface the scenario seeds as selected (null: the store's
   * default pick). */
  seededInterface(): NetworkInterface | null {
    const list = interfacesFor(this.scenario.platform);
    if (this.scenario.name === 'first-run' || this.scenario.name === 'empty') return null;
    return list.find((item) => item.subnet === (this.scenario.name === 'many' ? OFFICE_SUBNET : HOME_SUBNET)) ?? null;
  }

  /** The user data the scenario starts with, its snapshots dated from
   * `at` (ms). */
  userData(at = this.deps.now()): SeededUserData {
    const fresh = this.scenario.name === 'first-run' || this.scenario.name === 'empty';
    return userData(fresh ? 'fresh' : 'regular', at);
  }

  private initialScan(): ScanResult | null | 'never' {
    const now = this.deps.now();
    const home = interfacesFor(this.scenario.platform).find((item) => item.subnet === HOME_SUBNET)!;

    switch (this.scenario.name) {
      case 'loading':
        return 'never';
      case 'first-run':
        return null;
      case 'empty':
        return storedScan(home, [], now);
      case 'many': {
        const office = interfacesFor(this.scenario.platform).find((item) => item.subnet === OFFICE_SUBNET)!;
        return storedScan(office, manyHosts(), now);
      }
      default:
        return storedScan(home, HOME_HOSTS, now);
    }
  }

  // -------------------------------------------------------------------
  // IPC

  /** mockIPC's handler. Arguments and results cross a JSON boundary, as
   * with real IPC. */
  handle(cmd: string, rawArgs?: unknown): Promise<unknown> {
    const args = (wire(rawArgs) ?? {}) as Record<string, unknown>;
    this.recorded.push({ cmd, args, at: this.deps.now() });
    if (this.recorded.length > MAX_RECORDED) this.recorded.shift();

    const reply = cmd.startsWith('plugin:') ? this.pluginReply(cmd, args) : this.command(cmd, args).then(wire);
    return reply.then(
      (value) => (this.halted ? NEVER : value),
      (error: unknown) => (this.halted ? NEVER : Promise.reject(error))
    );
  }

  /** Stop answering: every pending and later command never settles. A
   * page that is about to reload keeps running until the new page
   * commits; halted, its startup (scanStore.init() above all) gets no
   * answers and so persists nothing over the seed. */
  halt(): void {
    this.halted = true;
  }

  private pluginReply(cmd: string, args: Record<string, unknown>): Promise<unknown> {
    if (this.scenario.acl && !this.allowed.has(cmd)) return Promise.reject(permissionError(cmd));
    try {
      return Promise.resolve(wire(this.plugin(cmd, args)));
    } catch (error) {
      return Promise.reject(error);
    }
  }

  private async command(cmd: string, args: Record<string, unknown>): Promise<unknown> {
    const { fail } = this.scenario;

    switch (cmd) {
      case 'get_network_interfaces':
        await this.sleep(40);
        if (this.scenario.name === 'error' && this.scenario.error === 'init') {
          throw 'Failed to list network interfaces';
        }
        return this.interfaces();

      case 'get_scan_results':
        if (this.stored === 'never') return new Promise(() => {});
        await this.sleep(150);
        return this.stored;

      case 'start_scan':
        return this.startScan(args.options as ScanOptions);

      case 'cancel_scan':
        if (fail.has('cancel')) throw 'ipc channel closed';
        if (this.scanRunning) this.cancelRequested = true;
        return null;

      case 'scan_host_ports':
        return this.scanHostPorts(String(args.ip), args.profile as PortProfile);

      case 'open_external_url': {
        const url = String(args.url);
        if (!/^(https?|smb|ssh|ftp|vnc|telnet|rtsp):\/\//i.test(url)) throw 'Unsupported URL scheme';
        if (fail.has('open')) throw 'Launcher "xdg-open" failed with ExitStatus(unix_wait_status(768))';
        this.opened.push(url);
        console.info(`Lantenna mock: would open ${url}`);
        return null;
      }

      case 'get_system_colors':
        return this.scenario.platform === 'mac'
          ? {
              accent_color: this.scenario.accent,
              accent_text_color: '#FFFFFF',
              highlight_color: this.scenario.accent,
              highlight_text_color: '#FFFFFF'
            }
          : { accent_color: null, accent_text_color: null, highlight_color: null, highlight_text_color: null };

      case 'wake_host': {
        const mac = String(args.mac);
        if (!/^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$/i.test(mac)) throw `Invalid MAC address '${mac}'`;
        await this.sleep(250);
        if (fail.has('wake')) throw 'Failed to enable UDP broadcast';
        return null;
      }

      case 'check_self_update':
        await this.sleep(300);
        if (fail.has('update')) throw 'GitHub returned HTTP 503 Service Unavailable';
        return this.scenario.update ? UPDATE_INFO : null;

      case 'open_release_url': {
        const url = String(args.url);
        if (!/^https?:\/\//i.test(url)) throw 'Only http(s) URLs may be opened';
        this.opened.push(url);
        console.info(`Lantenna mock: would open ${url}`);
        return null;
      }

      case 'is_window_active':
        return this.active;
    }

    throw `command ${cmd} not found`;
  }

  private plugin(cmd: string, args: Record<string, unknown>): unknown {
    const [plugin, command] = cmd.slice('plugin:'.length).split('|');
    if (plugin === 'window') return this.windowCommand(command, args);
    if (plugin === 'menu') return this.menuCommand(command, args);
    if (plugin === 'resources' && command === 'close') {
      // Only the table entry goes (ResourceTable::close); the native
      // item stays wherever it is attached.
      if (!this.resources.delete(Number(args.rid))) throw badResourceId(args.rid);
      return null;
    }

    // plugin:event|* never gets here: with shouldMockEvents, mockIPC
    // answers listen, emit and unlisten itself and drops emit_to.

    if (plugin === 'app') {
      // getVersion() and friends read tauri.conf.json, as the real app does.
      if (command === 'version') return tauriConf.version;
      if (command === 'name') return tauriConf.productName;
      if (command === 'identifier') return tauriConf.identifier;
      if (command === 'tauri_version') return '2.10.3';
      return null;
    }

    throw `Lantenna mock: no handler for ${cmd}`;
  }

  // -------------------------------------------------------------------
  // Window

  private workArea(): { x: number; y: number; width: number; height: number } {
    // A 14-inch MacBook Pro (menu bar 38) or a 1080p Linux desktop (top
    // bar 32), logical pixels.
    return this.scenario.platform === 'mac'
      ? { x: 0, y: 38, width: 1512, height: 944 }
      : { x: 0, y: 32, width: 1920, height: 1048 };
  }

  private physical(size: Size): Size {
    return { width: Math.round(size.width * this.scale), height: Math.round(size.height * this.scale) };
  }

  private monitor() {
    const work = this.workArea();
    const s = this.scale;
    return {
      name: this.scenario.platform === 'mac' ? 'Built-in Retina Display' : 'DP-1',
      scaleFactor: s,
      position: { x: 0, y: 0 },
      size: { width: work.width * s, height: (work.y + work.height) * s },
      workArea: {
        position: { x: work.x * s, y: work.y * s },
        size: { width: work.width * s, height: work.height * s }
      }
    };
  }

  /** The window's logical inner size (what the viewport should be). */
  windowSize(): Size {
    return { ...this.size };
  }

  isClosed(): boolean {
    return this.closed;
  }

  private windowCommand(command: string, args: Record<string, unknown>): unknown {
    const s = this.scale;

    switch (command) {
      case 'inner_size':
      case 'outer_size':
        return this.physical(this.size);
      case 'inner_position':
      case 'outer_position':
        return { x: Math.round(this.position.x * s), y: Math.round(this.position.y * s) };
      case 'scale_factor':
        return s;
      case 'current_monitor':
      case 'primary_monitor':
      case 'monitor_from_point':
        return this.monitor();
      case 'available_monitors':
        return [this.monitor()];
      case 'is_focused':
        return this.active;
      case 'is_visible':
      case 'is_resizable':
      case 'is_enabled':
      case 'is_closable':
      case 'is_minimizable':
      case 'is_maximizable':
        return true;
      case 'is_decorated':
      case 'is_fullscreen':
      case 'is_minimized':
      case 'is_maximized':
      case 'is_always_on_top':
        return false;
      case 'title':
        return tauriConf.app.windows[0].title;
      case 'theme':
        return 'light';
      case 'cursor_position':
        return { x: 0, y: 0 };
      case 'get_all_windows':
        return ['main'];

      case 'set_size': {
        const next = toLogical(args.value, s);
        const min = this.minSize ?? { width: 0, height: 0 };
        this.size = {
          width: Math.max(min.width, next.width ?? this.size.width),
          height: Math.max(min.height, next.height ?? this.size.height)
        };
        this.deps.emit('tauri://resize', this.physical(this.size));
        return null;
      }

      case 'set_min_size': {
        const next = args.value === null ? null : toLogical(args.value, s);
        this.minSize = next ? { width: next.width ?? 0, height: next.height ?? 0 } : null;
        return null;
      }

      case 'set_position': {
        const next = toLogical(args.value, s);
        this.position = { x: next.x ?? this.position.x, y: next.y ?? this.position.y };
        this.deps.emit('tauri://move', { x: Math.round(this.position.x * s), y: Math.round(this.position.y * s) });
        return null;
      }

      case 'start_resize_dragging':
        // tao can't start a resize drag on macOS (spec 2.10).
        if (this.scenario.platform === 'mac') throw 'the requested operation is not supported by Tao';
        return null;

      case 'close':
        this.closed = true;
        console.info('Lantenna mock: the window closed (the app would quit)');
        return null;

      default:
        // Setters without an observable effect here (start_dragging,
        // set_focus, set_title, ...): recorded only.
        if (/^(set_|start_|request_|center|show|hide|minimize|unminimize|maximize|unmaximize|toggle_maximize|destroy|internal_)/.test(command)) {
          return null;
        }

        throw `Lantenna mock: no handler for plugin:window|${command}`;
    }
  }

  /** Report the window active or not, as the backend's activity event
   * does (window-activity-changed). */
  setActive(active: boolean): void {
    this.active = active;
    this.deps.emit('window-activity-changed', active);
  }

  // -------------------------------------------------------------------
  // Menus (@tauri-apps/api/menu), recorded, not drawn

  private createMenu(kind: NativeMenu['kind'], options: Record<string, unknown>, handler: unknown): NativeMenu {
    const predefined = kind === 'Predefined' ? predefinedName(options.item) : null;
    const menu: NativeMenu = {
      id: typeof options.id === 'string' ? options.id : `mock-${this.nextMenuId++}`,
      kind,
      text: typeof options.text === 'string' ? options.text : predefinedText(predefined),
      enabled: options.enabled !== false,
      checked: options.checked === true,
      accelerator: typeof options.accelerator === 'string' ? options.accelerator : null,
      items: [],
      predefined,
      channel: channelId(handler ?? options.handler)
    };

    if (Array.isArray(options.items)) {
      menu.items = options.items.map((item) => this.menuItem(item));
    }

    return menu;
  }

  /** A new resource-table entry for `menu`. */
  private addResource(menu: NativeMenu): number {
    const rid = this.nextRid++;
    this.resources.set(rid, menu);
    return rid;
  }

  /** An `items` entry: [rid, kind] of an existing item, or inline
   * options (Tauri's untagged MenuItemPayloadKind). */
  private menuItem(item: unknown): NativeMenu {
    if (Array.isArray(item)) return this.requireMenu(item[0]);

    const options = item as Record<string, unknown>;
    const kind: NativeMenu['kind'] =
      'item' in options ? 'Predefined' : 'items' in options ? 'Submenu' : 'checked' in options ? 'Check' : 'icon' in options ? 'Icon' : 'MenuItem';
    return this.createMenu(kind, options, options.handler);
  }

  /** What Tauri's make_item_resource! returns: a new rid for `menu`. */
  private menuRef(menu: NativeMenu): [number, string, string] {
    return [this.addResource(menu), menu.id, menu.kind];
  }

  private requireMenu(rid: unknown): NativeMenu {
    const menu = this.resources.get(Number(rid));
    if (!menu) throw badResourceId(rid);
    return menu;
  }

  private menuCommand(command: string, args: Record<string, unknown>): unknown {
    switch (command) {
      case 'new': {
        const menu = this.createMenu(args.kind as NativeMenu['kind'], (args.options as Record<string, unknown>) ?? {}, args.handler);
        return [this.addResource(menu), menu.id];
      }
      case 'create_default': {
        const menu = this.createMenu('Menu', {}, null);
        return [this.addResource(menu), menu.id];
      }
      case 'append':
      case 'prepend':
      case 'insert': {
        const menu = this.requireMenu(args.rid);
        const items = (args.items as unknown[]).map((item) => this.menuItem(item));
        const at = command === 'append' ? menu.items.length : command === 'prepend' ? 0 : Number(args.position);
        menu.items.splice(at, 0, ...items);
        return null;
      }
      case 'remove': {
        const menu = this.requireMenu(args.rid);
        const item = this.requireMenu((args.item as unknown[])[0]);
        menu.items = menu.items.filter((child) => child !== item);
        return null;
      }
      case 'remove_at': {
        const menu = this.requireMenu(args.rid);
        const [item] = menu.items.splice(Number(args.position), 1);
        return item === undefined ? null : this.menuRef(item);
      }
      case 'items':
        return this.requireMenu(args.rid).items.map((item) => this.menuRef(item));
      case 'get': {
        const found = this.requireMenu(args.rid).items.find((item) => item.id === args.id);
        return found === undefined ? null : this.menuRef(found);
      }
      case 'text':
        return this.requireMenu(args.rid).text;
      case 'set_text':
        this.requireMenu(args.rid).text = String(args.text);
        return null;
      case 'is_enabled':
        return this.requireMenu(args.rid).enabled;
      case 'set_enabled':
        this.requireMenu(args.rid).enabled = args.enabled === true;
        return null;
      case 'set_accelerator':
        this.requireMenu(args.rid).accelerator = typeof args.accelerator === 'string' ? args.accelerator : null;
        return null;
      case 'is_checked':
        return this.requireMenu(args.rid).checked;
      case 'set_checked':
        this.requireMenu(args.rid).checked = args.checked === true;
        return null;
      case 'set_as_app_menu':
      case 'set_as_window_menu': {
        const previous = this.appMenu;
        this.appMenu = this.requireMenu(args.rid);
        return previous === null ? null : [this.addResource(previous), previous.id];
      }
      case 'set_as_help_menu_for_nsapp':
        this.helpMenu = this.requireMenu(args.rid);
        return null;
      case 'set_as_windows_menu_for_nsapp':
      case 'set_icon':
      case 'popup':
        return null;
    }

    throw `Lantenna mock: no handler for plugin:menu|${command}`;
  }

  private menuNode(menu: NativeMenu): MenuNode {
    const node: Record<string, unknown> = { kind: menu.kind, text: menu.text, enabled: menu.enabled };
    if (menu.kind === 'Check') node.checked = menu.checked;
    if (menu.accelerator) node.accelerator = menu.accelerator;
    if (menu.predefined) node.predefined = menu.predefined;
    if (menu === this.helpMenu) node.help = true;
    if (menu.kind === 'Menu' || menu.kind === 'Submenu') node.items = menu.items.map((item) => this.menuNode(item));
    return node as unknown as MenuNode;
  }

  /** The app menu's submenus, or null before setAsAppMenu. */
  menuTree(): MenuNode[] | null {
    if (this.appMenu === null) return null;
    return this.menuNode(this.appMenu).items as MenuNode[];
  }

  /** Choose the item at `path` (titles, e.g. ["Scan", "Scan Network"])
   * as muda would: nothing for a dimmed item; a check item toggles
   * itself before the page hears of it. Returns whether it fired. */
  clickMenu(path: readonly string[]): boolean {
    let items = this.appMenu?.items ?? [];
    let target: NativeMenu | null = null;

    for (const title of path) {
      target = items.find((item) => item.text === title) ?? null;
      if (!target) return false;
      items = target.items;
    }

    if (!target || !target.enabled || target.channel === null) return false;
    if (target.kind === 'Check') target.checked = !target.checked;

    const index = this.channelIndex.get(target.channel) ?? 0;
    this.channelIndex.set(target.channel, index + 1);
    const internals = (window as unknown as { __TAURI_INTERNALS__: { runCallback(id: number, data: unknown): void } })
      .__TAURI_INTERNALS__;
    internals.runCallback(target.channel, { index, message: target.id });
    return true;
  }

  // -------------------------------------------------------------------
  // Time and holds

  private sleep(ms: number): Promise<void> {
    const { speed } = this.scenario;
    if (speed === 0) return Promise.resolve();
    return new Promise((resolve) => setTimeout(resolve, ms / speed));
  }

  /** Wait at the scenario's hold point, once (a phase shorter than the
   * hold point holds at its end). */
  private async checkpoint(phase: HoldPhase, scanned: number, total: number): Promise<void> {
    const hold = this.hold;
    if (!hold || hold.phase !== phase || scanned < Math.min(hold.at, total)) return;

    this.hold = null;
    this.settleHold();
    await new Promise<void>((resolve) => {
      this.releaseHold = resolve;
    });
  }

  /** The hold point was reached, or the scan ended without reaching it. */
  private settleHold(): void {
    this.holdReached = true;
    for (const waiter of this.holdWaiters.splice(0)) waiter();
  }

  /** The next count a phase loop may reach: `step` further, but no
   * further than `total` or the hold point. */
  private nextStop(phase: HoldPhase, scanned: number, step: number, total: number): number {
    let next = Math.min(total, scanned + step);
    const hold = this.hold;
    if (hold && hold.phase === phase && hold.at > scanned) next = Math.min(next, hold.at);
    return next;
  }

  /** Resolves when a scripted scan reaches the hold point or ends
   * without reaching it (at once if that happened, or if the scenario
   * has no hold point). */
  holdPoint(): Promise<void> {
    if (this.holdReached || !this.scenario.hold || holdFor(this.scenario.name) === null) return Promise.resolve();
    return new Promise((resolve) => this.holdWaiters.push(resolve));
  }

  /** Let held scans run on. */
  resume(): void {
    this.hold = null;
    const release = this.releaseHold;
    this.releaseHold = null;
    release?.();
  }

  // -------------------------------------------------------------------
  // Scripted network scan (scanner.rs run_scan + commands.rs start_scan)

  private async startScan(options: ScanOptions): Promise<null> {
    if (this.scenario.name === 'error' && this.scenario.error === 'start') throw 'A scan is already running';
    if (this.scanRunning) throw 'A scan is already running';

    this.scanRunning = true;
    this.cancelRequested = false;
    // start_scan returns at once; the scan runs in the background.
    void Promise.resolve().then(() => this.runScan(options));
    return null;
  }

  private progress(event: 'scan-progress' | 'host-scan-progress', progress: ScanProgress): void {
    this.deps.emit(event, progress);
  }

  private async runScan(options: ScanOptions): Promise<void> {
    const startedAt = new Date(this.deps.now()).toISOString();
    const finish = (event: string, payload: unknown) => {
      this.scanRunning = false;
      this.deps.emit(event, payload);
      this.settleHold();
    };

    const iface = interfacesFor(this.scenario.platform).find(
      (item) => item.name === options.interface_name && (!options.subnet || item.subnet === options.subnet)
    );
    if (!iface) return finish('scan-error', { message: `Interface '${options.interface_name}' not found` });

    const subnet = options.subnet ?? iface.subnet;
    const maxHosts = Math.min(4096, Math.max(1, options.max_hosts ?? iface.host_count));
    const targets = buildScanTargets(subnet, iface.ip, maxHosts);
    if (targets.length === 0) return finish('scan-error', { message: `No target hosts found in subnet ${subnet}` });

    const network = new Map<string, NetworkHost>();
    for (const host of networkFor(subnet, this.scenario.platform)) if (host.awake) network.set(host.ip, host);

    const profile = options.port_profile;
    const seenAt = () => new Date(this.deps.now()).toISOString();
    const found = new Map<string, NetworkHost>();
    const answered = new Set<string>();
    // The ports probed on each found host so far: the discovery ports
    // after the sweep, none for a host found through ARP or ping, the
    // profile once the port phase reached it. After a Stop, scan-complete
    // reports only what was probed, as the backend does.
    const probedOn = new Map<string, readonly number[]>();
    const foundQuietly = (host: NetworkHost): Host => ({
      ...reportedHost(host, profile, 'discovery', seenAt()),
      open_ports: []
    });
    const cancelled = () => this.cancelRequested;
    const failDuringDiscovery = this.scenario.name === 'error' && this.scenario.error === 'scan';

    // Phase 1: discovery sweep.
    const total = targets.length;
    const step = Math.max(1, Math.ceil(total / 36));
    this.progress('scan-progress', { phase: 'discovery', scanned: 0, total, found: 0, running: true, current_ip: null });
    let scanned = 0;
    while (scanned < total) {
      await this.sleep(TICK_MS);
      const next = this.nextStop('discovery', scanned, step, total);
      for (const ip of targets.slice(scanned, next)) {
        const host = network.get(ip);
        if (!host || host.via !== 'sweep') continue;
        found.set(ip, host);
        answered.add(ip);
        probedOn.set(ip, DISCOVERY_PORTS);
        this.deps.emit('host-found', reportedHost(host, profile, 'discovery', seenAt()));
      }

      scanned = next;
      const stop = cancelled();
      this.progress('scan-progress', {
        phase: 'discovery',
        scanned,
        total,
        found: found.size,
        running: !stop,
        current_ip: targets[scanned - 1]
      });
      if (stop) break;

      if (failDuringDiscovery && scanned >= Math.min(40, total)) {
        return finish('scan-error', { message: PANIC_MESSAGE });
      }

      await this.checkpoint('discovery', scanned, total);
    }

    const quiet = () => targets.filter((ip) => !found.has(ip));

    // ARP table: hosts that ignored every probe but answered ARP.
    if (!cancelled() && quiet().length > 0) {
      await this.sleep(150);
      for (const ip of quiet()) {
        const host = network.get(ip);
        if (!host || host.via !== 'arp') continue;
        found.set(ip, host);
        probedOn.set(ip, []);
        this.deps.emit('host-found', foundQuietly(host));
      }
    }

    // Ping (hybrid discovery only); replies are reported after the loop.
    if (options.discovery_mode === 'hybrid' && !cancelled() && quiet().length > 0) {
      const pending = quiet();
      const quietTotal = pending.length;
      const before = found.size;
      const pingStep = Math.max(1, Math.ceil(quietTotal / 18));
      const replies: NetworkHost[] = [];
      this.progress('scan-progress', { phase: 'ping', scanned: 0, total: quietTotal, found: before, running: true, current_ip: null });

      let checked = 0;
      while (checked < quietTotal) {
        await this.sleep(TICK_MS);
        const next = Math.min(quietTotal, checked + pingStep);
        for (const ip of pending.slice(checked, next)) {
          const host = network.get(ip);
          if (host && host.via === 'ping') replies.push(host);
        }

        checked = next;
        const stop = cancelled();
        this.progress('scan-progress', {
          phase: 'ping',
          scanned: checked,
          total: quietTotal,
          found: before + replies.length,
          running: !stop,
          current_ip: null
        });
        if (stop) break;
      }

      for (const host of replies) {
        found.set(host.ip, host);
        probedOn.set(host.ip, []);
        this.deps.emit('host-found', foundQuietly(host));
      }
    }

    // Phase 2: the profile's ports on live hosts.
    const live = [...found.values()].sort((a, b) => ipToNumber(a.ip) - ipToNumber(b.ip));
    if (!cancelled() && live.length > 0) {
      const liveTotal = live.length;
      const portStep = Math.max(1, Math.ceil(liveTotal / 25));
      const profilePorts = portsForProfile(profile);
      this.progress('scan-progress', { phase: 'ports', scanned: 0, total: liveTotal, found: liveTotal, running: true, current_ip: null });

      let probed = 0;
      while (probed < liveTotal) {
        await this.sleep(TICK_MS);
        const next = this.nextStop('ports', probed, portStep, liveTotal);
        for (const host of live.slice(probed, next)) {
          probedOn.set(host.ip, profilePorts);
          const probedPorts = answered.has(host.ip)
            ? profilePorts.filter((port) => !DISCOVERY_PORTS.includes(port))
            : profilePorts;
          if (host.ports.some((spec) => probedPorts.includes(spec.port))) {
            this.deps.emit('host-found', reportedHost(host, profile, 'ports', seenAt()));
          }
        }

        probed = next;
        const stop = cancelled();
        this.progress('scan-progress', {
          phase: 'ports',
          scanned: probed,
          total: liveTotal,
          found: liveTotal,
          running: !stop,
          current_ip: live[probed - 1].ip
        });
        if (stop) break;
        await this.checkpoint('ports', probed, liveTotal);
      }
    }

    // Fingerprinting runs even after a cancel; it has no per-host progress.
    const wasCancelled = cancelled();
    this.progress('scan-progress', {
      phase: 'fingerprint',
      scanned: 0,
      total: found.size,
      found: found.size,
      running: !wasCancelled,
      current_ip: null
    });
    await this.checkpoint('fingerprint', 0, 0);
    await this.sleep(1200);

    const completedAt = seenAt();
    const result: ScanResult = {
      started_at: startedAt,
      completed_at: completedAt,
      cancelled: wasCancelled,
      hosts: live.map((host) => ({
        ...reportedHost(host, profile, 'complete', completedAt),
        open_ports: openPorts(host, probedOn.get(host.ip) ?? [])
      })),
      options: { ...options, subnet }
    };
    this.stored = result;
    finish('scan-complete', result);
  }

  // -------------------------------------------------------------------
  // Scripted deep scan (commands.rs scan_host_ports)

  private async scanHostPorts(ip: string, profile: PortProfile): Promise<Host> {
    if (!isIpv4(ip)) throw `Invalid IPv4 address '${ip}'`;

    const known = [
      ...HOME_HOSTS,
      ...networkFor(OFFICE_SUBNET, this.scenario.platform),
      ...vmNetwork(this.scenario.platform)
    ].find((item) => item.ip === ip);
    // An asleep or unknown host answers nothing.
    const host = known?.awake ? known : null;
    const ports = portsForProfile(profile);
    const total = ports.length;
    const open = host ? host.ports.map((spec) => ports.indexOf(spec.port)).filter((i) => i >= 0) : [];
    const emitProgress = (scanned: number) =>
      this.progress('host-scan-progress', {
        phase: 'ports',
        scanned,
        total,
        found: open.filter((i) => i < scanned).length,
        running: true,
        current_ip: ip
      });

    emitProgress(0);
    const step = Math.max(12, Math.ceil(total / 50));
    let scanned = 0;
    while (scanned < total) {
      await this.sleep(TICK_MS);
      scanned = this.nextStop('deep', scanned, step, total);
      emitProgress(scanned);
      await this.checkpoint('deep', scanned, total);
    }

    if (this.scenario.fail.has('deep')) {
      this.progress('host-scan-progress', { phase: 'ports', scanned: 0, total: 1, found: 0, running: false, current_ip: ip });
      throw 'Too many open files (os error 24)';
    }

    await this.sleep(300);
    const seen = new Date(this.deps.now()).toISOString();
    // The backend stamps last_seen even for a host that didn't answer
    // (ANALYSIS BUG-3).
    const result: Host = host
      ? reportedHost(host, profile, 'complete', seen)
      : known
        ? { ...reportedHost(known, profile, 'complete', seen), reachable: false, open_ports: [] }
        : { ip, name: null, reachable: false, open_ports: [], last_seen: seen, fingerprint: null };
    this.progress('host-scan-progress', {
      phase: 'ports',
      scanned: 1,
      total: 1,
      found: result.open_ports.length,
      running: false,
      current_ip: ip
    });
    return result;
  }
}

function vmNetwork(platform: Platform): readonly NetworkHost[] {
  const bridge = interfacesFor(platform).find((item) => item.subnet !== HOME_SUBNET && item.subnet !== OFFICE_SUBNET && item.host_count > 0);
  return bridge ? networkFor(bridge.subnet, platform) : [];
}

/** Where a scenario's scripted scan waits for the screenshot. */
function holdFor(name: ScenarioName): HoldPoint | null {
  switch (name) {
    case 'scanning':
      // Spec 2.2: "Looking for hosts: 112 of 254 addresses" (253 here:
      // the backend never probes this computer's own address).
      return { phase: 'discovery', at: 112 };
    case 'fingerprint':
      return { phase: 'fingerprint', at: 0 };
    case 'stopping':
      // Spec 2.4: "Probing ports: 4 of 11 hosts", then Stop.
      return { phase: 'ports', at: 4 };
    case 'deep-scan':
      // Spec 5.3: "Deep scan: 412 of 2,048 ports".
      return { phase: 'deep', at: 412 };
    default:
      return null;
  }
}

function predefinedName(item: unknown): string {
  if (typeof item === 'string') return item;
  if (item && typeof item === 'object') return Object.keys(item)[0] ?? 'Unknown';
  return 'Unknown';
}

/** muda's default titles for predefined items (app name Lantenna). */
function predefinedText(item: string | null): string {
  switch (item) {
    case null:
    case 'Separator':
      return '';
    case 'SelectAll':
      return 'Select All';
    case 'Hide':
      return `Hide ${tauriConf.productName}`;
    case 'HideOthers':
      return 'Hide Others';
    case 'ShowAll':
      return 'Show All';
    case 'Quit':
      return `Quit ${tauriConf.productName}`;
    case 'CloseWindow':
      return 'Close Window';
    case 'About':
      return `About ${tauriConf.productName}`;
    default:
      return item;
  }
}

// ---------------------------------------------------------------------
// Seeding the user data scanStore reads at launch

const STORAGE_KEYS = {
  favoriteIps: 'lantenna.favoriteIps',
  favoriteHosts: 'lantenna.favoriteHosts',
  hiddenIps: 'lantenna.hiddenIps',
  customNames: 'lantenna.customNames',
  selectedInterface: 'lantenna.selectedInterface',
  lastUpdateCheck: 'updateChecker.lastCheck',
  skippedVersion: 'updateChecker.skippedVersion'
} as const;

/** Write the scenario's user data where scanStore reads it, and forget
 * the update check's throttle and skip so the launch check runs. */
export function seedStorage(storage: Storage, data: SeededUserData, iface: NetworkInterface | null): void {
  storage.setItem(STORAGE_KEYS.favoriteIps, JSON.stringify(data.favoriteIps));
  storage.setItem(STORAGE_KEYS.favoriteHosts, JSON.stringify(data.favoriteHosts));
  storage.setItem(STORAGE_KEYS.hiddenIps, JSON.stringify(data.hiddenIps));
  storage.setItem(STORAGE_KEYS.customNames, JSON.stringify(data.customNames));
  if (iface) storage.setItem(STORAGE_KEYS.selectedInterface, interfaceKeyOf(iface));
  else storage.removeItem(STORAGE_KEYS.selectedInterface);
  storage.removeItem(STORAGE_KEYS.lastUpdateCheck);
  storage.removeItem(STORAGE_KEYS.skippedVersion);
}

interface StoreUserState {
  favoriteIps: readonly string[];
  hiddenIps: readonly string[];
  customNames: Readonly<Record<string, string>>;
  selectedInterface: string | null;
  hosts: readonly Host[];
  staleFavoriteIps: readonly string[];
}

/** JSON with sorted keys, so equal data compares equal whatever order
 * its keys were written in. */
function canonical(value: unknown): string {
  return JSON.stringify(value, (_key, v: unknown) =>
    v && typeof v === 'object' && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
      : v
  );
}

/**
 * Whether scanStore read the seeded data. It reads localStorage when its
 * module loads, and SvelteKit may load the page's modules (scanStore
 * among them) before the layout's load() has imported this module
 * (scaffold notes 4.2). Favorites, hidden hosts and custom names are
 * never changed by init(); the interface only when the stored key is
 * stale, which a seeded key is not. The favorites' snapshots show only
 * as the stale favorites' rows (before init() every favorite is stale),
 * so those rows must be the seeded snapshots.
 */
export function storeMatchesSeed(state: StoreUserState, data: SeededUserData, iface: NetworkInterface | null): boolean {
  const same = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((v, i) => v === b[i]);
  const names = (r: Readonly<Record<string, string>>) =>
    Object.entries(r)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${v}`);
  const snapshotsMatch = state.staleFavoriteIps.every((ip) => {
    const seeded = data.favoriteHosts[ip];
    // The fixtures seed a snapshot for every favorite.
    if (!seeded) return true;
    const row = state.hosts.find((host) => host.ip === ip);
    return row !== undefined && canonical(row) === canonical({ ...seeded, ip });
  });

  return (
    same(state.favoriteIps, data.favoriteIps) &&
    same(state.hiddenIps, data.hiddenIps) &&
    same(names(state.customNames), names(data.customNames)) &&
    (iface === null || state.selectedInterface === interfaceKeyOf(iface)) &&
    snapshotsMatch
  );
}

// ---------------------------------------------------------------------
// Installing it in the page

export interface MockHandle {
  readonly scenario: Scenario;
  /** The scenario's picture is on screen. */
  ready: boolean;
  whenReady(): Promise<void>;
  calls(prefix?: string): RecordedCall[];
  menuTree(): MenuNode[] | null;
  clickMenu(path: readonly string[]): boolean;
  /** The window's logical inner size after the window ops so far. */
  windowSize(): { width: number; height: number };
  setActive(active: boolean): void;
  resume(): void;
  emit(event: string, payload: unknown): void;
  /** URLs open_external_url and open_release_url were asked to open. */
  readonly opened: readonly string[];
  /** The scan store and its progress, once the mock has loaded them
   * (null before). */
  state(): { store: unknown; progress: unknown } | null;
}

declare global {
  interface Window {
    __lantennaMock?: MockHandle;
  }
}

const RELOAD_KEY = 'lantenna.mockReload';

/** Left in sessionStorage for the load after a reload: which page
 * reloaded, and when it seeded, so the new load seeds the same data. */
interface ReloadMark {
  readonly href: string;
  readonly seededAt: number;
}

/** The mark a reload of this very page left, if any; removes it. */
function takeReloadMark(): ReloadMark | null {
  const raw = sessionStorage.getItem(RELOAD_KEY);
  sessionStorage.removeItem(RELOAD_KEY);
  if (raw === null) return null;

  try {
    const mark = JSON.parse(raw) as Partial<ReloadMark>;
    return mark.href === location.href && typeof mark.seededAt === 'number' ? (mark as ReloadMark) : null;
  } catch {
    return null;
  }
}

function nextFrame(): Promise<void> {
  return new Promise((resolve) => requestAnimationFrame(() => resolve()));
}

function waitFor<T>(store: { subscribe(fn: (v: T) => void): () => void }, test: (v: T) => boolean): Promise<T> {
  return new Promise((resolve) => {
    let done = false;
    let stop: (() => void) | null = null;
    stop = store.subscribe((value) => {
      if (done || !test(value)) return;
      done = true;
      resolve(value);
      stop?.();
    });
    if (done) stop();
  });
}

/** Install the mock for `scenario` and drive the page to its picture. */
export function installMockBackend(scenario: Scenario): MockHandle {
  const backend = new MockBackend(scenario, {
    now: () => Date.now(),
    emit: (event, payload) => void emit(event, wire(payload)),
    viewport: { width: window.innerWidth, height: window.innerHeight, scale: window.devicePixelRatio || 1 }
  });

  // Before anything can read it: scanStore reads these at module load.
  // After a reload for the seed (drive), the same data again.
  const reloaded = scenario.seed ? takeReloadMark() : null;
  const seededAt = reloaded?.seededAt ?? Date.now();
  const seed: Seed = {
    iface: backend.seededInterface(),
    data: backend.userData(seededAt),
    at: seededAt,
    reloaded: reloaded !== null
  };
  if (scenario.seed) seedStorage(window.localStorage, seed.data, seed.iface);

  mockWindows('main');
  mockIPC((cmd, args) => backend.handle(cmd, args), { shouldMockEvents: true });

  // ui read its settings when it loaded; apply the parameters through it.
  if (scenario.view !== null) ui.setViewMode(scenario.view);
  if (scenario.pane !== null) ui.setInfoPane(scenario.pane);
  if (scenario.tab !== null) ui.setInfoTab(scenario.tab);
  if (scenario.balloons !== null) ui.setBalloons(scenario.balloons ? 'shown' : 'hidden');

  let stores: { store: Readable<unknown>; progress: Readable<unknown> } | null = null;
  let markReady: () => void = () => {};
  const readyPromise = new Promise<void>((resolve) => {
    markReady = resolve;
  });

  const handle: MockHandle = {
    scenario,
    ready: false,
    whenReady: () => readyPromise,
    calls: (prefix) => backend.calls(prefix),
    menuTree: () => backend.menuTree(),
    clickMenu: (path) => backend.clickMenu(path),
    windowSize: () => backend.windowSize(),
    setActive: (active) => backend.setActive(active),
    resume: () => backend.resume(),
    emit: (event, payload) => void emit(event, wire(payload)),
    opened: backend.opened,
    state: () => (stores ? { store: get(stores.store), progress: get(stores.progress) } : null)
  };
  window.__lantennaMock = handle;

  void import('$lib/util/scanStore').then(({ scanStore, scanProgress }) => {
    stores = { store: scanStore, progress: scanProgress };
  });

  void drive(backend, scenario, seed).then(async (outcome) => {
    if (outcome === 'reloading') return;
    await nextFrame();
    await nextFrame();
    handle.ready = true;
    markReady();
  });

  console.info(
    `Lantenna mock backend: scenario ${scenario.name} on ${scenario.platform}` +
      (scenario.hold && holdFor(scenario.name) ? ' (held; __lantennaMock.resume() lets it run)' : '')
  );
  return handle;
}

/** The user data installMockBackend seeded. */
interface Seed {
  readonly iface: NetworkInterface | null;
  readonly data: SeededUserData;
  /** When the snapshots are dated from (ms). */
  readonly at: number;
  /** This load follows a reload for the seed. */
  readonly reloaded: boolean;
}

/** Act like the user until the scenario's picture is on screen. */
async function drive(backend: MockBackend, scenario: Scenario, seed: Seed): Promise<'ready' | 'reloading'> {
  const { scanStore, scanProgress } = await import('$lib/util/scanStore');

  if (scenario.seed && !storeMatchesSeed(get(scanStore), seed.data, seed.iface)) {
    if (seed.reloaded) {
      console.error(
        'Lantenna mock: scanStore still does not hold the seeded user data after a reload; this picture is not the scenario.'
      );
    } else {
      // scanStore loaded before the seed; the next load reads it. This
      // page runs on until the reload commits: halted, the backend no
      // longer answers its startup, and whatever it writes anyway is
      // seeded over again as it goes.
      backend.halt();
      addEventListener('pagehide', () => seedStorage(window.localStorage, seed.data, seed.iface));
      sessionStorage.setItem(RELOAD_KEY, JSON.stringify({ href: location.href, seededAt: seed.at } satisfies ReloadMark));
      console.info('Lantenna mock: scanStore loaded before the mock seeded its data; reloading once.');
      location.reload();
      return 'reloading';
    }
  }

  const hosted = await waitFor(hostedWindow, (value) => value !== null);
  if (scenario.shaded) setTimeout(() => hosted?.setShaded(true));
  if (scenario.name === 'loading') return 'ready';

  await waitFor(scanStore, (state) => !state.loading);
  if (scenario.select) scanStore.setSelectedHost(scenario.select);

  switch (scenario.name) {
    case 'scanning':
    case 'fingerprint':
      await scanStore.startScan();
      await backend.holdPoint();
      break;

    case 'stopping':
      await scanStore.startScan();
      await backend.holdPoint();
      await scanStore.cancelScan();
      break;

    case 'rescanned':
      await scanStore.startScan();
      await waitFor(scanStore, (state) => !state.scanning);
      break;

    case 'error':
      if (scenario.error === 'init') break;
      await scanStore.startScan();
      await waitFor(scanStore, (state) => !state.scanning);
      break;

    case 'deep-scan': {
      // Through the pane's action (it also writes the host status line).
      // If no scan_host_ports call follows within a quarter second, the
      // action is still a stub: ask the store directly.
      const ip = scenario.select ?? '192.168.1.31';
      const { deepScan } = await import('$lib/app/actions');
      void deepScan(ip);
      const asked = Date.now();
      while (backend.calls('scan_host_ports').length === 0 && Date.now() - asked < 250) await nextFrame();
      if (backend.calls('scan_host_ports').length === 0 && !get(scanProgress).hostScanProgress?.running) {
        void scanStore.refreshHostPorts(ip, 'deep');
      }
      await backend.holdPoint();
      break;
    }
  }

  return 'ready';
}

if (import.meta.env.MODE === 'mock') {
  installMockBackend(parseScenario(location.search, pagePlatform));
}
