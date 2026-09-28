// Owner: unit F (spec 8.4). Spec: 1.25 (3.1), 2.5, 2.6, 2.8, 6, 7.2.
//
// Lantenna's own pixel art, registered with Osmium's registerSprites()
// as --osm-sprite-lan-* custom properties: twelve 16 x 16 host icons
// for the list (the icon view and the General tab keep the 32 x 32
// SVGs in src/lib/assets/host-icons), the favorite stars and the
// antenna that stands in for the Apple menu on Linux.
//
// Grids use Osmium's palette keys: a hex digit is a gray (0 = #000000,
// 8 = #888888, f = #ffffff), '.' is transparent, and letters are the
// colors in PALETTE, all of them entries of the Mac OS 8 system
// palette (the 256-color 'clut' 8: the 6 x 6 x 6 cube plus the red,
// green, blue and gray ramps). The accent-following stars use Osmium's
// accent ramp keys instead (q p m, light to dark, Lavender unless the
// page sets another accent).
//
// Provenance: drawn for Lantenna, not copied from Apple artwork. Each
// host icon redraws the matching 32 x 32 SVG (same object, same
// details) in the style of Mac OS 8.0's small icons ('ics8'), as
// captured from the Finder's list views (Control Panels and Extensions
// folders, Mac OS 8.0 in Infinite Mac): a 1 px black outline, white
// highlights on the top and left edges and gray shadows on the bottom
// and right (light from the top left), and screens in #ccccff, the
// screen color of the Monitors extensions' small icons in those
// captures (emulator gamma undone).

import { registerSprites } from 'osmium-ui';

export type HostIconKind =
  | 'camera'
  | 'iot'
  | 'kvm'
  | 'media'
  | 'mobile'
  | 'pc-generic'
  | 'pc-linux'
  | 'pc-mac'
  | 'pc-windows'
  | 'printer'
  | 'router'
  | 'server';

/** The colors the grids name by letter, from the Mac OS 8 system
 * palette. The SVGs' colors are taken to their nearest palette entry,
 * nudged toward a more saturated one where a 1 px detail would
 * otherwise vanish. Osmium's own keys (accent w q p m l n h, alert
 * R P M N Y K k y s) are left alone. */
const PALETTE = {
  v: '#ccccff', // screens (Mac OS 8's monitor icons)
  C: '#ccffff', // camera lens glass
  B: '#0033ff', // Linux "L"
  U: '#3366cc', // dark blue: IoT eyes, router LED, phone row
  u: '#6699cc', // blue: Windows panes, media bar, remote window
  x: '#3399cc', // rainbow blue
  j: '#9966cc', // rainbow purple
  J: '#cc99cc', // phone row purple
  Q: '#9999cc', // router LED purple
  r: '#cc3333', // rainbow red
  E: '#ff0000', // server LED
  o: '#ff9933', // orange
  z: '#ffcc33', // yellow
  Z: '#cccc66', // phone row yellow
  O: '#cc9900', // router LED amber
  t: '#cc9966', // tan: camera flash, media bar
  g: '#66cc66', // green
  G: '#339966', // dark green: IoT mouth, router LED
  X: '#99cc99', // phone row green
  S: '#ff6633', // antenna red
  V: '#996699', // antenna purple
  W: '#0099ff' // antenna blue
} as const;

// ---- host icons (16 x 16) ------------------------------------------

/** A monitor on a stand (pc-*.svg, media.svg): platinum bezel, the
 * screen recessed behind a black edge, a gray neck and a black foot.
 * `screen` is the 10 x 8 picture inside the edge. */
function onMonitor(screen: readonly string[]): string[] {
  if (screen.length !== 8 || screen.some((row) => row.length !== 10))
    throw new Error('a monitor screen is 10 x 8');
  return [
    '.00000000000000.',
    '0fffffffffffffd0',
    '0f000000000000a0',
    ...screen.map((row) => `0f0${row}0a0`),
    '0f000000000000a0',
    '0daaaaaaaaaaaaa0',
    '.00000000000000.',
    '......0880......',
    '....00000000....'
  ];
}

/** "Unknown host" (pc-generic.svg): a blank screen with a glint. */
const PC_GENERIC = onMonitor([
  'vvvvvvvvvv',
  'vffvvvvvvv',
  'vfvvvvvvvv',
  'vvvvvvvvvv',
  'vvvvvvvvvv',
  'vvvvvvvvvv',
  'vvvvvvvvvv',
  'vvvvvvvvvv'
]);

/** "Linux host" (pc-linux.svg): a blue L. */
const PC_LINUX = onMonitor([
  'vvvvvvvvvv',
  'vvBBvvvvvv',
  'vvBBvvvvvv',
  'vvBBvvvvvv',
  'vvBBvvvvvv',
  'vvBBBBBvvv',
  'vvBBBBBvvv',
  'vvvvvvvvvv'
]);

/** "Apple host" (pc-mac.svg): six rainbow stripes, red at the top as
 * in the SVG. */
const PC_MAC = onMonitor([
  'vvvvvvvvvv',
  'vvrrrrrrvv',
  'vvoooooovv',
  'vvzzzzzzvv',
  'vvggggggvv',
  'vvxxxxxxvv',
  'vvjjjjjjvv',
  'vvvvvvvvvv'
]);

/** "Windows host" (pc-windows.svg): four panes. */
const PC_WINDOWS = onMonitor([
  'vvvvvvvvvv',
  'vvvvvvvvvv',
  'vvvuuvuuvv',
  'vvvuuvuuvv',
  'vvvvvvvvvv',
  'vvvuuvuuvv',
  'vvvuuvuuvv',
  'vvvvvvvvvv'
]);

/** "TV / media device" (media.svg): three bars, blue, green and tan. */
const MEDIA = onMonitor([
  'vvvvvvvvvv',
  'vvvvvvttvv',
  'vvuuvvttvv',
  'vvuuggttvv',
  'vvuuggttvv',
  'vvuuggttvv',
  'vvuuggttvv',
  'vvvvvvvvvv'
]);

/** "KVM device" (kvm.svg): a monitor showing a remote window, and a
 * keyboard (its keys as in Mac OS 8's Keyboard control panel icon). */
const KVM = [
  '.00000000000000.',
  '0fffffffffffffd0',
  '0f000000000000a0',
  '0f0vvvvvvvvvv0a0',
  '0f0vvuuuuuuvv0a0',
  '0f0vvuffffuvv0a0',
  '0f0vvuuuuuuvv0a0',
  '0f0vvvvvvvvvv0a0',
  '0f000000000000a0',
  '0daaaaaaaaaaaaa0',
  '.00000000000000.',
  '................',
  '..400000000004..',
  '..0d0d0d0d0dd0..',
  '..0dd000000dd0..',
  '..400000000004..'
];

/** "Mobile device" (mobile.svg): a dark phone whose screen lists four
 * colored rows. */
const MOBILE = [
  '....00000000....',
  '...0777777750...',
  '...0700000040...',
  '...070UUUU040...',
  '...070vvvv040...',
  '...070XXXX040...',
  '...070vvvv040...',
  '...070ZZZZ040...',
  '...070vvvv040...',
  '...070JJJJ040...',
  '...070vvvv040...',
  '...070vvvv040...',
  '...0700000040...',
  '...0755555540...',
  '...0544444440...',
  '....00000000....'
];

/** "Printer" (printer.svg): a printed page standing out of a gray
 * printer with a light front panel. */
const PRINTER = [
  '....00000000....',
  '....0ffffff0....',
  '....0faaaaf0....',
  '....0ffffff0....',
  '....0faaaaf0....',
  '....0ffffff0....',
  '.00000000000000.',
  '0aaaaaaaaaaaaaa0',
  '0a8dddddddddd850',
  '0a8dddddddddd850',
  '0a8dddddddddd850',
  '0a8dddddddddd850',
  '0a88888888888850',
  '0555555555555550',
  '.00000000000000.',
  '................'
];

/** "Network device" (router.svg): three antennas on a box whose panel
 * shows four status lights (blue, green, amber, purple). */
const ROUTER = [
  '................',
  '....0...0...0...',
  '....0...0...0...',
  '....0...0...0...',
  '....0...0...0...',
  '...000.000.000..',
  '...0a0.0a0.0a0..',
  '..0000000000000.',
  '..0fffffffffff0.',
  '..0f000000000a0.',
  '..0f0fffffff0a0.',
  '..0f0UfGfOfQ0a0.',
  '..0f0fffffff0a0.',
  '..0f000000000a0.',
  '..0aaaaaaaaaaa0.',
  '..0000000000000.'
];

/** "Server / storage" (server.svg): three rack units, each with a red
 * light at the left of its slot. */
const SERVER = [
  '................',
  '.00000000000000.',
  '.0aaaaaaaaaaa80.',
  '.0a8Eeeeeeee850.',
  '.0a555555555550.',
  '.00000000000000.',
  '.0aaaaaaaaaaa80.',
  '.0a8Eeeeeeee850.',
  '.0a555555555550.',
  '.00000000000000.',
  '.0aaaaaaaaaaa80.',
  '.0a8Eeeeeeee850.',
  '.0a555555555550.',
  '.00000000000000.',
  '................',
  '................'
];

/** "Camera" (camera.svg): a box with a large lens and a tan flash. */
const CAMERA = [
  '................',
  '..0000..........',
  '..0fa0..........',
  '.00000000000000.',
  '0fffffffffffffd0',
  '0fdddd0000dttda0',
  '0fddd0CCCC0ddda0',
  '0fdd0CffCCC0dda0',
  '0fdd0CfCCCC0dda0',
  '0fdd0CCCCCC0dda0',
  '0fdd0CCCCCC0dda0',
  '0fddd0CCCC0ddda0',
  '0fdddd0000dddda0',
  '0daaaaaaaaaaaaa0',
  '.00000000000000.',
  '................'
];

/** "IoT device" (iot.svg): a chip with two pins a side and a face. */
const IOT = [
  '.....0....0.....',
  '.....0....0.....',
  '..000000000000..',
  '..0ffffffffff0..',
  '..0f88888888a0..',
  '000f8ffffff8a000',
  '..0f8fUffUf8a0..',
  '..0f8ffffff8a0..',
  '..0f8ffUfff8a0..',
  '..0f8ffffff8a0..',
  '000f8fGGGff8a000',
  '..0f8ffffff8a0..',
  '..0faaaaaaaaa0..',
  '..000000000000..',
  '.....0....0.....',
  '.....0....0.....'
];

const HOST_ICONS: Readonly<Record<HostIconKind, readonly string[]>> = {
  camera: CAMERA,
  iot: IOT,
  kvm: KVM,
  media: MEDIA,
  mobile: MOBILE,
  'pc-generic': PC_GENERIC,
  'pc-linux': PC_LINUX,
  'pc-mac': PC_MAC,
  'pc-windows': PC_WINDOWS,
  printer: PRINTER,
  router: ROUTER,
  server: SERVER
};

// ---- favorite stars ---------------------------------------------------
// Mac OS 8 had no favorite star; these follow its checkbox: an empty
// mark for off, and on filled in the accent (as the thumbs and the
// progress bar are), lit from the top left.

/** A list cell's star, off (11 x 11): a white star in a gray outline,
 * lighter than a black one so a column of them stays quiet. */
const STAR_OFF = [
  '.....8.....',
  '....8f8....',
  '....8f8....',
  '...8fff8...',
  '888fffff888',
  '8fffffffff8',
  '.8fffffff8.',
  '..8fffff8..',
  '..8ff8ff8..',
  '.8ff8.8ff8.',
  '.888...888.'
];

/** A list cell's star, on (11 x 11): filled in the accent ramp. */
const STAR_ON = [
  '.....0.....',
  '....0q0....',
  '....0q0....',
  '...0qpp0...',
  '000qpppp000',
  '0qppppppmm0',
  '.0ppppppm0.',
  '..0ppppm0..',
  '..0pm0pm0..',
  '.0pm0.0mm0.',
  '.000...000.'
];

/** The star column's header (11 x 11): solid black like the header
 * titles, so it reads on the plain (#ccc) and the sorted (#888)
 * header. */
const STAR_HEADER = [
  '.....0.....',
  '....000....',
  '....000....',
  '...00000...',
  '00000000000',
  '00000000000',
  '.000000000.',
  '..0000000..',
  '..0000000..',
  '.0000.0000.',
  '.000...000.'
];

/** The badge on a favorite's icon-view tile (9 x 9), in the accent.
 * Its outline mirrors about column 4, as the 11 x 11 stars' do. */
const STAR_BADGE = [
  '....0....',
  '...0q0...',
  '...0p0...',
  '000qpp000',
  '0qppppmm0',
  '.0pppmm0.',
  '..0p0m0..',
  '.0p0.0m0.',
  '.00...00.'
];

// ---- antenna (16 x 16) --------------------------------------------------
/** Lantenna's ant (media-sources/antenna-icon.png) for the Linux menu
 * bar's first title, drawn the way Mac OS 8 draws the Apple menu's
 * logo there: no outline, stripes of color, a 44 gray shadow one pixel
 * down and right. */
const ANTENNA_ICON = [
  '..gg.......VV...',
  '.g..z.....S..W..',
  'g....zzooS....W.',
  'g...zzooSSS...W.',
  '...zzooSSSVV....',
  '...z00SSS00V4...',
  '...o00SSV00W4...',
  '...o00SVV00W4...',
  '...SSSVVVWWW4...',
  '....SVVVWWW44...',
  '....VVVWWWW4....',
  '.....VWWWW44....',
  '.....WWWWW4.....',
  '......WWW44.....',
  '.......444......',
  '................'
];

let registered = false;

/** Register Lantenna's sprites with Osmium. Safe to call more than once:
 * only the first call registers. */
export function registerAppSprites(): void {
  if (registered) return;
  const fixed: Record<string, readonly string[]> = {
    'lan-star-off': STAR_OFF,
    'lan-star-header': STAR_HEADER,
    'lan-antenna': ANTENNA_ICON
  };
  for (const [kind, rows] of Object.entries(HOST_ICONS)) fixed[`lan-${kind}`] = rows;
  registerSprites(fixed, PALETTE);
  registerSprites({ 'lan-star-on': STAR_ON, 'lan-star-badge': STAR_BADGE }, PALETTE, {
    accent: 'follow'
  });
  registered = true;
}

/** CSS images of the 16 x 16 list icons, for ListRowIcon.image. */
export const SMALL_ICON: Readonly<Record<HostIconKind, string>> = {
  camera: 'var(--osm-sprite-lan-camera)',
  iot: 'var(--osm-sprite-lan-iot)',
  kvm: 'var(--osm-sprite-lan-kvm)',
  media: 'var(--osm-sprite-lan-media)',
  mobile: 'var(--osm-sprite-lan-mobile)',
  'pc-generic': 'var(--osm-sprite-lan-pc-generic)',
  'pc-linux': 'var(--osm-sprite-lan-pc-linux)',
  'pc-mac': 'var(--osm-sprite-lan-pc-mac)',
  'pc-windows': 'var(--osm-sprite-lan-pc-windows)',
  printer: 'var(--osm-sprite-lan-printer)',
  router: 'var(--osm-sprite-lan-router)',
  server: 'var(--osm-sprite-lan-server)'
};

/** CSS images of the favorite star: list cell off/on (11 x 11), the
 * star column's header (11 x 11), and the 9 x 9 badge on icon-view
 * tiles. "on" and the badge follow the accent. */
export const STAR: { off: string; on: string; header: string; badge: string } = {
  off: 'var(--osm-sprite-lan-star-off)',
  on: 'var(--osm-sprite-lan-star-on)',
  header: 'var(--osm-sprite-lan-star-header)',
  badge: 'var(--osm-sprite-lan-star-badge)'
};

/** Sprite name (not a CSS value) of the 16 x 16 antenna that stands in
 * for the Apple menu, for Osmium's Menu.icon. */
export const ANTENNA: string = 'lan-antenna';
