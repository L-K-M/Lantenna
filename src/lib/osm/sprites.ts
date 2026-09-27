// Owner: unit F (spec 8.4). Spec: 1.25 (3.1), 2.5, 2.6, 2.8, 7.2.
//
// SCAFFOLD STUB: the names below are final; registerAppSprites()
// registers nothing yet, so every var(--osm-sprite-lan-*) resolves to
// nothing and icons, stars and the antenna draw blank.
// Final contract: registerAppSprites() calls Osmium's registerSprites
// once (idempotent) for twelve 16 x 16 host icons, star off/on (11 x 11,
// "on" with { accent: "follow" }), the header star, a 9 x 9 badge and
// the 16 x 16 antenna.

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

/** Register Lantenna's sprites with Osmium. Safe to call more than once. */
export function registerAppSprites(): void {}

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
 * star column's header, and the 9 x 9 badge on icon-view tiles. */
export const STAR: { off: string; on: string; header: string; badge: string } = {
  off: 'var(--osm-sprite-lan-star-off)',
  on: 'var(--osm-sprite-lan-star-on)',
  header: 'var(--osm-sprite-lan-star-header)',
  badge: 'var(--osm-sprite-lan-star-badge)'
};

/** Sprite name (not a CSS value) of the 16 x 16 antenna that stands in
 * for the Apple menu, for Osmium's Menu.icon. */
export const ANTENNA: string = 'lan-antenna';
