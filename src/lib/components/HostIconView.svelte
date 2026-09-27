<!--
  Owner: unit B (spec 8.4). Spec: 2.8, 3.1 (1.13 to 1.15, 1.23, 1.24),
  3.2, 3.3, 3.4, 4.4, 4.5, 5.6.

  View > as Icons: the hosts as a grid of 32 x 32 icons, Lantenna's own
  (Osmium has no icon view yet, spec 7.2 N9), drawn with Osmium's fonts,
  highlight color, list box classes and scroll bar. The same rows,
  order, selection and contextual menus as the list. Rows arrive from
  hostModel once per animation frame, as in the list. Publishes a
  HostViewApi in activeView while mounted.

  A listbox of options with a roving tabindex: only the selected tile
  (or the first) is in the Tab order, and the keys are handled on the
  grid. keyboardFocus (focus.ts) classifies focus inside .lan-icons as
  "icons"; the page's CSS places it (position: absolute; inset: 0 in
  .lan-view).

  Osmium's scroll bar (attachScrollbar) owns the host's scroll-bar class
  and appends its bar to the host: static class and class: directives
  only on it.
-->
<svelte:options runes={true} />

<script module lang="ts">
  /** Where an icon label may break: after a space, hyphen, period or
   * underscore (host names rarely have spaces). */
  const BREAK_AFTER = /[\s\-._]/;

  /** The largest n in 1..max for which fits(n) holds (at least 1). */
  function longest(max: number, fits: (n: number) => boolean): number {
    let lo = 1;
    let hi = max;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (fits(mid)) lo = mid;
      else hi = mid - 1;
    }
    return lo;
  }

  /**
   * An icon label as at most two lines no wider than `max` px by
   * `measure`: the first line breaks after the last break character
   * that fits (anywhere if none does); a second line too long ends in
   * an ellipsis. Pure, for the tiles' whole-pixel layout.
   */
  export function wrapLabel(text: string, max: number, measure: (s: string) => number): string[] {
    if (text.length < 2 || measure(text) <= max) return [text];

    const fit = longest(text.length, (n) => measure(text.slice(0, n)) <= max);
    let cut = fit;
    for (let i = fit; i > 0; i--) {
      if (BREAK_AFTER.test(text[i - 1])) {
        cut = i;
        break;
      }
    }

    const first = text.slice(0, cut).trimEnd() || text.slice(0, cut);
    const rest = text.slice(cut).trimStart();
    if (!rest) return [first];
    if (measure(rest) <= max) return [first, rest];

    const kept = longest(rest.length, (n) => measure(`${rest.slice(0, n)}…`) <= max);
    return [first, `${rest.slice(0, kept).trimEnd()}…`];
  }
</script>

<script lang="ts">
  import { flushSync, onMount, tick, untrack } from 'svelte';
  import { get } from 'svelte/store';
  import { attachScrollbar, centerText, installOsmium, type MenuPoint } from 'osmium-ui';
  import { openHost } from '$lib/app/actions';
  import { HOST_LIST_BALLOON } from '$lib/app/balloonTexts';
  import { openHostMenu, openViewMenu } from '$lib/app/contextMenus';
  import { hostModel, type HostModel, type HostRow } from '$lib/app/hostModel';
  import { ui } from '$lib/app/ui';
  import { activeView, type HostViewApi } from '$lib/app/views';
  import { areaBalloon } from '$lib/osm/actions';
  import { STAR } from '$lib/osm/sprites';
  import { scanStore } from '$lib/util/scanStore';

  // The grid (2.8): 112px columns as before the port (Finder 8's pitch
  // is not measured), 6px apart; tiles 72px tall (a 32px icon, two
  // lines of Geneva 9 and the IP line), 14px apart; 14px and 12px
  // padding. The CSS below uses the same numbers.
  const PAD_X = 12;
  const PAD_Y = 14;
  const TILE_W = 112;
  const COL_GAP = 6;
  const ROW_PITCH = 72 + 14;
  /** The name's highlight reaches 3px past its text on either side. */
  const LABEL_PAD = 3;

  /** Type-select starts over after this long without a key (Osmium's
   * list uses the same second). */
  const TYPE_RESET_MS = 1000;

  /** A contextmenu event this soon after the menu key or Shift-F10 is
   * that key's (where the system sends one too): the menu is open. */
  const KEY_MENU_MS = 500;

  let host: HTMLDivElement;
  let grid: HTMLDivElement;
  let empty: HTMLDivElement;

  const start = get(hostModel);
  let rows: readonly HostRow[] = $state.raw(start.rows);
  let placeholder = $state(placeholderOf(start));

  const selectedIp = $derived($scanStore.selectedHostIp);
  /** The tile in the Tab order: the selected one while it is shown,
   * else the first. */
  const tabStop = $derived(
    selectedIp !== null && rows.some((row) => row.ip === selectedIp) ? selectedIp : (rows[0]?.ip ?? null)
  );

  function placeholderOf(m: HostModel): string {
    if (m.rows.length) return '';
    return m.loading ? m.loadingText : m.emptyText;
  }

  /** The option's accessible name: what the tile shows (the address
   * once when it is also the name), plus the icon's label and the row
   * state as text (5.6). */
  function tileLabel(row: HostRow): string {
    const ip = row.iconName === row.ip ? '' : row.ip;
    const parts = [row.iconName, ip, row.icon.label, row.status, row.favorite ? 'Favorite' : ''];
    return parts.filter(Boolean).join(', ');
  }

  function isDim(row: HostRow): boolean {
    return row.pending || row.stale || row.hidden;
  }

  // ---- whole-pixel labels ------------------------------------------------
  // Centered bitmap text must start on a whole pixel (text-align: center
  // puts odd differences on half pixels and blurs the glyphs; Osmium's
  // centerText and its demo's icon labels place text the same way). The
  // tiles' texts are measured in their font (bitmap advances are whole
  // pixels), broken into lines here and each line placed at
  // floor((tile - line) / 2). Until the fonts load, and without a
  // canvas, the widths are wrong or unknown; `fontsReady` redoes them.

  interface Line {
    readonly text: string;
    /** Left offset in the tile, or null (unmeasured: CSS centers it). */
    readonly x: number | null;
  }

  interface TileLayout {
    readonly lines: readonly Line[];
    readonly ip: Line;
  }

  let fontsReady = $state(0);
  let context: CanvasRenderingContext2D | null | undefined;
  let captionFont = '';
  const layouts = new WeakMap<HostRow, { readonly ready: number; readonly layout: TileLayout }>();

  function measurer(bold: boolean): ((s: string) => number) | null {
    context ??= document.createElement('canvas').getContext('2d');
    if (!context) return null;
    captionFont ||=
      getComputedStyle(document.documentElement).getPropertyValue('--osm-font-caption').trim() ||
      '9px/12px "Osmium Geneva 9", Geneva, sans-serif';
    const ctx = context;
    const font = `${bold ? 'bold ' : ''}${captionFont}`;
    return (s) => {
      ctx.font = font;
      return Math.round(ctx.measureText(s).width);
    };
  }

  function px(x: number | null): string | null {
    return x === null ? null : `${x}px`;
  }

  function layoutOf(row: HostRow, ready: number): TileLayout {
    const cached = layouts.get(row);
    if (cached?.ready === ready) return cached.layout;

    const ipText = row.isNew ? `${row.ip} New` : row.ip;
    const measureName = measurer(row.isNew);
    const measure = measurer(false);
    const layout: TileLayout =
      measureName && measure
        ? {
            lines: wrapLabel(row.iconName, TILE_W - 2 * LABEL_PAD, measureName).map((text) => ({
              text,
              x: Math.max(0, Math.floor((TILE_W - measureName(text) - 2 * LABEL_PAD) / 2))
            })),
            ip: { text: ipText, x: Math.max(0, Math.floor((TILE_W - measure(ipText)) / 2)) }
          }
        : { lines: [{ text: row.iconName, x: null }], ip: { text: ipText, x: null } };
    layouts.set(row, { ready, layout });
    return layout;
  }

  // The tiles' elements by IP, for focus and scrolling.
  const tiles = new Map<string, HTMLElement>();

  function tile(node: HTMLElement, ip: string) {
    let current = ip;
    tiles.set(current, node);
    return {
      update(next: string) {
        if (tiles.get(current) === node) tiles.delete(current);
        current = next;
        tiles.set(current, node);
      },
      destroy() {
        if (tiles.get(current) === node) tiles.delete(current);
      }
    };
  }

  function tileOf(target: EventTarget | null): HTMLElement | null {
    return target instanceof Element ? target.closest<HTMLElement>('.lan-tile') : null;
  }

  /** Columns in the grid as laid out now (at least 1). */
  function columnCount(): number {
    return Math.max(1, Math.floor((grid.clientWidth - 2 * PAD_X + COL_GAP) / (TILE_W + COL_GAP)));
  }

  function scrollToTile(el: HTMLElement): void {
    const top = el.offsetTop - PAD_Y;
    const bottom = el.offsetTop + el.offsetHeight + PAD_Y;
    if (top < grid.scrollTop) grid.scrollTop = top;
    else if (bottom > grid.scrollTop + grid.clientHeight) grid.scrollTop = bottom - grid.clientHeight;
  }

  /** Select `ip` (the store holds the selection) and move the keyboard
   * to its tile, which the tile's tabindex follows. */
  function selectAndFocus(ip: string): void {
    if (get(scanStore).selectedHostIp !== ip) scanStore.setSelectedHost(ip);
    const el = tiles.get(ip);
    if (!el) return;
    el.focus({ preventScroll: true });
    scrollToTile(el);
  }

  /** Where the keyboard goes when the view takes it: the selected tile
   * while it is shown, else the grid itself, since focusing a tile
   * selects its host (onFocusin). */
  function focusTarget(): HTMLElement {
    const ip = get(scanStore).selectedHostIp;
    return (ip === null ? undefined : tiles.get(ip)) ?? grid;
  }

  function selectedIndex(): number {
    const ip = get(scanStore).selectedHostIp;
    return ip === null ? -1 : rows.findIndex((row) => row.ip === ip);
  }

  let typed = '';
  let typedAt = -Infinity;
  const typing = () => typed !== '' && Date.now() - typedAt < TYPE_RESET_MS;

  let keyMenuAt = -Infinity;

  function isInside(e: MouseEvent, el: Element): boolean {
    const r = el.getBoundingClientRect();
    return e.clientX >= r.left && e.clientX < r.right && e.clientY >= r.top && e.clientY < r.bottom;
  }

  /** Under the name of `el`'s tile (its last line). */
  function underName(el: HTMLElement): MenuPoint {
    const lines = el.querySelectorAll('.lan-tile-name');
    const r = (lines[lines.length - 1] ?? el).getBoundingClientRect();
    return { x: r.left, y: r.bottom };
  }

  function gridCorner(): MenuPoint {
    const r = grid.getBoundingClientRect();
    return { x: r.left, y: r.top };
  }

  /** The menu key or Shift-F10: the selected tile's menu under its
   * name, or the view's menu without a (shown) selection. */
  function keyboardMenu(): void {
    keyMenuAt = performance.now();
    const index = selectedIndex();
    const el = index < 0 ? undefined : tiles.get(rows[index].ip);
    if (!el) {
      openViewMenu(gridCorner());
      return;
    }

    scrollToTile(el);
    openHostMenu(rows[index].ip, underName(el));
  }

  const NAV_KEYS = new Set(['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End', 'PageUp', 'PageDown']);

  function onKeydown(e: KeyboardEvent): void {
    if (e.defaultPrevented || e.isComposing || e.metaKey || e.ctrlKey || e.altKey) return;

    if (e.key === 'ContextMenu' || (e.key === 'F10' && e.shiftKey)) {
      e.preventDefault();
      keyboardMenu();
      return;
    }

    if (NAV_KEYS.has(e.key)) {
      if (!rows.length) return;
      e.preventDefault();
      const at = selectedIndex();
      const last = rows.length - 1;
      const cols = columnCount();
      const page = cols * Math.max(1, Math.floor(grid.clientHeight / ROW_PITCH) - 1);
      const next =
        e.key === 'ArrowRight' ? (at < 0 ? 0 : Math.min(last, at + 1))
        : e.key === 'ArrowLeft' ? (at < 0 ? last : Math.max(0, at - 1))
        : e.key === 'ArrowDown' ? (at < 0 ? 0 : Math.min(last, at + cols))
        : e.key === 'ArrowUp' ? (at < 0 ? last : Math.max(0, at - cols))
        : e.key === 'Home' ? 0
        : e.key === 'End' ? last
        : e.key === 'PageDown' ? Math.min(last, Math.max(0, at) + page)
        : Math.max(0, (at < 0 ? last : at) - page);
      selectAndFocus(rows[next].ip);
      return;
    }

    if (e.key === 'Enter') {
      const at = selectedIndex();
      if (at < 0 || e.repeat) return;
      e.preventDefault();
      void openHost(rows[at].ip);
      return;
    }

    if (e.key.length !== 1) return;
    // Space on its own is not a name's start (it would scroll the grid).
    e.preventDefault();
    if (e.key === ' ' && !typing()) return;

    typed = (typing() ? typed : '') + e.key.toLowerCase();
    typedAt = Date.now();
    const match = rows.find((row) => row.iconName.toLowerCase().startsWith(typed));
    if (match) selectAndFocus(match.ip);
  }

  function onPointerdown(e: PointerEvent): void {
    // Control-click and right-click belong to the contextual menu.
    if (e.button !== 0 || e.ctrlKey) return;
    const ip = tileOf(e.target)?.dataset.ip;
    if (ip) scanStore.setSelectedHost(ip);
  }

  function onDblclick(e: MouseEvent): void {
    const ip = tileOf(e.target)?.dataset.ip;
    if (ip && ip === get(scanStore).selectedHostIp) void openHost(ip);
  }

  /** Tabbing into the grid (onto the first tile) selects it, as a click
   * would: the keyboard's place and the selection stay one. */
  function onFocusin(e: FocusEvent): void {
    const ip = tileOf(e.target)?.dataset.ip;
    if (ip && ip !== get(scanStore).selectedHostIp) scanStore.setSelectedHost(ip);
  }

  /** Control-click or right-click on a tile or on empty space (3.3),
   * or a menu request from the keyboard that the system sends as a
   * contextmenu event (aimed at the focused element, anywhere). */
  function onContextmenu(e: MouseEvent): void {
    e.preventDefault();
    if (performance.now() - keyMenuAt < KEY_MENU_MS) return;

    const el = tileOf(e.target);
    const ip = el?.dataset.ip;
    if (!el || !ip) {
      openViewMenu(isInside(e, grid) ? { x: e.clientX, y: e.clientY } : gridCorner());
      return;
    }

    selectAndFocus(ip);
    openHostMenu(ip, isInside(e, el) ? { x: e.clientX, y: e.clientY } : underName(el));
  }

  // The placeholder is centered the Osmium way (whole-pixel indent).
  $effect(() => {
    void placeholder;
    untrack(() => centerText(empty));
  });

  onMount(() => {
    // Measure the labels again once the bitmap fonts can be measured.
    void installOsmium()
      .catch(() => {})
      .finally(() => fontsReady++);

    let model: HostModel = start;
    let frame = 0;

    // Osmium's bar follows the grid's scrolling and box, not its
    // content: apply() updates it when the tiles change.
    const scrollbar = attachScrollbar(host, grid, ROW_PITCH);

    function apply(): void {
      frame = 0;
      const hadFocus = grid.contains(document.activeElement);
      rows = model.rows;
      placeholder = placeholderOf(model);
      flushSync();
      scrollbar.update();

      // The keyed each moves a reordered tile (insertBefore) and removes
      // a gone one, and either takes the focus with it to the body. Keep
      // the keyboard in the grid, where the tile went; no scrolling, as
      // the list keeps its place when rows move.
      if (hadFocus && !grid.contains(document.activeElement)) focusTarget().focus({ preventScroll: true });
    }

    /** Hand over rows still waiting for the frame, and draw them now
     * (views.ts: callers use the view in the same task). */
    function flush(): void {
      if (frame) {
        cancelAnimationFrame(frame);
        apply();
      }
      flushSync();
    }

    const stopModel = hostModel.subscribe((m) => {
      if (m === model) return;
      model = m;
      if (!frame) frame = requestAnimationFrame(apply);
    });

    const api: HostViewApi = {
      element: grid,
      focus() {
        flush();
        const el = focusTarget();
        el.focus({ preventScroll: true });
        if (el !== grid) scrollToTile(el);
      },
      reveal(ip) {
        flush();
        const el = tiles.get(ip);
        if (el) scrollToTile(el);
      },
      extraHeight() {
        flush();
        return Math.max(0, grid.scrollHeight - grid.clientHeight);
      },
      idealColumnsWidth() {
        return null;
      }
    };
    activeView.set(api);

    // Switching views keeps the selection: show it.
    const ip = get(scanStore).selectedHostIp;
    const el = ip === null ? undefined : tiles.get(ip);
    if (el) scrollToTile(el);

    // And the keyboard: the page swaps the views on Svelte's next update
    // (activeView is still this view's until then), so the next view
    // takes it after tick().
    let mode = get(ui).viewMode;
    const stopMode = ui.subscribe((u) => {
      if (u.viewMode === mode) return;
      mode = u.viewMode;
      if (host.contains(document.activeElement)) void tick().then(() => get(activeView)?.focus());
    });

    return () => {
      if (get(activeView) === api) activeView.set(null);
      stopModel();
      stopMode();
      if (frame) cancelAnimationFrame(frame);
      scrollbar.destroy();
    };
  });
</script>

<div
  class="lan-icons osm-list"
  class:lan-icons-corner={!$ui.infoPaneShown}
  style:--lan-star-badge={STAR.badge}
  bind:this={host}
>
  <div
    class="osm-list-view lan-icons-grid"
    role="listbox"
    aria-label="Hosts"
    tabindex={rows.length ? -1 : 0}
    bind:this={grid}
    use:areaBalloon={HOST_LIST_BALLOON}
    onkeydown={onKeydown}
    onpointerdown={onPointerdown}
    ondblclick={onDblclick}
    onfocusin={onFocusin}
    oncontextmenu={onContextmenu}
  >
    {#each rows as row (row.ip)}
      {@const layout = layoutOf(row, fontsReady)}
      <div
        class="lan-tile"
        class:lan-selected={row.ip === selectedIp}
        class:lan-new={row.isNew}
        class:lan-dim={isDim(row)}
        role="option"
        aria-selected={row.ip === selectedIp}
        aria-label={tileLabel(row)}
        tabindex={row.ip === tabStop ? 0 : -1}
        data-ip={row.ip}
        use:tile={row.ip}
      >
        <span class="lan-tile-icon">
          <img src={row.icon.large} alt="" width="32" height="32" draggable="false" />
          {#if row.favorite}<span class="lan-tile-badge"></span>{/if}
        </span>
        {#each layout.lines as line, i (i)}
          <span class="lan-tile-name" class:lan-centered={line.x === null} style:margin-left={px(line.x)}>{line.text}</span>
        {/each}
        <span class="lan-tile-ip" class:lan-centered={layout.ip.x === null} style:margin-left={px(layout.ip.x)}
          >{layout.ip.text}</span
        >
      </div>
    {/each}
  </div>
  <div class="osm-list-empty lan-icons-empty" role="status" hidden={!placeholder} bind:this={empty}>{placeholder}</div>
</div>

<style>
  /* Osmium's list box and scroller classes (the scroll bar's setup, as
     mountList makes it), edge to edge like the list: the view's right
     edge and the content frame draw the black lines. */
  .lan-icons {
    border: 0;
    background: #fff;
    color: #000;
    font: var(--osm-font-caption);
  }

  /* The bar starts under the window header rather than on its bottom
     row (no column headers here to overlap). */
  .lan-icons > :global(.osm-scrollbar) {
    top: 0;
  }

  /* With the pane hidden, the grow box sits in this view's bottom-right
     corner: stop short of it, as a list's two scroll bars do. */
  .lan-icons-corner > :global(.osm-scrollbar) {
    bottom: 14px;
  }

  .lan-icons-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, 112px);
    grid-auto-rows: 72px;
    gap: 14px 6px;
    align-content: start;
    padding: 14px 12px;
    box-sizing: border-box;
    outline: none;
  }

  /* Over the grid, where the tiles go; presses go through to it. */
  .lan-icons-empty {
    position: absolute;
    left: 0;
    right: 15px;
    top: 0;
    pointer-events: none;
  }

  /* Everything placed on whole pixels: the icon 40px in, the lines at
     their measured offsets. */
  .lan-tile {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    min-width: 0;
    outline: none;
    /* Long grids: lay out only the tiles near the view. */
    content-visibility: auto;
    contain-intrinsic-size: 112px 72px;
  }

  .lan-tile-icon {
    position: relative;
    flex: none;
    width: 32px;
    height: 32px;
    margin: 0 0 2px 40px;
  }

  .lan-tile-icon > img {
    display: block;
    width: 32px;
    height: 32px;
    image-rendering: pixelated;
  }

  /* The 9 x 9 favorite badge at the icon's top-right (8.5's badges sit
     on the icon). */
  .lan-tile-badge {
    position: absolute;
    top: 0;
    right: 0;
    width: 9px;
    height: 9px;
    background: var(--lan-star-badge) 0 0 no-repeat;
  }

  /* One line of the name (wrapLabel makes at most two). */
  .lan-tile-name {
    flex: none;
    max-width: 106px;
    padding: 0 3px 1px;
    white-space: nowrap;
    overflow: hidden;
  }

  .lan-tile-ip {
    flex: none;
    max-width: 112px;
    color: #666;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  /* Not measured (no canvas): centered by CSS instead. */
  .lan-centered {
    align-self: center;
  }

  .lan-new .lan-tile-name {
    font-weight: 700;
  }

  /* Pending, stale and shown-hidden hosts (2.8). */
  .lan-dim .lan-tile-icon {
    opacity: 0.5;
  }

  .lan-dim .lan-tile-name {
    color: #888;
  }

  /* Selected: the icon darkened and the name in the highlight color, in
     an inactive window too (Finder). */
  .lan-selected .lan-tile-icon {
    filter: brightness(0.5);
  }

  .lan-selected .lan-tile-name {
    background: var(--osm-highlight);
    color: var(--osm-highlight-text);
  }

  :global(.osm-kbd) .lan-tile:focus-visible .lan-tile-name {
    outline: 2px solid var(--osm-focus-ring);
  }

  /* The grid itself has the keyboard only while no tile is selected
     (focusTarget): ring it inside its edges, as the list does. */
  :global(.osm-kbd) .lan-icons-grid:focus-visible {
    outline: 2px solid var(--osm-focus-ring);
    outline-offset: -2px;
  }
</style>
