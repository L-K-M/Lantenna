<!--
  Owner: unit B (spec 8.4). Spec: 2.6, 3.1 (1.9, 1.10, 1.15, 1.16, 1.22,
  1.24), 3.2, 3.3, 3.4, 4.4, 4.5, 5.6.

  The host list: Osmium's Finder list view (mountListView) on this
  element, with the columns of 2.6, a star button per row, and rows from
  hostModel handed over once per animation frame (a scan updates the
  store many times a frame). The sort and dragged column widths live in
  ui (persisted there); the selection lives in scanStore. Publishes a
  HostViewApi in activeView while mounted.

  The element belongs to Osmium once mounted: static class and style:
  directives only, and nothing inside it in the template. keyboardFocus
  (focus.ts) classifies focus inside .lan-list as "list"; the page's CSS
  places it (position: absolute; inset: 0 in .lan-view).
-->
<svelte:options runes={true} />

<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { get } from 'svelte/store';
  import {
    attachBalloon,
    mountListView,
    trackPress,
    type ListViewColumn,
    type ListViewSort,
    type MenuPoint,
    type OsmiumBalloon,
    type OsmiumListView,
    type SortDirection
  } from 'osmium-ui';
  import { openHost } from '$lib/app/actions';
  import { columnBalloon, HOST_LIST_BALLOON, SORT_ORDER_BALLOON } from '$lib/app/balloonTexts';
  import type { ColumnId } from '$lib/app/columns';
  import { installControlClick, keyMenuWait, openHostMenu, openViewMenu } from '$lib/app/contextMenus';
  import { hostModel, type HostModel, type HostRow } from '$lib/app/hostModel';
  import { LIST_ROW_H } from '$lib/app/layout';
  import { ui } from '$lib/app/ui';
  import { activeView, type HostViewApi } from '$lib/app/views';
  import { AREA_TIP, pressOnceOnReturn } from '$lib/osm/actions';
  import { STAR } from '$lib/osm/sprites';
  import { formatRelativeTime, normalizeSpaces } from '$lib/util/format';
  import { scanStore } from '$lib/util/scanStore';

  interface ColumnSpec {
    readonly id: ColumnId;
    /** Header title; the star column's is its accessible name. */
    readonly title: string;
    readonly width: number;
    readonly minWidth: number;
    readonly grow: number;
    /** Its normal order's direction (Osmium's aria-sort). */
    readonly sort: SortDirection;
  }

  /** Table 2.6, in display order (COLUMN_IDS). */
  const COLUMNS: readonly ColumnSpec[] = [
    { id: 'favorite', title: 'Favorite', width: 22, minWidth: 22, grow: 0, sort: 'descending' },
    { id: 'name', title: 'Name', width: 200, minWidth: 120, grow: 1, sort: 'ascending' },
    { id: 'ip', title: 'IP Address', width: 100, minWidth: 100, grow: 0, sort: 'ascending' },
    { id: 'status', title: 'Status', width: 64, minWidth: 64, grow: 0, sort: 'ascending' },
    { id: 'kind', title: 'Kind', width: 124, minWidth: 60, grow: 0, sort: 'ascending' },
    { id: 'vendor', title: 'Vendor', width: 112, minWidth: 60, grow: 0, sort: 'ascending' },
    { id: 'ports', title: 'Ports', width: 96, minWidth: 60, grow: 0, sort: 'descending' },
    { id: 'lastSeen', title: 'Last Seen', width: 72, minWidth: 60, grow: 0, sort: 'descending' }
  ];

  /** The columns' base total (790): the zoom box's width until a
   * divider drag fixes the widths (2.10). */
  const BASE_COLUMNS_WIDTH = COLUMNS.reduce((sum, c) => sum + c.width, 0);

  /** Relative Last Seen texts go stale by the minute (1.22). */
  const REFRESH_MS = 60_000;

  // rowClass results, one array per combination, so 4,096 rows share four.
  const ROW_CLASSES: readonly (readonly string[])[] = [[], ['lan-new'], ['lan-dim'], ['lan-new', 'lan-dim']];

  let host: HTMLDivElement;

  /** The columns, with the widths a divider drag stored (then fixed:
   * the first drag fixes every column, and they stay so). */
  function listColumns(stored: Readonly<Record<string, number>> | null): ListViewColumn[] {
    return COLUMNS.map((c) => {
      const saved = stored?.[c.id];
      return {
        id: c.id,
        title: c.id === 'favorite' ? starHeader() : c.title,
        label: c.title,
        width: saved === undefined ? c.width : Math.max(c.minWidth, Math.round(saved)),
        minWidth: c.minWidth,
        grow: stored ? 0 : c.grow,
        sort: c.sort
      };
    });
  }

  function starHeader(): HTMLElement {
    const star = document.createElement('span');
    star.className = 'lan-star-head';
    star.setAttribute('aria-hidden', 'true');
    return star;
  }

  /** The star column's control (2.6): Osmium leaves presses on a button
   * in a cell to the button, so the selection stays, and Space on the
   * list clicks the selected row's first control. The node is reused
   * for its row; data-fav says whose star it is. */
  function starButton(row: HostRow, current: Node | null): HTMLButtonElement {
    let star = current instanceof HTMLButtonElement ? current : null;
    if (!star) {
      const button = document.createElement('button');
      button.type = 'button';
      button.tabIndex = -1;
      button.className = 'lan-star';
      // Control-click is the contextual menu's, as on the rest of the
      // row (the press reaches the list, not the star's tracking).
      button.addEventListener(
        'pointerdown',
        (e) => {
          if (e.ctrlKey) e.stopImmediatePropagation();
        },
        true
      );
      // Tracked like any Mac OS 8 press: it acts on release inside.
      trackPress(button, () => {
        const ip = button.dataset.fav;
        if (ip) scanStore.toggleFavorite(ip);
      });
      star = button;
    }

    star.dataset.fav = row.ip;
    star.setAttribute('aria-pressed', String(row.favorite));
    star.setAttribute('aria-label', `${row.favorite ? 'Unfavorite' : 'Favorite'} ${row.ip}`);
    return star;
  }

  function cell(row: HostRow, column: ListViewColumn, _width: number, current: Node | null): string | Node {
    switch (column.id as ColumnId) {
      case 'favorite':
        return starButton(row, current);
      case 'name':
        return row.listName;
      case 'ip':
        return row.ip;
      case 'status':
        return row.status;
      case 'kind':
        return row.kind;
      case 'vendor':
        return row.vendor;
      case 'ports':
        return row.portsText;
      case 'lastSeen':
        return normalizeSpaces(formatRelativeTime(row.host.last_seen, Date.now()));
    }
  }

  function rowClass(row: HostRow): readonly string[] {
    const dim = row.pending || row.stale || row.hidden;
    return ROW_CLASSES[Number(row.isNew) + 2 * Number(dim)];
  }

  function sameSort(a: ListViewSort | null, b: ListViewSort): boolean {
    return a !== null && a.column === b.column && a.order === b.order;
  }

  onMount(() => {
    let model: HostModel | null = null;
    let frame = 0;
    let list: OsmiumListView<HostRow> | null = null;
    /** The next rows come in a new order: back to the top, then to the
     * selection (Osmium's "top"). */
    let newOrder = false;

    const stopModel = hostModel.subscribe((m) => {
      model = m;
      if (list && !frame) frame = requestAnimationFrame(applyFrame);
    });

    const startUi = get(ui);
    const view = mountListView<HostRow>(host, {
      label: 'Hosts',
      columns: listColumns(startUi.columnWidths),
      primary: 'name',
      highlight: 'label',
      resize: 'drag',
      scrollbars: 'both',
      sortOrderButton: 'shown',
      rendering: 'auto',
      sort: startUi.listSort,
      key: (row) => row.ip,
      cell,
      icon: (row) => ({ image: row.icon.small, label: row.icon.label }),
      rowClass,
      typeSelect: (row) => row.listName,
      onSelect: (ip) => scanStore.setSelectedHost(ip),
      onOpen: (ip) => void openHost(ip),
      onContextMenu: (ip, e) => openHostMenu(ip, rowMenuPoint(e)),
      onSort: (sort) => {
        newOrder = true;
        ui.setListSort(sort);
        flush();
      },
      // Osmium reports only the dragged column, but its first drag fixes
      // them all: store every width (ui validates the ids).
      onColumnResize: () => ui.setColumnWidths(view.columnWidths)
    });
    list = view;

    const grid = host.querySelector<HTMLElement>('.osm-lv-grid')!;
    const scroller = host.querySelector<HTMLElement>('.osm-lv-body > .osm-list-view')!;

    function apply(m: HostModel): void {
      view.setLoadingText(m.loadingText);
      view.setEmptyText(m.emptyText);
      view.setLoading(m.loading ? 'loading' : 'loaded');
      view.setRows(m.rows, { scroll: newOrder ? 'top' : 'anchor' });
      newOrder = false;
      markSelection();
    }

    /** Without a listed selection nothing marks the keyboard's place in
     * the list: the CSS below rings the grid then. */
    function markSelection(): void {
      const ip = get(scanStore).selectedHostIp;
      const listed = ip !== null && view.rows.some((row) => row.ip === ip);
      host.classList.toggle('lan-unselected', !listed);
    }

    function applyFrame(): void {
      frame = 0;
      if (model) apply(model);
    }

    /** Hand over rows still waiting for the frame now (callers change
     * the stores and use the view in the same task; views.ts). */
    function flush(): void {
      if (!frame) return;
      cancelAnimationFrame(frame);
      applyFrame();
    }

    /** Where a contextual menu for a row goes: at the pointer, or for a
     * request from the keyboard (aimed at the grid), under the selected
     * row's name, as the Osmium Finder demo does. */
    function rowMenuPoint(e: MouseEvent): MenuPoint {
      if (e.target instanceof Element && e.target.closest('.osm-lv-row')) return { x: e.clientX, y: e.clientY };
      return underSelectedName() ?? { x: e.clientX, y: e.clientY };
    }

    function underSelectedName(): MenuPoint | null {
      const label = host.querySelector('.osm-lv-row.osm-selected .osm-lv-label');
      const r = label?.getBoundingClientRect();
      return r ? { x: r.left, y: r.bottom } : null;
    }

    /** Scroll `ip`'s row into view without selecting it. Osmium scrolls
     * only to its selection (select() of the selected key reveals it);
     * this does the same arithmetic on the scroller (listview.ts). */
    function revealRow(ip: string): void {
      if (view.selected === ip) {
        view.select(ip, 'silent');
        return;
      }

      const index = view.rows.findIndex((row) => row.ip === ip);
      if (index < 0) return;
      const top = index * LIST_ROW_H;
      if (top < scroller.scrollTop) scroller.scrollTop = top;
      else if (top + LIST_ROW_H > scroller.scrollTop + scroller.clientHeight)
        scroller.scrollTop = top + LIST_ROW_H - scroller.clientHeight;
    }

    // Control-click or right-click on empty space (below the rows, or on
    // the placeholder), or the menu key with nothing selected: the view
    // menu (3.3). Added after mountListView so Osmium's own listener on
    // this element, which takes the rows' requests and calls
    // preventDefault, runs first. Headers and scroll bars are left to
    // the page's guard.
    const onContextMenu = (e: MouseEvent) => {
      if (e.defaultPrevented || !(e.target instanceof Element)) return;
      const t = e.target;
      const fromKeyboard = t === grid;
      if (!fromKeyboard && !t.closest('.osm-list-view, .osm-lv-empty')) return;

      e.preventDefault();
      const r = scroller.getBoundingClientRect();
      openViewMenu(fromKeyboard ? { x: r.left, y: r.top } : { x: e.clientX, y: e.clientY });
    };
    host.addEventListener('contextmenu', onContextMenu);
    // Linux sends no contextmenu event for Control-click on the rows or
    // the space below them: make one (contextMenus.ts).
    const stopControlClick = installControlClick(host, grid, '.osm-list-view, .osm-lv-empty');

    // The menu key and Shift-F10 (3.2). Osmium's list answers only the
    // contextmenu event browsers send for them, and WebKit (WKWebView,
    // WebKitGTK) sends none, so the list opens the menu from the key:
    // the selected row's under its name, else the view's. The one
    // contextmenu event that follows the key (Chromium) is dropped before
    // Osmium's listener and the one above see it; a right-click or
    // Control-click starts with a press, which ends the wait for it.
    const keyMenu = keyMenuWait();
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.isComposing || e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key !== 'ContextMenu' && !(e.key === 'F10' && e.shiftKey)) return;

      e.preventDefault();
      keyMenu.keyPressed();
      flush();
      const ip = view.selected;
      if (ip !== null && view.rows.some((row) => row.ip === ip)) {
        revealRow(ip);
        openHostMenu(ip, underSelectedName() ?? gridCorner());
        return;
      }
      openViewMenu(gridCorner());
    };
    const dropKeyMenuEvent = (e: MouseEvent) => {
      if (keyMenu.takeKeyEvent()) e.preventDefault();
    };
    const endKeyMenuWait = () => keyMenu.pressed();
    grid.addEventListener('keydown', onKeyDown);
    host.addEventListener('contextmenu', dropKeyMenuEvent, true);
    host.addEventListener('pointerdown', endKeyMenuWait, true);

    function gridCorner(): MenuPoint {
      const r = scroller.getBoundingClientRect();
      return { x: r.left, y: r.top };
    }

    apply(get(hostModel));
    let selection = get(scanStore).selectedHostIp;
    view.select(selection, 'silent');

    // The store's selection changes elsewhere too (the menus, Find's
    // Return, hiding the host). Follow only real changes: comparing
    // with the list on every store update would undo a press that is
    // still moving the selection (reported on release).
    const stopStore = scanStore.subscribe((s) => {
      if (s.selectedHostIp === selection) return;
      selection = s.selectedHostIp;
      if (view.selected !== selection) view.select(selection, 'silent');
      markSelection();
    });

    const stopUi = ui.subscribe((u) => {
      if (sameSort(view.sort, u.listSort)) return;
      newOrder = true;
      view.setSort(u.listSort);
    });

    // Switching views keeps the keyboard in the view: the page swaps the
    // views on Svelte's next update (activeView is still this view's
    // until then), so the next view takes it after tick().
    let mode = startUi.viewMode;
    const stopMode = ui.subscribe((u) => {
      if (u.viewMode === mode) return;
      mode = u.viewMode;
      if (host.contains(document.activeElement)) void tick().then(() => get(activeView)?.focus());
    });

    const timer = setInterval(() => view.refresh(), REFRESH_MS);

    // Balloon Help (4.5) on Osmium's parts: the grid, each sortable
    // header and the sort order button (markup of listview.ts).
    // The grid's tip is a large area's (osm/actions.ts, AREA_TIP).
    const balloons: OsmiumBalloon[] = [attachBalloon(grid, { content: HOST_LIST_BALLOON, ...AREA_TIP })];
    for (const c of COLUMNS) {
      const head = host.querySelector<HTMLElement>(`[data-column="${c.id}"] > .osm-colhead`);
      if (head) balloons.push(attachBalloon(head, { content: columnBalloon(c.id) }));
    }
    const sortButton = host.querySelector<HTMLElement>('.osm-lv-sortdir');
    if (sortButton) {
      balloons.push(attachBalloon(sortButton, { content: SORT_ORDER_BALLOON }));
      pressOnceOnReturn(sortButton);
    }

    const api: HostViewApi = {
      element: grid,
      focus() {
        flush();
        view.focus();
      },
      reveal(ip) {
        flush();
        revealRow(ip);
      },
      extraHeight() {
        flush();
        return Math.max(0, view.contentHeight - view.viewportHeight);
      },
      idealColumnsWidth() {
        if (!get(ui).columnWidths) return BASE_COLUMNS_WIDTH;
        return Object.values(view.columnWidths).reduce((sum, w) => sum + w, 0);
      }
    };
    activeView.set(api);

    return () => {
      if (get(activeView) === api) activeView.set(null);
      stopModel();
      stopStore();
      stopUi();
      stopMode();
      clearInterval(timer);
      if (frame) cancelAnimationFrame(frame);
      host.removeEventListener('contextmenu', onContextMenu);
      stopControlClick();
      host.removeEventListener('contextmenu', dropKeyMenuEvent, true);
      host.removeEventListener('pointerdown', endKeyMenuWait, true);
      grid.removeEventListener('keydown', onKeyDown);
      for (const b of balloons) b.detach();
      view.destroy();
    };
  });
</script>

<div
  class="lan-list"
  bind:this={host}
  style:--lan-star-off={STAR.off}
  style:--lan-star-on={STAR.on}
  style:--lan-star-header={STAR.header}
></div>

<style>
  /* Edge to edge, as in Osmium's Finder demo: the view's right edge and
     the window's content frame draw the black lines. */
  .lan-list {
    border: 0;
  }

  /* Edge to edge, Osmium's focus ring would show only in part; the
     selected name marks the keyboard's place (Osmium's Finder demo).
     With no row selected (Tab into the list, the selected host hidden)
     the ring is drawn inside the edges instead (WCAG 2.4.7). */
  :global(.osm-kbd) .lan-list :global(.osm-lv-grid:focus-visible) {
    outline: none;
  }

  /* Over the rows and the scroll bars, which would cover an outline of
     the grid (they are positioned). Above their arrow boxes too, which
     osmium.css stacks at z-index 2 in the same stacking context. */
  :global(.osm-kbd) .lan-list:global(.lan-unselected) :global(.osm-lv-grid:focus-visible .osm-lv-body::after) {
    content: '';
    position: absolute;
    inset: 0;
    z-index: 3;
    box-shadow: inset 0 0 0 2px var(--osm-focus-ring);
    pointer-events: none;
  }

  /* The 11 x 11 star (2.6), 5px into its 22px column and 3px down its
     18px cell (not measured: Mac OS 8 had no star column). */
  .lan-list :global(.lan-star) {
    display: block;
    width: 11px;
    height: 11px;
    margin: 1px 0 0 1px;
    padding: 0;
    border: 0;
    background: var(--lan-star-off) 0 0 no-repeat;
    appearance: none;
    -webkit-appearance: none;
    outline: none;
    cursor: default;
  }

  .lan-list :global(.lan-star[aria-pressed='true']) {
    background-image: var(--lan-star-on);
  }

  /* A pressed star darkens, as a pressed icon does. */
  .lan-list :global(.lan-star.osm-pressed) {
    filter: brightness(0.5);
  }

  /* The header's star, in line with the rows' stars and centered in
     the 21px header. It fills the header button's 13px content height,
     which the button would otherwise center on a half pixel. */
  .lan-list :global(.lan-star-head) {
    display: block;
    width: 11px;
    height: 13px;
    margin-left: 1px;
    background: var(--lan-star-header) 0 1px no-repeat;
  }

  /* 2.6: new hosts' names bold; pending, stale and shown-hidden rows in
     gray. Only text changes, so the row shading and the sorted column
     stay Osmium's. */
  .lan-list :global(.lan-new .osm-lv-label) {
    font-weight: 700;
  }

  .lan-list :global(.lan-dim .osm-lv-cell) {
    color: #888;
  }
</style>
