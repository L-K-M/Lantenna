<!--
  Owner: unit C (spec 8.4). Spec: 2.7 (Ports), 3.1 (1.17, 1.18), 3.2,
  3.3 (Ports row double-click, Return).
  The Ports panel for `row` (null: no selection): an Osmium list view of
  the host's open ports and a three-line caption for the selected port.
  Double-click or Return on a port with a target opens its URL.
  The root element is Osmium-owned once HostInfoPane runs mountTabs:
  static class only, and no display on it. The list's host belongs to
  mountListView.
-->
<svelte:options runes={true} />

<script module lang="ts">
  import type { ListViewSort } from 'osmium-ui';
  import type { Host } from '$lib/types';
  import { getPortTarget, type PortTarget } from '$lib/util/portTargets';

  /** One list row; immutable, cached per Host so an unchanged host keeps
   * its row objects (the list skips rows that are ===). */
  export interface PortRow {
    readonly key: string;
    readonly port: number;
    readonly service: string;
    readonly banner: string;
    readonly target: PortTarget | null;
  }

  const rowCache = new WeakMap<Host, readonly PortRow[]>();

  /** The host's open ports as rows, one per port number (the list needs
   * unique keys). */
  export function portRows(host: Host): readonly PortRow[] {
    const cached = rowCache.get(host);
    if (cached) return cached;

    const seen = new Set<number>();
    const rows: PortRow[] = [];
    for (const p of host.open_ports) {
      if (seen.has(p.port)) continue;
      seen.add(p.port);
      rows.push({
        key: String(p.port),
        port: p.port,
        service: p.service || 'unknown',
        banner: p.banner ?? '',
        target: getPortTarget(host.ip, p.port, p.service)
      });
    }

    rowCache.set(host, rows);
    return rows;
  }

  /** Port: ascending; Service: A to Z, ties by port. Reversed turns the
   * whole order over (Osmium's sort semantics). */
  export function sortPortRows(rows: readonly PortRow[], sort: ListViewSort): PortRow[] {
    const byPort = (a: PortRow, b: PortRow) => a.port - b.port;
    const compare =
      sort.column === 'service'
        ? (a: PortRow, b: PortRow) => a.service.localeCompare(b.service) || byPort(a, b)
        : byPort;
    const sorted = [...rows].sort(compare);
    return sort.order === 'reversed' ? sorted.reverse() : sorted;
  }

  /** The caption's three lines (2.7), or the prompt without a port. */
  export function portCaption(p: PortRow | null): readonly string[] {
    if (!p) return ['Select a port to see its banner.'];

    return [
      `${p.port} ${p.service}`,
      p.banner || 'No banner.',
      p.target ? `Opens ${p.target.url}.` : 'Lantenna can’t open this service.'
    ];
  }
</script>

<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { attachBalloon, centerText, mountListView, type ListViewColumn, type OsmiumListView } from 'osmium-ui';
  import { openUrl } from '$lib/app/actions';
  import { PORTS_BALLOON } from '$lib/app/balloonTexts';
  import { AREA_TIP } from '$lib/osm/actions';
  import type { HostRow } from '$lib/app/hostModel';
  import { scanProgress } from '$lib/util/scanStore';

  let { row }: { row: HostRow | null } = $props();

  const COLUMNS: readonly ListViewColumn[] = [
    { id: 'port', title: 'Port', width: 44, align: 'right', sort: 'ascending' },
    { id: 'service', title: 'Service', width: 80, sort: 'ascending' },
    { id: 'opens', title: 'Opens', width: 50 },
    { id: 'banner', title: 'Banner', width: 60, grow: 1 }
  ];

  let listHost: HTMLDivElement;
  let list: OsmiumListView<PortRow> | null = null;
  /** The sort the reader picked; kept from host to host. */
  let sort: ListViewSort = { column: 'port', order: 'normal' };
  /** Whose ports the list shows, so a new host starts unselected. */
  let listedIp: string | null = null;

  let selectedKey: string | null = $state(null);

  const rows = $derived(row ? portRows(row.host) : []);
  const scanning = $derived(
    row !== null &&
      $scanProgress.hostScanProgress?.running === true &&
      $scanProgress.hostScanProgress.current_ip === row.ip
  );
  const selected = $derived(rows.find((p) => p.key === selectedKey) ?? null);
  const caption = $derived(rows.length > 0 ? portCaption(selected) : []);

  function cell(p: PortRow, column: ListViewColumn): string {
    switch (column.id) {
      case 'port':
        return String(p.port);
      case 'service':
        return p.service;
      case 'opens':
        return p.target?.label ?? '';
      default:
        return p.banner;
    }
  }

  function open(key: string): void {
    const target = rows.find((p) => p.key === key)?.target;
    if (target) void openUrl(target.url);
  }

  function show(next: readonly PortRow[], ip: string | null, loading: boolean): void {
    if (!list) return;

    const newHost = ip !== listedIp;
    listedIp = ip;
    if (newHost) {
      list.select(null, 'silent');
      selectedKey = null;
    }

    list.setRows(sortPortRows(next, sort), { scroll: newHost ? 'top' : 'anchor' });
    list.setLoading(loading && next.length === 0 ? 'loading' : 'loaded');
  }

  onMount(() => {
    list = mountListView<PortRow>(listHost, {
      label: 'Open ports',
      columns: COLUMNS,
      key: (p) => p.key,
      cell,
      highlight: 'row',
      scrollbars: 'vertical',
      sort,
      emptyText: 'No open ports found.',
      loadingText: 'Scanning ports…',
      onSelect: (key) => (selectedKey = key),
      onOpen: open,
      onSort: (next) => {
        sort = next;
        list?.setRows(sortPortRows(rows, sort), { scroll: 'top' });
      }
    });

    const grid = listHost.querySelector<HTMLElement>('.osm-lv-grid');
    // The list's tip is a large area's (osm/actions.ts, AREA_TIP).
    const help = grid ? attachBalloon(grid, { content: PORTS_BALLOON, trigger: 'balloon-help', ...AREA_TIP }) : null;

    show(rows, row?.ip ?? null, scanning);

    return () => {
      help?.detach();
      list?.destroy();
      list = null;
    };
  });

  $effect(() => {
    const next = rows;
    const ip = row?.ip ?? null;
    const loading = scanning;
    untrack(() => show(next, ip, loading));
  });

  // A long banner wraps and the list gets shorter: keep the selected
  // port in view (Osmium reveals its selection when it is selected
  // again).
  $effect(() => {
    const key = selected?.key ?? null;
    void caption;
    if (key === null) return;
    untrack(() => list?.select(key, 'silent'));
  });

  function centered(node: HTMLElement): void {
    centerText(node);
  }
</script>

<div class="lan-info-ports">
  <div class="lan-none osm-small" hidden={row !== null} use:centered>Select a host to see its information.</div>

  <div class="lan-body" hidden={row === null}>
    <div class="lan-ports" bind:this={listHost}></div>
    <div class="lan-caption osm-small">
      {#each caption as line, i (i)}
        <div class="lan-line" class:osm-label={i === 0 && selected !== null} class:lan-banner={i === 1}>{line}</div>
      {/each}
    </div>
  </div>
</div>

<style>
  .lan-info-ports {
    position: absolute;
    inset: 0;
  }

  .lan-none {
    position: absolute;
    left: 0;
    right: 0;
    top: 24px;
    color: #888;
    white-space: nowrap;
    overflow: hidden;
  }

  /* 2.7: the list x 10..right-10, y 12..bottom-54 (osm-listview draws
     the frame), the caption's three lines under it, 7px below; a banner
     that wraps (2.7: the full banner) takes lines from the list. */
  .lan-body {
    position: absolute;
    inset: 0;
    display: flex;
    flex-direction: column;
    padding: 12px 10px 8px;
    box-sizing: border-box;
  }

  .lan-body[hidden] {
    display: none;
  }

  .lan-ports {
    flex: 1 1 0;
    min-height: 0;
  }

  /* At least three Geneva 10 lines. */
  .lan-caption {
    flex: none;
    min-height: 39px;
    margin-top: 7px;
    line-height: 13px;
  }

  .lan-line {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    user-select: text;
    -webkit-user-select: text;
    cursor: text;
  }

  /* The backend keeps 200 characters of a banner, five or six lines. */
  .lan-line.lan-banner {
    white-space: normal;
    overflow-wrap: anywhere;
  }
</style>
