<script lang="ts">
  import type { Host } from '$lib/types';

  export let hosts: Host[] = [];
  export let loading = false;
  export let selectedHostIp: string | null = null;
  export let favoriteIps: string[] = [];
  export let staleFavoriteIps: string[] = [];
  export let onSelectHost: ((ip: string) => void) | undefined = undefined;
  export let onToggleFavorite: ((ip: string) => void) | undefined = undefined;

  type SortField = 'ip' | 'favorite' | 'name' | 'fingerprint' | 'ports' | 'lastSeen';
  type SortDirection = 'asc' | 'desc';

  interface IconInfo {
    symbol: string;
    label: string;
  }

  let sortField: SortField = 'ip';
  let sortDirection: SortDirection = 'asc';

  const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });

  $: favoriteSet = new Set(favoriteIps);
  $: staleFavoriteSet = new Set(staleFavoriteIps);

  $: sortedHosts = [...hosts].sort((a, b) => {
    const result = compareHosts(a, b, sortField, favoriteSet);
    if (result !== 0) {
      return sortDirection === 'asc' ? result : -result;
    }

    return ipToNumber(a.ip) - ipToNumber(b.ip);
  });

  function setSort(field: SortField) {
    if (sortField === field) {
      sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
      return;
    }

    sortField = field;
    sortDirection = 'asc';
  }

  function ipToNumber(ip: string): number {
    const parts = ip.split('.').map((part) => Number(part));
    if (parts.length !== 4 || parts.some((part) => Number.isNaN(part))) {
      return Number.MAX_SAFE_INTEGER;
    }

    return parts[0] * 256 ** 3 + parts[1] * 256 ** 2 + parts[2] * 256 + parts[3];
  }

  function dateToNumber(iso: string): number {
    if (!iso) {
      return 0;
    }

    const timestamp = Date.parse(iso);
    if (Number.isNaN(timestamp)) {
      return 0;
    }
    return timestamp;
  }

  function compareHosts(a: Host, b: Host, field: SortField, favorites: Set<string>): number {
    switch (field) {
      case 'ip':
        return ipToNumber(a.ip) - ipToNumber(b.ip);
      case 'favorite':
        return Number(favorites.has(b.ip)) - Number(favorites.has(a.ip));
      case 'name':
        return collator.compare(a.name || '', b.name || '');
      case 'fingerprint':
        return collator.compare(formatFingerprint(a), formatFingerprint(b));
      case 'ports':
        return a.open_ports.length - b.open_ports.length;
      case 'lastSeen':
        return dateToNumber(a.last_seen) - dateToNumber(b.last_seen);
      default:
        return 0;
    }
  }

  function formatPorts(host: Host): string {
    if (host.open_ports.length === 0) {
      return '-';
    }

    const labels = host.open_ports.slice(0, 5).map((port) => {
      if (port.service) {
        return `${port.port} (${port.service})`;
      }
      return String(port.port);
    });

    if (host.open_ports.length > 5) {
      labels.push(`+${host.open_ports.length - 5}`);
    }

    return labels.join(', ');
  }

  function formatTime(iso: string): string {
    if (!iso) {
      return '-';
    }

    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) {
      return '-';
    }

    return date.toLocaleTimeString();
  }

  function formatFingerprint(host: Host): string {
    const fp = host.fingerprint;
    if (!fp) {
      return 'Not fingerprinted yet';
    }

    const vendor = fp.vendor || fp.manufacturer || 'Unknown vendor';
    const kind = fp.device_type || fp.os_guess || fp.model_guess || 'Unknown type';
    const confidence = Number.isFinite(fp.confidence) ? `${fp.confidence}%` : 'n/a';

    return `${vendor} • ${kind} (${confidence})`;
  }

  function toggleFavorite(event: MouseEvent, ip: string) {
    event.stopPropagation();
    onToggleFavorite?.(ip);
  }

  function favoriteLabel(ip: string): string {
    return favoriteSet.has(ip) ? `Unfavorite ${ip}` : `Favorite ${ip}`;
  }

  function getTypeIcon(host: Host): IconInfo {
    const source = `${host.fingerprint?.device_type || ''} ${host.fingerprint?.model_guess || ''} ${host.name || ''}`.toLowerCase();

    if (source.includes('router') || source.includes('gateway') || source.includes('modem') || source.includes('access point') || source.includes('switch') || source.includes('firewall')) {
      return { symbol: '\u{1F4E1}', label: 'Network device' };
    }

    if (source.includes('phone') || source.includes('mobile') || source.includes('tablet')) {
      return { symbol: '\u{1F4F1}', label: 'Mobile device' };
    }

    if (source.includes('camera')) {
      return { symbol: '\u{1F4F7}', label: 'Camera' };
    }

    if (source.includes('printer')) {
      return { symbol: '\u{1F5A8}', label: 'Printer' };
    }

    if (source.includes('tv') || source.includes('media')) {
      return { symbol: '\u{1F4FA}', label: 'TV / media device' };
    }

    if (source.includes('nas') || source.includes('server') || source.includes('storage')) {
      return { symbol: '\u{1F5C4}', label: 'Server / storage' };
    }

    if (source.includes('iot') || source.includes('smart')) {
      return { symbol: '\u{1F50C}', label: 'IoT device' };
    }

    if (source.includes('laptop') || source.includes('notebook')) {
      return { symbol: '\u{1F4BB}', label: 'Laptop' };
    }

    return { symbol: '\u{1F5A5}', label: 'Computer' };
  }

  function getOsIcon(host: Host): IconInfo {
    const os = (host.fingerprint?.os_guess || '').toLowerCase();

    if (os.includes('windows')) {
      return { symbol: '\u{1FA9F}', label: 'Windows' };
    }

    if (os.includes('mac') || os.includes('ios') || os.includes('darwin')) {
      return { symbol: '\u{1F34E}', label: 'Apple OS' };
    }

    if (os.includes('linux') || os.includes('ubuntu') || os.includes('debian') || os.includes('fedora') || os.includes('centos') || os.includes('arch')) {
      return { symbol: '\u{1F427}', label: 'Linux' };
    }

    if (os.includes('android')) {
      return { symbol: '\u{1F916}', label: 'Android' };
    }

    if (os.includes('bsd') || os.includes('unix')) {
      return { symbol: '\u2699', label: 'Unix / BSD' };
    }

    return { symbol: '\u25A1', label: 'Unknown OS' };
  }
</script>

<div class="table-wrap">
  <div class="table-header-container">
    <table>
      <thead>
        <tr>
          <th class="col-ip">
            <div class="ip-header">
              <button
                type="button"
                class="sort-button"
                class:sorted={sortField === 'ip'}
                onclick={() => setSort('ip')}
              >
                IP
              </button>

              <button
                type="button"
                class="favorite-sort"
                class:sorted={sortField === 'favorite'}
                onclick={() => setSort('favorite')}
                aria-label="Sort by favorites"
                title="Sort by favorites"
              >
                <svg viewBox="0 0 16 16" role="img" focusable="false" aria-hidden="true">
                  <path d="M8 1.5l2 4 4.5.6-3.3 3.1.8 4.8L8 12l-4 2 0.8-4.8L1.5 6.1l4.5-.6L8 1.5z" />
                </svg>
              </button>
            </div>
          </th>
          <th class="col-name">
            <button
              type="button"
              class="sort-button"
              class:sorted={sortField === 'name'}
              onclick={() => setSort('name')}
            >
              Name
            </button>
          </th>
          <th class="col-fingerprint">
            <button
              type="button"
              class="sort-button"
              class:sorted={sortField === 'fingerprint'}
              onclick={() => setSort('fingerprint')}
            >
              Fingerprint
            </button>
          </th>
          <th class="col-ports">
            <button
              type="button"
              class="sort-button"
              class:sorted={sortField === 'ports'}
              onclick={() => setSort('ports')}
            >
              Open Ports
            </button>
          </th>
          <th class="col-seen">
            <button
              type="button"
              class="sort-button"
              class:sorted={sortField === 'lastSeen'}
              onclick={() => setSort('lastSeen')}
            >
              Last Seen
            </button>
          </th>
        </tr>
      </thead>
    </table>
  </div>

  <div class="table-body-container">
    <table>
      <tbody>
        {#if loading && hosts.length === 0}
          <tr>
            <td colspan="5" class="placeholder">Scanning...</td>
          </tr>
        {:else if hosts.length === 0}
          <tr>
            <td colspan="5" class="placeholder">No hosts yet. Start a scan.</td>
          </tr>
        {:else}
          {#each sortedHosts as host}
            {@const typeIcon = getTypeIcon(host)}
            {@const osIcon = getOsIcon(host)}

            <!-- svelte-ignore a11y-click-events-have-key-events -->
            <!-- svelte-ignore a11y-no-static-element-interactions -->
            <tr
              class:selected={selectedHostIp === host.ip}
              class:stale={staleFavoriteSet.has(host.ip)}
              onclick={() => onSelectHost?.(host.ip)}
            >
              <td class="col-ip">
                <div class="ip-cell">
                  <button
                    type="button"
                    class="favorite-toggle"
                    class:active={favoriteSet.has(host.ip)}
                    aria-label={favoriteLabel(host.ip)}
                    title={favoriteLabel(host.ip)}
                    onclick={(event) => toggleFavorite(event, host.ip)}
                  >
                    <svg viewBox="0 0 16 16" role="img" focusable="false" aria-hidden="true">
                      <path d="M8 1.5l2 4 4.5.6-3.3 3.1.8 4.8L8 12l-4 2 0.8-4.8L1.5 6.1l4.5-.6L8 1.5z" />
                    </svg>
                  </button>
                  <span class="ip-text">{host.ip}</span>
                </div>
              </td>
              <td class="col-name">
                <div class="name-cell">
                  <span class="host-icons" title={`${typeIcon.label}, ${osIcon.label}`}>
                    <span class="host-icon">{typeIcon.symbol}</span>
                    <span class="host-icon">{osIcon.symbol}</span>
                  </span>
                  <span class="host-name">{host.name || 'Unknown'}</span>
                </div>
              </td>
              <td class="col-fingerprint">{formatFingerprint(host)}</td>
              <td class="col-ports">{formatPorts(host)}</td>
              <td class="col-seen">{formatTime(host.last_seen)}</td>
            </tr>
          {/each}
        {/if}
      </tbody>
    </table>
  </div>
</div>

<style>
  .table-wrap {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    min-height: 0;
  }

  .table-header-container {
    padding-right: 16px;
    border-bottom: 1.5px solid #000;
  }

  .table-body-container {
    flex: 1;
    overflow-y: scroll;
    overflow-x: hidden;
    min-height: 0;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    table-layout: fixed;
  }

  th,
  td {
    text-align: left;
    border-bottom: 1px dotted #000;
    padding: 6px 8px;
    vertical-align: middle;
  }

  td {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  th {
    font-weight: normal;
    border-bottom: none;
  }

  .sort-button {
    border: none;
    background: transparent;
    color: inherit;
    font-family: inherit !important;
    font-size: inherit !important;
    font-weight: inherit !important;
    letter-spacing: normal !important;
    font-feature-settings: normal !important;
    line-height: inherit;
    padding: 0;
    cursor: pointer;
    text-decoration: none;
  }

  .sort-button.sorted {
    text-decoration: underline;
  }

  .ip-header {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .favorite-sort,
  .favorite-toggle {
    border: 1px solid transparent;
    background: transparent;
    color: inherit;
    padding: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
  }

  .favorite-sort {
    width: 14px;
    height: 14px;
  }

  .favorite-toggle {
    width: 16px;
    height: 16px;
    flex: 0 0 auto;
  }

  .favorite-sort svg,
  .favorite-toggle svg {
    width: 100%;
    height: 100%;
    fill: none;
    stroke: #000;
    stroke-width: 1.1;
    stroke-linejoin: round;
  }

  .favorite-sort.sorted svg,
  .favorite-sort:hover svg,
  .favorite-toggle.active svg,
  .favorite-toggle:hover svg {
    fill: #000;
  }

  .col-ip {
    width: 140px;
    min-width: 140px;
    max-width: 140px;
  }

  .col-name {
    width: 25%;
  }

  .col-fingerprint {
    width: 32%;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .col-ports {
    width: auto;
  }

  .col-seen {
    width: 100px;
    min-width: 100px;
    max-width: 100px;
  }

  .ip-cell,
  .name-cell {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
  }

  .ip-text,
  .host-name {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .host-icons {
    display: inline-flex;
    align-items: center;
    gap: 2px;
    flex: 0 0 auto;
  }

  .host-icon {
    width: 14px;
    display: inline-flex;
    justify-content: center;
    align-items: center;
    line-height: 1;
  }

  tr {
    cursor: pointer;
  }

  tr.stale td {
    color: #777;
  }

  tr:hover td {
    background: #000;
    color: #fff;
  }

  tr.selected td {
    background: #000;
    color: #fff;
  }

  tr:hover .favorite-sort svg,
  tr:hover .favorite-toggle svg,
  tr.selected .favorite-toggle svg {
    stroke: #fff;
  }

  tr:hover .favorite-toggle.active svg,
  tr.selected .favorite-toggle.active svg {
    fill: #fff;
  }

  .placeholder {
    text-align: center;
    color: #666;
    font-style: italic;
    padding: 24px 8px;
  }
</style>
