<script lang="ts">
  import type { Host } from '$lib/types';
  import cameraIcon from '$lib/assets/host-icons/camera.svg';
  import iotIcon from '$lib/assets/host-icons/iot.svg';
  import mediaIcon from '$lib/assets/host-icons/media.svg';
  import mobileIcon from '$lib/assets/host-icons/mobile.svg';
  import pcGenericIcon from '$lib/assets/host-icons/pc-generic.svg';
  import pcLinuxIcon from '$lib/assets/host-icons/pc-linux.svg';
  import pcMacIcon from '$lib/assets/host-icons/pc-mac.svg';
  import pcWindowsIcon from '$lib/assets/host-icons/pc-windows.svg';
  import printerIcon from '$lib/assets/host-icons/printer.svg';
  import routerIcon from '$lib/assets/host-icons/router.svg';
  import serverIcon from '$lib/assets/host-icons/server.svg';

  export let hosts: Host[] = [];
  export let loading = false;
  export let selectedHostIp: string | null = null;
  export let customNames: Record<string, string> = {};
  export let favoriteIps: string[] = [];
  export let staleFavoriteIps: string[] = [];
  export let onSelectHost: ((ip: string) => void) | undefined = undefined;
  export let onToggleFavorite: ((ip: string) => void) | undefined = undefined;

  type SortField = 'ip' | 'favorite' | 'name' | 'fingerprint' | 'ports' | 'lastSeen';
  type SortDirection = 'asc' | 'desc';

  interface IconInfo {
    src: string;
    label: string;
  }

  let sortField: SortField = 'favorite';
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
        return collator.compare(displayName(a), displayName(b));
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

  function displayName(host: Host): string {
    const customName = customNames[host.ip]?.trim() || '';
    return customName || host.name || 'Unknown';
  }

  function getHostIcon(host: Host): IconInfo {
    const source = `${host.fingerprint?.device_type || ''} ${host.fingerprint?.model_guess || ''} ${host.name || ''}`.toLowerCase();
    const os = (host.fingerprint?.os_guess || '').toLowerCase();

    if (source.includes('router') || source.includes('gateway') || source.includes('modem') || source.includes('access point') || source.includes('switch') || source.includes('firewall')) {
      return { src: routerIcon, label: 'Network device' };
    }

    if (source.includes('phone') || source.includes('mobile') || source.includes('tablet')) {
      return { src: mobileIcon, label: 'Mobile device' };
    }

    if (source.includes('camera')) {
      return { src: cameraIcon, label: 'Camera' };
    }

    if (source.includes('printer')) {
      return { src: printerIcon, label: 'Printer' };
    }

    if (source.includes('tv') || source.includes('media')) {
      return { src: mediaIcon, label: 'TV / media device' };
    }

    if (source.includes('nas') || source.includes('server') || source.includes('storage')) {
      return { src: serverIcon, label: 'Server / storage' };
    }

    if (source.includes('iot') || source.includes('smart')) {
      return { src: iotIcon, label: 'IoT device' };
    }

    if (os.includes('windows')) {
      return { src: pcWindowsIcon, label: 'Windows host' };
    }

    if (os.includes('mac') || os.includes('ios') || os.includes('darwin')) {
      return { src: pcMacIcon, label: 'Apple host' };
    }

    if (os.includes('linux') || os.includes('ubuntu') || os.includes('debian') || os.includes('fedora') || os.includes('centos') || os.includes('arch')) {
      return { src: pcLinuxIcon, label: 'Linux host' };
    }

    if (os.includes('android')) {
      return { src: mobileIcon, label: 'Android host' };
    }

    if (os.includes('bsd') || os.includes('unix')) {
      return { src: pcLinuxIcon, label: 'Unix / BSD host' };
    }

    return { src: pcGenericIcon, label: 'Unknown host' };
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

              <button
                type="button"
                class="sort-button"
                class:sorted={sortField === 'ip'}
                onclick={() => setSort('ip')}
              >
                IP
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
            {@const hostIcon = getHostIcon(host)}

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
                  <img class="device-icon" src={hostIcon.src} alt="" aria-hidden="true" title={hostIcon.label} />
                  <span class="ip-text">{host.ip}</span>
                </div>
              </td>
              <td class="col-name">
                <span class="host-name">{displayName(host)}</span>
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
    white-space: nowrap;
    overflow: hidden;
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
    display: block;
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    text-align: left;
  }

  .sort-button.sorted {
    text-decoration: underline;
  }

  .ip-header {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
  }

  .ip-header .sort-button {
    flex: 1;
    min-width: 0;
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
    width: 160px;
    min-width: 160px;
    max-width: 160px;
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

  .ip-cell {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
  }

  .device-icon {
    width: 16px;
    height: 16px;
    image-rendering: pixelated;
    flex: 0 0 auto;
  }

  .ip-text,
  .host-name {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
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
