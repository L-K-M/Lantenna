<script lang="ts">
  import type { Host } from '$lib/types';

  export let hosts: Host[] = [];
  export let loading = false;
  export let selectedHostIp: string | null = null;
  export let onSelectHost: ((ip: string) => void) | undefined = undefined;

  type SortField = 'ip' | 'name' | 'fingerprint' | 'ports' | 'lastSeen';
  type SortDirection = 'asc' | 'desc';

  let sortField: SortField = 'ip';
  let sortDirection: SortDirection = 'asc';

  const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });

  $: sortedHosts = [...hosts].sort((a, b) => {
    const result = compareHosts(a, b, sortField);
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
    const timestamp = Date.parse(iso);
    if (Number.isNaN(timestamp)) {
      return 0;
    }
    return timestamp;
  }

  function compareHosts(a: Host, b: Host, field: SortField): number {
    switch (field) {
      case 'ip':
        return ipToNumber(a.ip) - ipToNumber(b.ip);
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
    const date = new Date(iso);
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
</script>

<div class="table-wrap">
  <div class="table-header-container">
    <table>
      <thead>
        <tr>
          <th class="col-ip">
            <button
              type="button"
              class="sort-button"
              class:sorted={sortField === 'ip'}
              onclick={() => setSort('ip')}
            >
              IP
            </button>
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
            <!-- svelte-ignore a11y-click-events-have-key-events -->
            <!-- svelte-ignore a11y-no-static-element-interactions -->
            <tr class:selected={selectedHostIp === host.ip} onclick={() => onSelectHost?.(host.ip)}>
              <td class="col-ip">{host.ip}</td>
              <td class="col-name">{host.name || 'Unknown'}</td>
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
    border-bottom: 1px solid #000;
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

  .col-ip {
    width: 16%;
  }

  .col-name {
    width: 18%;
  }

  .col-fingerprint {
    width: 30%;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .col-ports {
    width: 24%;
  }

  .col-seen {
    width: 12%;
  }

  tr {
    cursor: pointer;
  }

  tr:hover td {
    background: #000;
    color: #fff;
  }

  tr.selected td {
    background: #000;
    color: #fff;
  }

  .placeholder {
    text-align: center;
    color: #666;
    font-style: italic;
    padding: 24px 8px;
  }
</style>
