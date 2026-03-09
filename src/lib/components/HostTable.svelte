<script lang="ts">
  import { BalloonHelp, Button } from '@lkmc/system7-ui';
  import type { Host } from '$lib/types';

  export let hosts: Host[] = [];
  export let loading = false;
  export let selectedHostIp: string | null = null;
  export let onSelectHost: ((ip: string) => void) | undefined = undefined;
  export let onDeepScan: ((ip: string) => void) | undefined = undefined;

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
          <th class="col-ip">IP</th>
          <th class="col-name">Name</th>
          <th class="col-fingerprint">Fingerprint</th>
          <th class="col-ports">Open Ports</th>
          <th class="col-seen">Last Seen</th>
          <th class="col-actions">Actions</th>
        </tr>
      </thead>
    </table>
  </div>

  <div class="table-body-container">
    <table>
      <tbody>
        {#if loading && hosts.length === 0}
          <tr>
            <td colspan="6" class="placeholder">Scanning...</td>
          </tr>
        {:else if hosts.length === 0}
          <tr>
            <td colspan="6" class="placeholder">No hosts yet. Start a scan.</td>
          </tr>
        {:else}
          {#each hosts as host}
            <!-- svelte-ignore a11y-click-events-have-key-events -->
            <!-- svelte-ignore a11y-no-static-element-interactions -->
            <tr class:selected={selectedHostIp === host.ip} onclick={() => onSelectHost?.(host.ip)}>
              <td class="col-ip">{host.ip}</td>
              <td class="col-name">{host.name || 'Unknown'}</td>
              <td class="col-fingerprint">{formatFingerprint(host)}</td>
              <td class="col-ports">{formatPorts(host)}</td>
              <td class="col-seen">{formatTime(host.last_seen)}</td>
              <td class="col-actions">
                <BalloonHelp message="Run a deeper scan for this host">
                  <Button onclick={() => onDeepScan?.(host.ip)}>Deep Scan</Button>
                </BalloonHelp>
              </td>
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

  th {
    text-decoration: underline;
    font-weight: normal;
  }

  .col-ip {
    width: 14%;
  }

  .col-name {
    width: 17%;
  }

  .col-fingerprint {
    width: 24%;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .col-ports {
    width: 25%;
  }

  .col-seen {
    width: 10%;
  }

  .col-actions {
    width: 10%;
    text-align: right;
  }

  tr {
    cursor: pointer;
  }

  tr:hover td {
    background: #000;
    color: #fff;
  }

  tr:hover :global(.sys7-btn) {
    border-color: #fff;
  }

  tr.selected td {
    background: #000;
    color: #fff;
  }

  tr.selected :global(.sys7-btn) {
    border-color: #fff;
  }

  .placeholder {
    text-align: center;
    color: #666;
    font-style: italic;
    padding: 24px 8px;
  }
</style>
