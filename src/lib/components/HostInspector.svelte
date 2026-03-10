<script lang="ts">
  import { BalloonHelp, Button } from '@lkmc/system7-ui';
  import { TauriService } from '$lib/tauri';
  import type { Host } from '$lib/types';
  import { notifications } from '$lib/util/notifications';

  export let host: Host | null = null;
  export let customNames: Record<string, string> = {};
  export let onDeepScan: ((ip: string) => void) | undefined = undefined;
  export let onSetCustomName: ((ip: string, name: string) => void) | undefined = undefined;

  let customNameDraft = '';
  let customNameDraftIp: string | null = null;

  $: selectedCustomName = host ? customNames[host.ip] || '' : '';

  $: if (!host) {
    customNameDraft = '';
    customNameDraftIp = null;
  } else if (customNameDraftIp !== host.ip) {
    customNameDraft = selectedCustomName;
    customNameDraftIp = host.ip;
  }

  interface PortTarget {
    label: 'HTTP' | 'HTTPS' | 'SMB' | 'SSH' | 'FTP' | 'VNC' | 'Telnet' | 'RTSP';
    url: string;
  }

  const httpPorts = new Set([
    80,
    81,
    82,
    88,
    3000,
    3001,
    5000,
    5601,
    7001,
    7080,
    8000,
    8008,
    8080,
    8081,
    8088,
    8090,
    8181,
    8880,
    8888,
    9000,
    9080,
    9090
  ]);
  const httpsPorts = new Set([443, 444, 5443, 6443, 7443, 8443, 8843, 9443, 10443]);
  const smbPorts = new Set([139, 445]);
  const sshPorts = new Set([22, 2222]);
  const ftpPorts = new Set([20, 21, 2121]);
  const vncPorts = new Set([5900, 5901, 5902]);
  const telnetPorts = new Set([23, 2323]);
  const rtspPorts = new Set([554, 8554]);

  function formatTime(iso: string): string {
    if (!iso) {
      return '-';
    }

    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) {
      return '-';
    }

    return date.toLocaleString();
  }

  function getPortTarget(hostIp: string, port: number, service: string | null): PortTarget | null {
    const normalized = (service || '').toLowerCase();
    const buildUrl = (
      scheme: 'http' | 'https' | 'ftp' | 'ssh' | 'telnet' | 'rtsp' | 'vnc',
      defaultPort: number
    ): string =>
      `${scheme}://${hostIp}${port === defaultPort ? '' : `:${port}`}`;

    if (normalized.includes('https') || normalized.includes('ssl/http') || normalized.includes('tls/http')) {
      return { label: 'HTTPS', url: buildUrl('https', 443) };
    }

    if (normalized.includes('http')) {
      return { label: 'HTTP', url: buildUrl('http', 80) };
    }

    if (normalized.includes('smb') || normalized.includes('microsoft-ds') || normalized.includes('netbios')) {
      return { label: 'SMB', url: `smb://${hostIp}` };
    }

    if (normalized.includes('ssh')) {
      return { label: 'SSH', url: buildUrl('ssh', 22) };
    }

    if (normalized.includes('ftp')) {
      return { label: 'FTP', url: buildUrl('ftp', 21) };
    }

    if (normalized.includes('vnc')) {
      return { label: 'VNC', url: buildUrl('vnc', 5900) };
    }

    if (normalized.includes('telnet')) {
      return { label: 'Telnet', url: buildUrl('telnet', 23) };
    }

    if (normalized.includes('rtsp')) {
      return { label: 'RTSP', url: buildUrl('rtsp', 554) };
    }

    if (httpsPorts.has(port)) {
      return { label: 'HTTPS', url: buildUrl('https', 443) };
    }

    if (httpPorts.has(port)) {
      return { label: 'HTTP', url: buildUrl('http', 80) };
    }

    if (smbPorts.has(port)) {
      return { label: 'SMB', url: `smb://${hostIp}` };
    }

    if (sshPorts.has(port)) {
      return { label: 'SSH', url: buildUrl('ssh', 22) };
    }

    if (ftpPorts.has(port)) {
      return { label: 'FTP', url: buildUrl('ftp', 21) };
    }

    if (vncPorts.has(port)) {
      return { label: 'VNC', url: buildUrl('vnc', 5900) };
    }

    if (telnetPorts.has(port)) {
      return { label: 'Telnet', url: buildUrl('telnet', 23) };
    }

    if (rtspPorts.has(port)) {
      return { label: 'RTSP', url: buildUrl('rtsp', 554) };
    }

    return null;
  }

  async function openPortTarget(event: MouseEvent, url: string) {
    event.preventDefault();

    try {
      await TauriService.openExternalUrl(url);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to open link';
      notifications.add(message, 'error');
    }
  }

  function displayName(hostValue: Host): string {
    return customNames[hostValue.ip]?.trim() || hostValue.name || 'Unknown';
  }

  function saveCustomName() {
    if (!host) {
      return;
    }

    customNameDraft = customNameDraft.trim();
    onSetCustomName?.(host.ip, customNameDraft);
  }

  function clearCustomName() {
    if (!host) {
      return;
    }

    customNameDraft = '';
    onSetCustomName?.(host.ip, '');
  }

  function handleCustomNameKeydown(event: KeyboardEvent) {
    if (event.key === 'Enter') {
      event.preventDefault();
      saveCustomName();
    }
  }
</script>

<aside class="inspector">
  {#if host}
    {@const fp = host.fingerprint}
    {@const displayHostName = displayName(host)}
    <h3>Host Details</h3>
    <div class="kv"><span>IP</span><span>{host.ip}</span></div>
    <div class="kv"><span>Name</span><span>{displayHostName}</span></div>
    {#if selectedCustomName && host.name && host.name !== selectedCustomName}
      <div class="kv"><span>Detected Name</span><span>{host.name}</span></div>
    {/if}
    <div class="kv"><span>Reachable</span><span>{host.reachable ? 'Yes' : 'No'}</span></div>
    <div class="kv"><span>Last Seen</span><span>{formatTime(host.last_seen)}</span></div>

    <div class="name-editor">
      <label for="custom-name-input">Custom Name</label>
      <div class="name-editor-controls">
        <input
          id="custom-name-input"
          type="text"
          bind:value={customNameDraft}
          placeholder="Set a friendly device name"
          onkeydown={handleCustomNameKeydown}
        />
        <Button onclick={saveCustomName}>Save</Button>
        {#if selectedCustomName || customNameDraft.trim()}
          <Button onclick={clearCustomName}>Clear</Button>
        {/if}
      </div>
    </div>

    <div class="actions">
      <BalloonHelp message="Run a deeper scan for this host">
        <Button onclick={() => onDeepScan?.(host.ip)}>Deep Scan</Button>
      </BalloonHelp>
    </div>

    <h4>Fingerprint</h4>
    <div class="kv"><span>MAC</span><span>{fp?.mac_address || 'Unknown'}</span></div>
    <div class="kv"><span>Vendor</span><span>{fp?.vendor || fp?.manufacturer || 'Unknown'}</span></div>
    <div class="kv"><span>Type</span><span>{fp?.device_type || 'Unknown'}</span></div>
    <div class="kv"><span>OS</span><span>{fp?.os_guess || 'Unknown'}</span></div>
    <div class="kv"><span>Model</span><span>{fp?.model_guess || 'Unknown'}</span></div>
    <div class="kv"><span>Confidence</span><span>{fp ? `${fp.confidence}%` : 'n/a'}</span></div>

    {#if fp?.sources?.length}
      <h4>Fingerprint Sources</h4>
      <ul class="plain-list">
        {#each fp.sources as source}
          <li class="plain-item">{source}</li>
        {/each}
      </ul>
    {/if}

    {#if fp?.notes?.length}
      <h4>Fingerprint Notes</h4>
      <ul class="plain-list">
        {#each fp.notes as note}
          <li class="plain-item">{note}</li>
        {/each}
      </ul>
    {/if}

    <h4>Open Ports</h4>
    {#if host.open_ports.length === 0}
      <p class="empty">No open ports detected.</p>
    {:else}
      <ul>
        {#each host.open_ports as port}
          {@const target = getPortTarget(host.ip, port.port, port.service)}
          {#if target}
            <li>
              <a
                class="port-item port-item-link"
                href={target.url}
                target="_blank"
                rel="noreferrer noopener"
                title={target.url}
                onclick={(event) => openPortTarget(event, target.url)}
              >
                <div class="port-main">
                  <span class="port-number">{port.port}</span>
                  <span class="port-service">{port.service || 'unknown'}</span>
                </div>

                <span class="port-link-label">{target.label}</span>
              </a>
            </li>
          {:else}
            <li class="port-item">
              <div class="port-main">
                <span class="port-number">{port.port}</span>
                <span class="port-service">{port.service || 'unknown'}</span>
              </div>
            </li>
          {/if}
        {/each}
      </ul>
    {/if}
  {:else}
    <h3>Host Details</h3>
    <p class="empty">Select a host row to inspect details.</p>
  {/if}
</aside>

<style>
  .inspector {
    width: 290px;
    border-left: 1.5px solid #000;
    padding: 10px;
    overflow-y: auto;
    background: #fff;
  }

  h3,
  h4 {
    margin: 0 0 10px;
  }

  h4 {
    margin-top: 16px;
    text-decoration: underline;
  }

  .kv {
    display: flex;
    justify-content: space-between;
    gap: 10px;
    border-bottom: 1px dotted #000;
    padding: 4px 0;
  }

  .actions {
    margin-top: 10px;
  }

  .name-editor {
    margin-top: 10px;
  }

  .name-editor-controls {
    display: flex;
    align-items: center;
    gap: 6px;
    margin-top: 4px;
  }

  .name-editor-controls input {
    flex: 1;
    min-width: 0;
  }

  ul {
    list-style: none;
    margin: 0;
    padding: 0;
  }

  .port-item {
    display: flex;
    align-items: center;
    gap: 8px;
    border: 1px solid #000;
    padding: 4px 6px;
    margin-bottom: 6px;
  }

  .port-item-link {
    color: inherit;
    text-decoration: none;
  }

  .port-item-link:hover,
  .port-item-link:focus-visible {
    background: #000;
    color: #fff;
    outline: none;
  }

  .port-main {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
    overflow: hidden;
    flex: 1;
  }

  .port-number {
    min-width: 36px;
  }

  .port-service {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .port-link-label {
    margin-left: auto;
    color: inherit;
    text-decoration: underline;
    flex: 0 0 auto;
  }

  .plain-list {
    list-style: square;
    padding-left: 18px;
  }

  .plain-item {
    margin-bottom: 4px;
  }

  .empty {
    color: #666;
    font-style: italic;
  }

  @media (max-width: 980px) {
    .inspector {
      width: auto;
      border-left: none;
      border-top: 1.5px solid #000;
      max-height: 280px;
    }
  }
</style>
