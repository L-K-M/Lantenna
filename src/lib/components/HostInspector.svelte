<script lang="ts">
  import { BalloonHelp, Button } from '@lkmc/system7-ui';
  import type { Host } from '$lib/types';

  export let host: Host | null = null;
  export let onDeepScan: ((ip: string) => void) | undefined = undefined;

  interface PortTarget {
    label: 'HTTP' | 'HTTPS' | 'SMB' | 'SSH' | 'FTP';
    url: string;
  }

  const httpPorts = new Set([80, 81, 3000, 5000, 8000, 8080, 8081, 8888, 9000]);
  const httpsPorts = new Set([443, 8443, 9443]);

  function formatTime(iso: string): string {
    return new Date(iso).toLocaleString();
  }

  function getPortTarget(hostIp: string, port: number, service: string | null): PortTarget | null {
    const normalized = (service || '').toLowerCase();
    const buildUrl = (scheme: 'http' | 'https' | 'ftp', defaultPort: number): string =>
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
      return { label: 'SSH', url: `ssh://${hostIp}` };
    }

    if (normalized.includes('ftp')) {
      return { label: 'FTP', url: buildUrl('ftp', 21) };
    }

    if (httpsPorts.has(port)) {
      return { label: 'HTTPS', url: buildUrl('https', 443) };
    }

    if (httpPorts.has(port)) {
      return { label: 'HTTP', url: buildUrl('http', 80) };
    }

    if (port === 445 || port === 139) {
      return { label: 'SMB', url: `smb://${hostIp}` };
    }

    if (port === 22) {
      return { label: 'SSH', url: `ssh://${hostIp}` };
    }

    if (port === 21) {
      return { label: 'FTP', url: buildUrl('ftp', 21) };
    }

    return null;
  }
</script>

<aside class="inspector">
  {#if host}
    {@const fp = host.fingerprint}
    <h3>Host Details</h3>
    <div class="kv"><span>IP</span><span>{host.ip}</span></div>
    <div class="kv"><span>Name</span><span>{host.name || 'Unknown'}</span></div>
    <div class="kv"><span>Reachable</span><span>{host.reachable ? 'Yes' : 'No'}</span></div>
    <div class="kv"><span>Last Seen</span><span>{formatTime(host.last_seen)}</span></div>

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
          <li class="port-item">
            <div class="port-main">
              <span class="port-number">{port.port}</span>
              <span class="port-service">{port.service || 'unknown'}</span>
            </div>

            {#if target}
              <a
                class="port-link"
                href={target.url}
                target="_blank"
                rel="noreferrer noopener"
                title={target.url}
              >
                {target.label}
              </a>
            {/if}
          </li>
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

  .port-main {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
    overflow: hidden;
  }

  .port-number {
    min-width: 36px;
  }

  .port-service {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .port-link {
    margin-left: auto;
    color: inherit;
    text-decoration: underline;
  }

  .port-link:hover {
    color: #fff;
    background: #000;
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
