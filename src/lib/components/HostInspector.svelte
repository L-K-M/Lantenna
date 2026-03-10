<script lang="ts">
  import { BalloonHelp, Button } from '@lkmc/system7-ui';
  import type { Host } from '$lib/types';

  export let host: Host | null = null;
  export let onDeepScan: ((ip: string) => void) | undefined = undefined;

  function formatTime(iso: string): string {
    return new Date(iso).toLocaleString();
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
          <li class="port-item">
            <span>{port.port}</span>
            <span>{port.service || 'unknown'}</span>
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
    justify-content: space-between;
    gap: 8px;
    border: 1px solid #000;
    padding: 4px 6px;
    margin-bottom: 6px;
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
