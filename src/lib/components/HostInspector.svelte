<script lang="ts">
  import type { Host } from '$lib/types';

  export let host: Host | null = null;

  function formatTime(iso: string): string {
    return new Date(iso).toLocaleString();
  }
</script>

<aside class="inspector">
  {#if host}
    <h3>Host Details</h3>
    <div class="kv"><span>IP</span><span>{host.ip}</span></div>
    <div class="kv"><span>Name</span><span>{host.name || 'Unknown'}</span></div>
    <div class="kv"><span>Reachable</span><span>{host.reachable ? 'Yes' : 'No'}</span></div>
    <div class="kv"><span>Last Seen</span><span>{formatTime(host.last_seen)}</span></div>

    <h4>Open Ports</h4>
    {#if host.open_ports.length === 0}
      <p class="empty">No open ports detected.</p>
    {:else}
      <ul>
        {#each host.open_ports as port}
          <li>
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
    border-left: 1px solid #000;
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

  ul {
    list-style: none;
    margin: 0;
    padding: 0;
  }

  li {
    display: flex;
    justify-content: space-between;
    gap: 8px;
    border: 1px solid #000;
    padding: 4px 6px;
    margin-bottom: 6px;
  }

  .empty {
    color: #666;
    font-style: italic;
  }

  @media (max-width: 980px) {
    .inspector {
      width: auto;
      border-left: none;
      border-top: 1px solid #000;
      max-height: 280px;
    }
  }
</style>
