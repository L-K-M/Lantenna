<script lang="ts">
  import { BalloonHelp, Button, Dropdown, TextInput } from '@lkmc/system7-ui';
  import type { HostViewMode, NetworkInterface, ScanApproach } from '$lib/types';

  export let interfaces: NetworkInterface[] = [];
  export let selectedInterface: string | null = null;
  export let approach: ScanApproach = 'balanced';
  export let scanning = false;
  export let query = '';
  export let viewMode: HostViewMode = 'list';

  export let onInterfaceChange: ((name: string) => void) | undefined = undefined;
  export let onApproachChange: ((approach: ScanApproach) => void) | undefined = undefined;
  export let onStart: (() => void) | undefined = undefined;
  export let onStop: (() => void) | undefined = undefined;
  export let onQueryChange: ((value: string) => void) | undefined = undefined;
  export let onViewModeChange: ((mode: HostViewMode) => void) | undefined = undefined;

  const approachOptions: { value: ScanApproach; label: string }[] = [
    { value: 'fast', label: 'Fast' },
    { value: 'balanced', label: 'Balanced' },
    { value: 'thorough', label: 'Thorough' }
  ];

  $: interfaceOptions =
    interfaces.length === 0
      ? [{ value: '', label: 'No interfaces found', disabled: true }]
      : interfaces.map((item) => ({ value: interfaceValue(item), label: interfaceLabel(item) }));

  const interfaceHelpText =
    '**Interface**\n- Choose the adapter connected to the network you want to scan.\n- If there are multiple entries with the same name, pick the one with the matching subnet.\n- Scans are limited to the selected interface subnet.';

  const approachHelpText =
    '**Fast**\n- Focused common TCP ports + a few high-signal fingerprint ports\n- TCP-only discovery\n- Fastest, lower coverage\n\n**Balanced** (recommended)\n- Expanded service-port set + extra device-signature ports\n- Hybrid discovery (TCP + ICMP fallback)\n- Best default for most networks\n\n**Thorough**\n- TCP ports `1-2048` + every Balanced port above `2048`\n- Hybrid discovery (TCP + ICMP fallback)\n- Slowest, highest coverage\n\n*Note: very large subnets are capped to 4096 hosts per scan.*';

  function interfaceLabel(item: NetworkInterface): string {
    return `${item.name} (${item.subnet})`;
  }

  function interfaceValue(item: NetworkInterface): string {
    return `${item.name}|${item.ip}`;
  }
</script>

<div class="toolbar">
  <div class="toolbar-group">
    <BalloonHelp message={interfaceHelpText} markdown delay={300}>
      <div class="interface-control">
        <label class="visually-hidden" for="interface-select">Interface</label>
        <div class="dropdown-wrap interface-dropdown">
          <Dropdown
            id="interface-select"
            disabled={scanning}
            value={selectedInterface ?? ''}
            options={interfaceOptions}
            onchange={(value) => onInterfaceChange?.(value)}
          />
        </div>
      </div>
    </BalloonHelp>

    <BalloonHelp message={approachHelpText} markdown delay={300}>
      <div class="approach-control">
        <label class="visually-hidden" for="approach-select">Approach</label>
        <div class="dropdown-wrap approach-dropdown">
          <Dropdown
            id="approach-select"
            disabled={scanning}
            value={approach}
            options={approachOptions}
            onchange={(value) => onApproachChange?.(value as ScanApproach)}
          />
        </div>
      </div>
    </BalloonHelp>

    {#if scanning}
      <Button onclick={onStop}>Stop Scan</Button>
    {:else}
      <Button onclick={onStart} disabled={!selectedInterface}>Start Scan</Button>
    {/if}

  </div>

  <div class="toolbar-group right">
    <div class="view-toggle" role="group" aria-label="View">
      <button
        type="button"
        class:active={viewMode === 'list'}
        aria-pressed={viewMode === 'list'}
        title="View as List"
        aria-label="View as list"
        onclick={() => onViewModeChange?.('list')}
      >
        <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">
          <rect x="2" y="3" width="12" height="2" />
          <rect x="2" y="7" width="12" height="2" />
          <rect x="2" y="11" width="12" height="2" />
        </svg>
      </button>
      <button
        type="button"
        class:active={viewMode === 'icons'}
        aria-pressed={viewMode === 'icons'}
        title="View as Icons"
        aria-label="View as icons"
        onclick={() => onViewModeChange?.('icons')}
      >
        <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">
          <rect x="2" y="2" width="5" height="5" />
          <rect x="9" y="2" width="5" height="5" />
          <rect x="2" y="9" width="5" height="5" />
          <rect x="9" y="9" width="5" height="5" />
        </svg>
      </button>
    </div>
    <div class="search-wrap">
      <span class="search-icon" aria-hidden="true">
        <svg viewBox="0 0 16 16" role="img" focusable="false">
          <circle cx="6.5" cy="6.5" r="4.5" />
          <line x1="9.8" y1="9.8" x2="14" y2="14" />
        </svg>
      </span>
      <TextInput
        value={query}
        clearable
        placeholder="Filter by name, IP, vendor, port..."
        ariaLabel="Filter hosts by name, IP, vendor, type, MAC, port or service"
        oninput={(value) => onQueryChange?.(value)}
        onclear={() => onQueryChange?.('')}
      />
    </div>
  </div>
</div>

<style>
  .toolbar {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    padding: 10px;
    border-bottom: 1.5px solid #000;
    flex-wrap: wrap;
    background: #fff;
  }

  .toolbar-group {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
  }

  .toolbar-group :global(.sys7-btn) {
    margin-top: 2px;
  }

  .toolbar-group.right {
    margin-left: auto;
  }

  label {
    white-space: nowrap;
  }

  .visually-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    border: 0;
  }

  .dropdown-wrap :global(.sys7-dropdown) {
    min-width: 220px;
  }

  .approach-dropdown :global(.sys7-dropdown) {
    min-width: 120px;
  }

  .search-wrap {
    min-width: 280px;
    position: relative;
  }

  .view-toggle {
    display: inline-flex;
    border: 1px solid var(--system7-color-ink, #000);
  }

  .view-toggle button {
    width: 24px;
    height: 22px;
    padding: 0;
    border: none;
    background: var(--system7-color-paper, #fff);
    color: var(--system7-color-ink, #000);
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
  }

  .view-toggle button + button {
    border-left: 1px solid var(--system7-color-ink, #000);
  }

  .view-toggle button.active {
    background: var(--system7-color-ink, #000);
    color: var(--system7-color-paper, #fff);
  }

  .view-toggle button:focus-visible {
    outline: 1px dotted var(--system7-color-ink, #000);
    outline-offset: 2px;
  }

  .view-toggle svg {
    width: 14px;
    height: 14px;
    fill: currentColor;
    shape-rendering: crispEdges;
  }

  .search-wrap :global(.sys7-text-input-wrap) {
    width: 100%;
  }

  .search-wrap :global(.sys7-text-input) {
    width: 100%;
    padding-left: 26px;
  }

  .search-icon {
    position: absolute;
    left: 8px;
    top: 50%;
    transform: translateY(-50%);
    display: flex;
    align-items: center;
    justify-content: center;
    pointer-events: none;
    width: 12px;
    height: 12px;
    /* Paint above the TextInput wrap, which is also positioned and later
       in DOM order (the raw input it replaced was static, so the icon
       used to win by default). */
    z-index: 1;
  }

  .search-icon svg {
    width: 12px;
    height: 12px;
    fill: none;
    stroke: #000;
    stroke-width: 1.2;
    stroke-linecap: square;
  }

  .toolbar-group :global(.sys7-btn:not(:disabled):focus-visible) {
    background: var(--system7-color-accent, #000);
    color: var(--system7-color-accent-text, #fff);
    outline: 1px dotted var(--system7-color-accent, #000);
    outline-offset: 1px;
  }

  .approach-control {
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }

  .interface-control {
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }

  .toolbar :global(.balloon) {
    width: 450px;
    max-width: calc(100vw - 64px);
    white-space: normal;
  }

  .toolbar :global(.balloon .balloon-content) {
    white-space: pre-line;
    line-height: 0.95;
  }

  .toolbar :global(.balloon .balloon-content.markdown-content) {
    white-space: normal;
    line-height: 1;
  }

  @media (max-width: 980px) {
    .toolbar {
      flex-direction: column;
      align-items: stretch;
    }

    .toolbar-group.right {
      margin-left: 0;
      justify-content: flex-start;
    }

    .search-wrap {
      min-width: 0;
      flex: 1;
    }

  }
</style>
