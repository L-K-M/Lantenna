<script lang="ts">
  import { BalloonHelp, Button, Dropdown } from '@lkmc/system7-ui';
  import type { NetworkInterface, PortProfile } from '$lib/types';

  export let interfaces: NetworkInterface[] = [];
  export let selectedInterface: string | null = null;
  export let profile: PortProfile = 'quick';
  export let scanning = false;
  export let query = '';

  export let onInterfaceChange: ((name: string) => void) | undefined = undefined;
  export let onProfileChange: ((profile: PortProfile) => void) | undefined = undefined;
  export let onStart: (() => void) | undefined = undefined;
  export let onStop: (() => void) | undefined = undefined;
  export let onQueryChange: ((value: string) => void) | undefined = undefined;

  const profileOptions: { value: PortProfile; label: string }[] = [
    { value: 'quick', label: 'Quick' },
    { value: 'standard', label: 'Standard' },
    { value: 'deep', label: 'Deep' }
  ];

  $: interfaceOptions =
    interfaces.length === 0
      ? [{ value: '', label: 'No interfaces found', disabled: true }]
      : interfaces.map((item) => ({ value: interfaceValue(item), label: interfaceLabel(item) }));

  const portsHelpText =
    'Quick: 22 common ports (20,21,22,23,53,80,110,135,139,143,443,445,515,548,631,3389,5000,5353,5900,8000,8080,8443). Standard: expanded common service list. Deep: all TCP ports 1-2048.';

  function interfaceLabel(item: NetworkInterface): string {
    return `${item.name} (${item.subnet})`;
  }

  function interfaceValue(item: NetworkInterface): string {
    return `${item.name}|${item.ip}`;
  }
</script>

<div class="toolbar">
  <div class="toolbar-group">
    <label for="interface-select">Interface</label>
    <div class="dropdown-wrap interface-dropdown">
      <Dropdown
        id="interface-select"
        disabled={scanning}
        value={selectedInterface ?? ''}
        options={interfaceOptions}
        onchange={(value) => onInterfaceChange?.(value)}
      />
    </div>

    <BalloonHelp message={portsHelpText} delay={300}>
      <div class="ports-control">
        <label for="profile-select">Ports</label>
        <div class="dropdown-wrap profile-dropdown">
          <Dropdown
            id="profile-select"
            disabled={scanning}
            value={profile}
            options={profileOptions}
            onchange={(value) => onProfileChange?.(value as PortProfile)}
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
    <div class="search-wrap">
      <span class="search-icon" aria-hidden="true">
        <svg viewBox="0 0 16 16" role="img" focusable="false">
          <circle cx="6.5" cy="6.5" r="4.5" />
          <line x1="9.8" y1="9.8" x2="14" y2="14" />
        </svg>
      </span>
      <input
        value={query}
        type="text"
        placeholder="Filter by IP or host name"
        oninput={(event) => onQueryChange?.((event.currentTarget as HTMLInputElement).value)}
      />

      {#if query.length > 0}
        <button
          type="button"
          class="clear-search"
          aria-label="Clear filter"
          onclick={() => onQueryChange?.('')}
        >
          <svg viewBox="0 0 12 12" role="img" focusable="false" aria-hidden="true">
            <line x1="2" y1="2" x2="10" y2="10" />
            <line x1="10" y1="2" x2="2" y2="10" />
          </svg>
        </button>
      {/if}
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

  input {
    min-width: 160px;
  }

  .dropdown-wrap :global(.sys7-dropdown) {
    min-width: 220px;
  }

  .profile-dropdown :global(.sys7-dropdown) {
    min-width: 170px;
  }

  .search-wrap {
    min-width: 280px;
    position: relative;
  }

  .search-wrap input {
    width: 100%;
    box-sizing: border-box;
    padding-left: 26px;
    padding-right: 28px;
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
  }

  .search-icon svg {
    width: 12px;
    height: 12px;
    fill: none;
    stroke: #000;
    stroke-width: 1.2;
    stroke-linecap: square;
  }

  .clear-search {
    position: absolute;
    right: 5px;
    top: 50%;
    transform: translateY(-50%);
    width: 18px;
    height: 18px;
    border: 1px solid transparent;
    background: transparent;
    padding: 0;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #000;
  }

  .clear-search svg {
    width: 10px;
    height: 10px;
    fill: none;
    stroke: currentColor;
    stroke-width: 1.4;
    stroke-linecap: square;
  }

  .clear-search:hover {
    background: #000;
    color: #fff;
    border-color: #000;
  }

  .clear-search:focus-visible {
    border-color: #000;
    outline: none;
  }

  .ports-control {
    display: inline-flex;
    align-items: center;
    gap: 8px;
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
