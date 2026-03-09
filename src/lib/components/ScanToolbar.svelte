<script lang="ts">
  import { BalloonHelp, Button, Dropdown } from '@lkmc/system7-ui';
  import type { NetworkInterface, PortProfile, ScanProgress } from '$lib/types';

  export let interfaces: NetworkInterface[] = [];
  export let selectedInterface: string | null = null;
  export let profile: PortProfile = 'quick';
  export let scanning = false;
  export let progress: ScanProgress | null = null;
  export let query = '';
  export let canExport = false;

  export let onInterfaceChange: ((name: string) => void) | undefined = undefined;
  export let onProfileChange: ((profile: PortProfile) => void) | undefined = undefined;
  export let onStart: (() => void) | undefined = undefined;
  export let onStop: (() => void) | undefined = undefined;
  export let onQueryChange: ((value: string) => void) | undefined = undefined;
  export let onExport: (() => void) | undefined = undefined;

  const profileOptions: { value: PortProfile; label: string }[] = [
    { value: 'quick', label: 'Quick' },
    { value: 'standard', label: 'Standard' },
    { value: 'deep', label: 'Deep' }
  ];

  $: interfaceOptions =
    interfaces.length === 0
      ? [{ value: '', label: 'No interfaces found', disabled: true }]
      : interfaces.map((item) => ({ value: item.name, label: interfaceLabel(item) }));

  const portsHelpText =
    'Quick: 22 common ports (20,21,22,23,53,80,110,135,139,143,443,445,515,548,631,3389,5000,5353,5900,8000,8080,8443). Standard: expanded common service list. Deep: all TCP ports 1-2048.';

  function interfaceLabel(item: NetworkInterface): string {
    return `${item.name} (${item.subnet})`;
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
      <Button variant="primary" onclick={onStart} disabled={!selectedInterface}>Start Scan</Button>
    {/if}

    <Button onclick={onExport} disabled={!canExport}>Export JSON</Button>
  </div>

  <div class="toolbar-group right">
    <div class="search-wrap">
      <input
        value={query}
        type="text"
        placeholder="Filter by IP or host name"
        oninput={(event) => onQueryChange?.((event.currentTarget as HTMLInputElement).value)}
      />
    </div>

    <BalloonHelp message="Scanned / total, with discovered hosts">
      <div class="scan-meta">
        {#if progress}
          {progress.scanned}/{progress.total} scanned, {progress.found} hosts
        {:else}
          Idle
        {/if}
      </div>
    </BalloonHelp>
  </div>
</div>

<style>
  .toolbar {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    padding: 10px;
    border-bottom: 1px solid #000;
    flex-wrap: wrap;
    background: #fff;
  }

  .toolbar-group {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
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
  }

  .search-wrap input {
    width: 100%;
    box-sizing: border-box;
  }

  .scan-meta {
    border: 1px solid #000;
    padding: 5px 8px 3px;
    min-width: 180px;
    text-align: center;
    white-space: nowrap;
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
      justify-content: space-between;
    }

    .search-wrap {
      min-width: 0;
      flex: 1;
    }

  }
</style>
