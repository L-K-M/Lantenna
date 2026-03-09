<script lang="ts">
  import { onMount } from 'svelte';
  import { getCurrentWindow } from '@tauri-apps/api/window';
  import { ErrorBanner, Notification, TitleBar } from '@lkmc/system7-ui';

  import HostInspector from '$lib/components/HostInspector.svelte';
  import HostTable from '$lib/components/HostTable.svelte';
  import ScanToolbar from '$lib/components/ScanToolbar.svelte';

  import { WindowManager } from '$lib/windowManager';
  import { notifications } from '$lib/util/notifications';
  import { scanStore } from '$lib/util/scanStore';
  import { windowFocused } from '$lib/util/windowState';

  let isWindowShaded = false;

  $: ({
    interfaces,
    selectedInterface,
    portProfile,
    hosts,
    progress,
    scanning,
    loading,
    error,
    query,
    selectedHostIp,
    lastScanAt
  } = $scanStore);

  $: filteredHosts = hosts.filter((host) => {
    if (!query.trim()) {
      return true;
    }

    const needle = query.toLowerCase();
    return host.ip.includes(needle) || (host.name || '').toLowerCase().includes(needle);
  });

  $: selectedHost = hosts.find((host) => host.ip === selectedHostIp) || null;

  const appWindow = getCurrentWindow();
  const windowManager = new WindowManager();

  onMount(() => {
    scanStore.init();

    const unlistenFocus = appWindow.onFocusChanged(({ payload: focused }) => {
      windowFocused.set(focused);
    });

    return () => {
      unlistenFocus.then((fn) => fn());
      scanStore.destroy();
    };
  });

  function handleWindowClose() {
    windowManager.close();
  }

  async function handleWindowShade() {
    isWindowShaded = await windowManager.toggleShade();
  }

  function handleWindowDrag() {
    windowManager.startDragging();
  }

  function exportJson() {
    if (hosts.length === 0) {
      return;
    }

    const payload = {
      exported_at: new Date().toISOString(),
      last_scan_at: lastScanAt,
      hosts
    };

    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `lantenna-scan-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }
</script>

<div class="window-frame" class:window-unfocused={!$windowFocused}>
  <TitleBar
    title="Lantenna"
    focused={$windowFocused}
    closable
    shadeable
    draggable
    onclose={handleWindowClose}
    onshade={handleWindowShade}
    ondragstart={handleWindowDrag}
  />

  {#if !isWindowShaded}
    <Notification notifications={$notifications} />

    <main class="app-content">
      <ScanToolbar
        interfaces={interfaces}
        selectedInterface={selectedInterface}
        profile={portProfile}
        {scanning}
        {progress}
        {query}
        canExport={hosts.length > 0}
        onInterfaceChange={(name) => scanStore.setInterface(name)}
        onProfileChange={(profile) => scanStore.setProfile(profile)}
        onStart={() => scanStore.startScan()}
        onStop={() => scanStore.cancelScan()}
        onQueryChange={(value) => scanStore.setQuery(value)}
        onExport={exportJson}
      />

      {#if error}
        <ErrorBanner message={error} onclose={() => scanStore.clearError()} />
      {/if}

      <section class="results-layout">
        <HostTable
          hosts={filteredHosts}
          loading={loading || scanning}
          {selectedHostIp}
          onSelectHost={(ip) => scanStore.setSelectedHost(ip)}
          onDeepScan={(ip) => scanStore.refreshHostPorts(ip, 'deep')}
        />
        <HostInspector host={selectedHost} />
      </section>
    </main>
  {/if}
</div>

<style>
  .window-frame {
    width: 100vw;
    height: 100vh;
    background: #fff;
    border: 1px solid #000;
    box-shadow: 2px 2px 0 rgba(0, 0, 0, 0.2);
    display: flex;
    flex-direction: column;
  }

  .app-content {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    min-height: 0;
  }

  .results-layout {
    flex: 1;
    min-height: 0;
    display: flex;
    overflow: hidden;
  }

  @media (max-width: 980px) {
    .results-layout {
      flex-direction: column;
    }
  }
</style>
