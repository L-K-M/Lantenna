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
    customNames,
    favoriteIps,
    staleFavoriteIps,
    progress,
    scanning,
    loading,
    error,
    query,
    selectedHostIp
  } = $scanStore);

  $: filteredHosts = hosts.filter((host) => {
    if (!query.trim()) {
      return true;
    }

    const needle = query.toLowerCase();
    const customName = (customNames[host.ip] || '').toLowerCase();
    return (
      host.ip.includes(needle) ||
      (host.name || '').toLowerCase().includes(needle) ||
      customName.includes(needle)
    );
  });

  $: selectedHost = hosts.find((host) => host.ip === selectedHostIp) || null;

  $: footerStatus = scanning
    ? progress
      ? `${progress.scanned}/${progress.total} scanned, ${progress.found} hosts`
      : 'Scanning...'
    : 'Idle';

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
        {query}
        onInterfaceChange={(name) => scanStore.setInterface(name)}
        onProfileChange={(profile) => scanStore.setProfile(profile)}
        onStart={() => scanStore.startScan()}
        onStop={() => scanStore.cancelScan()}
        onQueryChange={(value) => scanStore.setQuery(value)}
      />

      {#if error}
        <ErrorBanner message={error} onclose={() => scanStore.clearError()} />
      {/if}

      <section class="results-layout">
        <HostTable
          hosts={filteredHosts}
          loading={loading || scanning}
          {selectedHostIp}
          {customNames}
          {favoriteIps}
          {staleFavoriteIps}
          onSelectHost={(ip) => scanStore.setSelectedHost(ip)}
          onToggleFavorite={(ip) => scanStore.toggleFavorite(ip)}
        />
        <HostInspector
          host={selectedHost}
          {customNames}
          onSetCustomName={(ip, name) => scanStore.setCustomName(ip, name)}
          onDeepScan={(ip) => scanStore.refreshHostPorts(ip, 'deep')}
        />
      </section>
    </main>

    <footer class="app-footer">{footerStatus}</footer>
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

  .app-footer {
    border-top: 1.5px solid #000;
    padding: 4px 8px;
    min-height: 24px;
    display: flex;
    align-items: center;
    white-space: nowrap;
  }

  @media (max-width: 980px) {
    .results-layout {
      flex-direction: column;
    }
  }
</style>
