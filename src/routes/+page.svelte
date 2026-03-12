<script lang="ts">
  import { onMount } from 'svelte';
  import { getCurrentWindow } from '@tauri-apps/api/window';
  import { Checkbox, ErrorBanner, Notification, TitleBar } from '@lkmc/system7-ui';

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
    scanApproach,
    hosts,
    newHostIps,
    customNames,
    favoriteIps,
    hiddenIps,
    showHiddenEntries,
    staleFavoriteIps,
    progress,
    scanning,
    loading,
    error,
    query,
    selectedHostIp
  } = $scanStore);

  $: hiddenSet = new Set(hiddenIps);

  $: queryMatchedHosts = hosts.filter((host) => {
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

  $: hiddenCount = hosts.filter((host) => hiddenSet.has(host.ip)).length;

  $: visibleHosts = showHiddenEntries ? hosts : hosts.filter((host) => !hiddenSet.has(host.ip));

  $: filteredHosts = showHiddenEntries
    ? queryMatchedHosts
    : queryMatchedHosts.filter((host) => !hiddenSet.has(host.ip));

  $: selectedHost = visibleHosts.find((host) => host.ip === selectedHostIp) || null;

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
        approach={scanApproach}
        {scanning}
        {query}
        onInterfaceChange={(name) => scanStore.setInterface(name)}
        onApproachChange={(approach) => scanStore.setScanApproach(approach)}
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
          {hiddenIps}
          {staleFavoriteIps}
          {newHostIps}
          onSelectHost={(ip) => scanStore.setSelectedHost(ip)}
          onToggleFavorite={(ip) => scanStore.toggleFavorite(ip)}
          onToggleHidden={(ip) => scanStore.toggleHidden(ip)}
        />
        <HostInspector
          host={selectedHost}
          {customNames}
          onSetCustomName={(ip, name) => scanStore.setCustomName(ip, name)}
          onDeepScan={(ip) => scanStore.refreshHostPorts(ip, 'deep')}
        />
      </section>
    </main>

    <footer class="app-footer">
      <span>{footerStatus}</span>
      {#if hiddenCount > 0}
        <div class="hidden-footer-toggle">
          <Checkbox
            checked={showHiddenEntries}
            label="Show hidden entries"
            onchange={(checked) => scanStore.setShowHiddenEntries(checked)}
          />
        </div>
      {/if}
    </footer>
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
    gap: 12px;
  }

  .hidden-footer-toggle {
    margin-left: auto;
    display: inline-flex;
    align-items: center;
  }

  @media (max-width: 980px) {
    .results-layout {
      flex-direction: column;
    }
  }
</style>
