<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { getCurrentWindow } from '@tauri-apps/api/window';
  import * as System7Ui from '@lkmc/system7-ui';
  import { Checkbox, ErrorBanner, Notification, ProgressBar, TitleBar } from '@lkmc/system7-ui';

  import HostInspector from '$lib/components/HostInspector.svelte';
  import HostTable from '$lib/components/HostTable.svelte';
  import ScanToolbar from '$lib/components/ScanToolbar.svelte';

  import { TauriService } from '$lib/tauri';
  import { WindowManager } from '$lib/windowManager';
  import { notifications } from '$lib/util/notifications';
  import { scanStore } from '$lib/util/scanStore';
  import { windowFocused } from '$lib/util/windowState';

  let isWindowShaded = false;
  let systemAccentColor: string | null = null;
  let systemAccentTextColor: string | null = null;
  let systemHighlightColor: string | null = null;
  let systemHighlightTextColor: string | null = null;

  const HEX_COLOR_PATTERN = /^#[0-9a-fA-F]{6}$/;

  interface System7ColorStyleInput {
    accent_color?: string | null;
    accent_text_color?: string | null;
    highlight_color?: string | null;
    highlight_text_color?: string | null;
  }

  interface RgbColor {
    r: number;
    g: number;
    b: number;
  }

  const maybeGetSystem7ColorStyle = Reflect.get(System7Ui, 'getSystem7ColorStyle') as
    | ((colors: System7ColorStyleInput) => string)
    | undefined;

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
    hostScanProgress,
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

  $: hostScanTarget = hostScanProgress?.current_ip || 'selected host';
  $: fullScanActive = scanning || Boolean(progress?.running);
  $: footerStatus = fullScanActive
    ? progress
      ? `${progress.scanned}/${progress.total} scanned, ${progress.found} hosts`
      : 'Scanning...'
    : hostScanProgress?.running
      ? hostScanProgress.total > 0
        ? `Deep scan ${hostScanTarget}: ${hostScanProgress.scanned}/${hostScanProgress.total} ports, ${hostScanProgress.found} open`
        : `Deep scan ${hostScanTarget} in progress...`
      : 'Idle';

  $: activeFooterProgress = fullScanActive ? progress : hostScanProgress?.running ? hostScanProgress : null;
  $: showFooterProgress = Boolean(activeFooterProgress?.running);
  $: footerProgressMax = activeFooterProgress && activeFooterProgress.total > 0 ? activeFooterProgress.total : 1;
  $: footerProgressValue = activeFooterProgress ? Math.min(activeFooterProgress.scanned, footerProgressMax) : 0;
  $: footerProgressAriaLabel = fullScanActive
    ? progress
      ? `Scan progress: ${progress.scanned} of ${progress.total} scanned`
      : 'Scan progress'
    : hostScanProgress?.running
      ? hostScanProgress.total > 0
        ? `Deep scan progress for ${hostScanTarget}: ${hostScanProgress.scanned} of ${hostScanProgress.total} ports`
        : `Deep scan in progress for ${hostScanTarget}`
      : 'Scan progress';

  $: windowStyle = getWindowColorStyle({
    accent_color: systemAccentColor,
    accent_text_color: systemAccentTextColor,
    highlight_color: systemHighlightColor,
    highlight_text_color: systemHighlightTextColor
  });

  const appWindow = getCurrentWindow();
  const windowManager = new WindowManager();

  onMount(() => {
    scanStore.init();
    void loadSystemColors();

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

  function getHostTableHeightMetrics(): { viewportHeight: number; contentHeight: number } | null {
    const tableBodyContainer = document.querySelector<HTMLDivElement>('.table-body-container');
    const tableBody = tableBodyContainer?.querySelector<HTMLTableElement>('table');

    if (!tableBodyContainer || !tableBody) {
      return null;
    }

    return {
      viewportHeight: tableBodyContainer.clientHeight,
      contentHeight: tableBody.getBoundingClientRect().height
    };
  }

  async function handleWindowResizeToFit() {
    if (isWindowShaded) {
      return;
    }

    await tick();

    const tableHeightMetrics = getHostTableHeightMetrics();
    if (!tableHeightMetrics) {
      return;
    }

    const heightDelta = Math.round(tableHeightMetrics.contentHeight - tableHeightMetrics.viewportHeight);
    await windowManager.resizeHeightBy(heightDelta);
  }

  function normalizeHexColor(value: string | null): string | null {
    if (!value) {
      return null;
    }

    const normalized = value.trim();
    return HEX_COLOR_PATTERN.test(normalized) ? normalized : null;
  }

  function hexToRgb(value: string): RgbColor {
    return {
      r: parseInt(value.slice(1, 3), 16),
      g: parseInt(value.slice(3, 5), 16),
      b: parseInt(value.slice(5, 7), 16)
    };
  }

  function rgbToHex({ r, g, b }: RgbColor): string {
    return `#${[r, g, b]
      .map((channel) =>
        Math.max(0, Math.min(255, Math.round(channel)))
          .toString(16)
          .padStart(2, '0')
      )
      .join('')
      .toUpperCase()}`;
  }

  function mixHexColors(fromHex: string, toHex: string, ratio: number): string {
    const clampedRatio = Math.max(0, Math.min(1, ratio));
    const from = hexToRgb(fromHex);
    const to = hexToRgb(toHex);

    return rgbToHex({
      r: from.r + (to.r - from.r) * clampedRatio,
      g: from.g + (to.g - from.g) * clampedRatio,
      b: from.b + (to.b - from.b) * clampedRatio
    });
  }

  function getWindowToneSet(windowColor: string) {
    return {
      edgeLight: mixHexColors(windowColor, '#FFFFFF', 0.55),
      edgeDark: mixHexColors(windowColor, '#000000', 0.25),
      edgeVeryDark: mixHexColors(windowColor, '#000000', 0.42),
      scrollbarLine: mixHexColors(windowColor, '#000000', 0.18),
      scrollbarThumb: mixHexColors(windowColor, '#FFFFFF', 0.7),
      titlebarButton: mixHexColors(windowColor, '#FFFFFF', 0.82)
    };
  }

  function getWindowColorStyle(colors: System7ColorStyleInput): string {
    const styleParts: string[] = [];

    if (maybeGetSystem7ColorStyle) {
      const baseStyle = maybeGetSystem7ColorStyle(colors);
      if (baseStyle) {
        styleParts.push(baseStyle);
      }
    } else {
      styleParts.push(
        ...[
          colors.accent_color ? `--system7-color-accent: ${colors.accent_color}` : '',
          colors.accent_text_color ? `--system7-color-accent-text: ${colors.accent_text_color}` : '',
          colors.highlight_color ? `--system7-color-highlight: ${colors.highlight_color}` : '',
          colors.highlight_text_color
            ? `--system7-color-highlight-text: ${colors.highlight_text_color}`
            : ''
        ].filter((value) => value.length > 0)
      );
    }

    if (colors.accent_color) {
      const windowTones = getWindowToneSet(colors.accent_color);

      styleParts.push(
        `--system7-color-focus-ring: ${colors.accent_color}`,
        `--system7-color-titlebar-edge-light: ${windowTones.edgeLight}`,
        `--system7-color-titlebar-edge-dark: ${windowTones.edgeDark}`,
        `--system7-color-titlebar-edge-verydark: ${windowTones.edgeVeryDark}`,
        `--system7-color-titlebar-button: ${windowTones.titlebarButton}`,
        `--system7-color-scrollbar-thumb-line: ${windowTones.scrollbarLine}`,
        `--system7-color-scrollbar-thumb: ${windowTones.scrollbarThumb}`,
        `--system7-color-success: ${colors.accent_color}`,
        `--system7-color-error: ${colors.accent_color}`,
        `--system7-color-info: ${colors.accent_color}`
      );
    }

    return styleParts.join('; ');
  }

  async function loadSystemColors() {
    try {
      const colors = await TauriService.getSystemColors();
      systemAccentColor = normalizeHexColor(colors.accent_color);
      systemAccentTextColor = normalizeHexColor(colors.accent_text_color);
      systemHighlightColor = normalizeHexColor(colors.highlight_color);
      systemHighlightTextColor = normalizeHexColor(colors.highlight_text_color);
    } catch {
      systemAccentColor = null;
      systemAccentTextColor = null;
      systemHighlightColor = null;
      systemHighlightTextColor = null;
    }
  }
</script>

<div class="window-frame s7-root" class:window-unfocused={!$windowFocused} style={windowStyle}>
  <TitleBar
    title="Lantenna"
    focused={$windowFocused}
    closable
    collapsible
    shadeable
    draggable
    onclose={handleWindowClose}
    oncollapse={handleWindowResizeToFit}
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
          onClearCustomName={(ip) => scanStore.setCustomName(ip, '')}
        />
        <HostInspector
          host={selectedHost}
          {customNames}
          deepScanRunning={Boolean(hostScanProgress?.running)}
          onSetCustomName={(ip, name) => scanStore.setCustomName(ip, name)}
          onDeepScan={(ip) => scanStore.refreshHostPorts(ip, 'deep')}
        />
      </section>
    </main>

    <footer class="app-footer">
      {#if showFooterProgress}
        <div class="footer-progress">
          <ProgressBar
            value={footerProgressValue}
            max={footerProgressMax}
            height={16}
            title={footerProgressAriaLabel}
            ariaLabel={footerProgressAriaLabel}
          />
        </div>
      {/if}
      <span class="footer-status">{footerStatus}</span>
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
    --system7-color-accent: #000;
    --system7-color-accent-text: #fff;
    --system7-color-highlight: #000;
    --system7-color-highlight-text: #fff;
    --system7-color-success: #000;
    --system7-color-error: #000;
    --system7-color-info: #000;
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

  .footer-status {
    flex: 0 0 auto;
  }

  .footer-progress {
    width: clamp(140px, 24vw, 280px);
    min-width: 140px;
    display: inline-flex;
    align-items: center;
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
