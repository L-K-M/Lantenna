<!--
  Owner: unit C (spec 8.4). Spec: 2.3 (pane rows), 2.7, 3.2 (Return
  presses Open), 4.1 (buttons follow the command model), 4.5, 5.3, 5.6.
  The Host Information pane: General / Ports / Fingerprint tabs (Osmium
  mountTabs; the panels stay mounted, the front tab is ui.infoTab), the
  host status line, and Wake, Deep Scan and the default Open button,
  which Return presses (bindDialogKeys). Publishes InfoPaneApi in
  infoPaneApi (views.ts).
  It hides itself with the `hidden` attribute when the pane is hidden, so
  drafts and scroll positions survive. The page's CSS owns the region
  box (.lan-pane, 300px, position: relative); this file places what is
  inside it, in the pane-local coordinates of 2.3.
  The panels' root elements are Osmium-owned once mountTabs runs (it
  sets their hidden, id, role and aria-labelledby), and so are the tabs
  and the push buttons (pushButton sets their width and padding).
-->
<svelte:options runes={true} />

<script module lang="ts">
  import type { ScanProgress } from '$lib/types';
  import { formatCount, plural } from '$lib/util/format';

  export interface HostStatus {
    readonly text: string;
    /** A deep scan of the host is streaming progress: screen readers
     * wait for its result instead of hearing every count (5.6). */
    readonly busy: boolean;
  }

  /**
   * The host status line (5.3) for the selected `ip`: live states first
   * (a wake being sent, the host's deep scan), else the host's latest
   * note (a result). Failures are alerts and never show here.
   */
  export function hostStatus(
    ip: string | null,
    note: { ip: string; text: string } | null,
    hostScan: ScanProgress | null,
    wakingIp: string | null
  ): HostStatus {
    if (ip === null) return { text: '', busy: false };
    if (wakingIp === ip) return { text: 'Sending a wake-up packet…', busy: false };

    if (hostScan?.running && hostScan.current_ip === ip) {
      const text =
        hostScan.total > 0
          ? `Deep scan: ${formatCount(hostScan.scanned)} of ${plural(hostScan.total, 'port')}, ${formatCount(hostScan.found)} open.`
          : 'Deep scan starting…';
      return { text, busy: true };
    }

    return { text: note?.ip === ip ? note.text : '', busy: false };
  }
</script>

<script lang="ts">
  import { flushSync, onMount, untrack } from 'svelte';
  import { get } from 'svelte/store';
  import { bindDialogKeys, mountTabs, type OsmiumTabs } from 'osmium-ui';
  import { wakingIp } from '$lib/app/actions';
  import { STATUS_BALLOON, TAB_BALLOON, deepScanBalloon, openBalloon, wakeBalloon } from '$lib/app/balloonTexts';
  import { commandContext, describe, run, type CommandContext } from '$lib/app/commands';
  import { hostNote } from '$lib/app/feedback';
  import { hostModel } from '$lib/app/hostModel';
  import { ui, type InfoTab } from '$lib/app/ui';
  import { infoPaneApi } from '$lib/app/views';
  import { balloon, dimmable, osmButton } from '$lib/osm/actions';
  import { scanProgress } from '$lib/util/scanStore';
  import InfoFingerprint from './InfoFingerprint.svelte';
  import InfoGeneral from './InfoGeneral.svelte';
  import InfoPorts from './InfoPorts.svelte';

  const TABS: readonly { readonly id: InfoTab; readonly title: string }[] = [
    { id: 'general', title: 'General' },
    { id: 'ports', title: 'Ports' },
    { id: 'fingerprint', title: 'Fingerprint' }
  ];

  let tabsHost: HTMLDivElement;
  let openButton: HTMLButtonElement;
  let tabs: OsmiumTabs | null = null;
  let general: { focusName(): void } | undefined = $state();

  const selected = $derived($hostModel.selected);
  const status = $derived(
    hostStatus(selected?.ip ?? null, $hostNote, $scanProgress.hostScanProgress, $wakingIp)
  );

  // The buttons are renderers of the command model (4.1): enabled as the
  // menu items are, and they run the same commands. They ignore its
  // "alert up" rule, as ControlStrip's controls do: behind an alert the
  // window draws inactive, which dims them anyway, and a button the
  // alert came from must stay enabled to take the keyboard back when
  // the alert closes (Osmium focuses it then, before Svelte could
  // enable it again).
  const ctx: CommandContext = $derived({ ...$commandContext, modal: false });
  const wakeEnabled = $derived(describe({ id: 'host.wake' }, ctx).enabled);
  const deepScanEnabled = $derived(describe({ id: 'host.deepScan' }, ctx).enabled);
  const openEnabled = $derived(describe({ id: 'host.open' }, ctx).enabled);

  // Why a button is dimmed, for its balloon (4.5); null adds no note.
  const noMac = $derived(selected !== null && !selected.host.fingerprint?.mac_address);
  const busy = $derived($scanProgress.hostScanProgress?.running === true);
  const noTarget = $derived(selected !== null && selected.primaryTarget === null);

  function tabIndex(tab: InfoTab): number {
    return TABS.findIndex((t) => t.id === tab);
  }

  /** Host > Rename…: actions.beginRename has shown the pane and asked
   * for General; apply that to the page first, so the field can take
   * the keyboard. */
  function focusName(): void {
    flushSync();
    general?.focusName();
  }

  onMount(() => {
    tabs = mountTabs(tabsHost, {
      selected: tabIndex(get(ui).infoTab),
      label: 'Host Information',
      onChange: (i) => ui.setInfoTab(TABS[i].id)
    });

    const unbindKeys = bindDialogKeys(openButton, null, {
      ok: () => run({ id: 'host.open' }),
      active: () => get(ui).active
    });
    infoPaneApi.set({ focusName });

    return () => {
      infoPaneApi.set(null);
      unbindKeys();
      tabs = null;
    };
  });

  // The front tab follows ui.infoTab (Get Info, a restored setting).
  $effect(() => {
    const index = tabIndex($ui.infoTab);
    untrack(() => {
      if (tabs && tabs.selected !== index) tabs.select(index, false);
    });
  });
</script>

<div class="lan-pane" hidden={!$ui.infoPaneShown}>
  <div class="lan-tabs" bind:this={tabsHost}>
    <div class="osm-tablist">
      {#each TABS as tab (tab.id)}
        <button class="osm-tab" type="button" use:balloon={TAB_BALLOON[tab.id]}>{tab.title}</button>
      {/each}
    </div>
    <div class="osm-tab-pane">
      <InfoGeneral bind:this={general} row={selected} />
      <InfoPorts row={selected} />
      <InfoFingerprint row={selected} />
    </div>
  </div>

  <div
    class="lan-host-status osm-small"
    role="status"
    aria-live="polite"
    aria-busy={status.busy ? 'true' : undefined}
    use:balloon={STATUS_BALLOON}>{status.text}</div
  >

  <button
    class="osm-button lan-wake"
    type="button"
    use:osmButton={() => run({ id: 'host.wake' })}
    use:dimmable={!wakeEnabled}
    use:balloon={() => wakeBalloon(noMac ? 'noMac' : null)}>Wake</button
  >
  <button
    class="osm-button lan-deep-scan"
    type="button"
    use:osmButton={() => run({ id: 'host.deepScan' })}
    use:dimmable={!deepScanEnabled}
    use:balloon={() => deepScanBalloon(busy ? 'busy' : null)}>Deep Scan</button
  >
  <button
    class="osm-button osm-default lan-open"
    type="button"
    disabled={!openEnabled}
    bind:this={openButton}
    use:osmButton={() => run({ id: 'host.open' })}
    use:balloon={() => openBalloon(noTarget ? 'noTarget' : null)}>Open</button
  >
</div>

<style>
  /* Pane-local geometry of 2.3 (pane height Hp): tab control x 12..287,
     y 8..Hp-90; status line y Hp-78..Hp-53; buttons y Hp-39..Hp-20
     (Open's ring Hp-42..Hp-17). */
  .lan-tabs {
    position: absolute;
    left: 12px;
    top: 8px;
    width: 276px;
    bottom: 89px;
  }

  .lan-host-status {
    position: absolute;
    left: 12px;
    width: 276px;
    bottom: 52px;
    height: 26px;
    line-height: 13px;
    overflow: hidden;
  }

  .lan-wake,
  .lan-deep-scan {
    position: absolute;
    bottom: 19px;
  }

  .lan-wake {
    left: 54px;
  }

  .lan-deep-scan {
    left: 125px;
  }

  .lan-open {
    position: absolute;
    left: 223px;
    bottom: 16px;
  }

  /* The tabs' selectable values (3.3) select in the Highlight Color,
     as Osmium's fields do (osmium.css .osm-edit::selection), and show
     no selection in an inactive window. */
  .lan-pane :global(:is(.lan-value, .lan-line)::selection) {
    background: var(--osm-highlight);
    background: color-mix(in srgb, var(--osm-highlight) 99.6%, transparent);
    color: var(--osm-highlight-text);
  }

  :global(.osm-inactive) .lan-pane :global(:is(.lan-value, .lan-line)::selection) {
    background: transparent;
    color: inherit;
  }
</style>
