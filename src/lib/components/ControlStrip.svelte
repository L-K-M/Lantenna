<!--
  Owner: unit D (spec 8.4). Spec: 2.3 (strip rows), 2.9, 3.1 (1.5 to 1.9), 3.2, 4.5.
  The controls on the gray above the list, at the positions of table 2.3:
    row 1  Interface: [pop-up]  Depth: [pop-up]  (Scan)
    row 2       Show: [pop-up]  [ ] Show hidden hosts        Find: [field]
  The pop-ups, the button and the checkbox are commands (4.1): their
  enabled states come from describe() and their actions go through
  run(), so they always agree with the menus. The Find field edits the
  store's query directly.
  The page's CSS owns the region box (.lan-strip, 64px, position: relative).
-->
<svelte:options runes={true} />

<script lang="ts">
  import { untrack } from 'svelte';
  import { get } from 'svelte/store';
  import { setButtonTitle } from 'osmium-ui';
  import type { PopupParams } from '$lib/osm/actions';
  import { balloon, checkboxBalloon, highlight, osmButton, popup } from '$lib/osm/actions';
  import {
    DEPTH_BALLOON,
    FIND_BALLOON,
    SHOW_BALLOON,
    interfaceBalloon,
    scanBalloon,
    showHiddenBalloon,
    type ScanButtonState
  } from '$lib/app/balloonTexts';
  import { commandContext, describe, run, type CommandContext, type CommandRef } from '$lib/app/commands';
  import { hostModel } from '$lib/app/hostModel';
  import { ui, type ShowScope } from '$lib/app/ui';
  import { activeView, FIND_FIELD_ID } from '$lib/app/views';
  import type { ScanApproach } from '$lib/types';
  import { findInterfaceByKey, interfaceKey, scanStore } from '$lib/util/scanStore';

  const DEPTHS: readonly { approach: ScanApproach; title: string }[] = [
    { approach: 'fast', title: 'Fast' },
    { approach: 'balanced', title: 'Balanced' },
    { approach: 'thorough', title: 'Thorough' }
  ];

  const SCOPES: readonly { scope: ShowScope; title: string }[] = [
    { scope: 'all', title: 'All Hosts' },
    { scope: 'favorites', title: 'Favorite Hosts' },
    { scope: 'new', title: 'New Hosts' }
  ];

  const SCAN_TITLES: Readonly<Record<ScanButtonState, string>> = {
    idle: 'Scan',
    noInterface: 'Scan',
    stop: 'Stop',
    stopping: 'Stopping…'
  };

  const INTERFACE_ID = 'lan-interface';
  const DEPTH_ID = 'lan-depth';
  const SHOW_ID = 'lan-show';

  /** A key the input method is composing with (Safari's last one). */
  const IME_KEY_CODE = 229;

  let scanButton: HTMLButtonElement;
  let showHiddenBox: HTMLInputElement;

  const store = $derived($scanStore);
  const interfaces = $derived(store.interfaces);
  const currentInterface = $derived(findInterfaceByKey(interfaces, store.selectedInterface));

  /** Controls take their enabled state from the command model. They
   * ignore its "alert up" rule: behind an alert the window draws
   * inactive, which dims them anyway, and a control that stays enabled
   * can take the keyboard back when the alert closes. */
  const ctx: CommandContext = $derived({ ...$commandContext, modal: false });
  const enabled = (ref: CommandRef): boolean => describe(ref, ctx).enabled;

  const scanState: ScanButtonState = $derived(
    store.stopping
      ? 'stopping'
      : store.scanning
        ? 'stop'
        : !store.loading && currentInterface === null
          ? 'noInterface'
          : 'idle'
  );
  const scanEnabled = $derived(enabled({ id: 'scan.toggle' }));

  // Interface: one item per interface, `name (subnet)`; a single dimmed
  // "No interfaces found" when there are none; nothing while the store
  // is still reading them.
  const interfaceItems: PopupParams['items'] = $derived(
    interfaces.length > 0
      ? interfaces.map((item) => `${item.name} (${item.subnet})`)
      : store.loading
        ? []
        : [{ title: 'No interfaces found', disabled: true }]
  );
  const interfaceIndex = $derived(currentInterface ? Math.max(0, interfaces.indexOf(currentInterface)) : 0);
  const interfaceEnabled = $derived(
    currentInterface !== null && enabled({ id: 'scan.interface', arg: interfaceKey(currentInterface) })
  );

  const depthIndex = $derived(Math.max(0, DEPTHS.findIndex((d) => d.approach === store.scanApproach)));
  const depthEnabled = $derived(enabled({ id: 'scan.depth', arg: store.scanApproach }));

  const scopeIndex = $derived(Math.max(0, SCOPES.findIndex((s) => s.scope === $ui.scope)));
  const scopeEnabled = $derived(enabled({ id: 'view.scope', arg: $ui.scope }));

  const showHidden = $derived(store.showHiddenEntries);
  const showHiddenEnabled = $derived(enabled({ id: 'view.showHidden' }));

  // Balloon texts that follow the state. Passed as strings, so the
  // balloon action's update replaces the message (and the description
  // screen readers get) whenever it changes; a content function would
  // re-run only on the target's attribute changes.
  const interfaceHelp = $derived(interfaceBalloon(store.scanning ? 'scanning' : null));
  const scanHelp = $derived(scanBalloon(scanState));
  const showHiddenHelp = $derived(showHiddenBalloon(!showHiddenEnabled && !showHidden ? 'noneHidden' : null));

  $effect(() => {
    const title = SCAN_TITLES[scanState];
    untrack(() => setButtonTitle(scanButton, title));
  });

  /** Bumped when a command refused a pop-up's choice: the pop-ups'
   * parameters are rebuilt, and the refused one shows the store's value
   * again (the action's update calls setSelected). */
  let resync = $state(0);

  /** Run a pop-up's command; `applied` says whether the store took it. */
  function choose(ref: CommandRef, applied: () => boolean) {
    run(ref);
    if (!applied()) resync += 1;
  }

  const interfaceParams: PopupParams = $derived.by(() => {
    void resync;
    return {
      items: interfaceItems,
      selected: interfaceIndex,
      label: 'Interface',
      disabled: !interfaceEnabled,
      onChange: (i: number) => {
        const item = get(scanStore).interfaces[i];
        if (!item) return;
        const key = interfaceKey(item);
        choose({ id: 'scan.interface', arg: key }, () => get(scanStore).selectedInterface === key);
      }
    };
  });

  const depthParams: PopupParams = $derived.by(() => {
    void resync;
    return {
      items: DEPTHS.map((d) => d.title),
      selected: depthIndex,
      label: 'Depth',
      disabled: !depthEnabled,
      onChange: (i: number) => {
        const { approach } = DEPTHS[i];
        choose({ id: 'scan.depth', arg: approach }, () => get(scanStore).scanApproach === approach);
      }
    };
  });

  const scopeParams: PopupParams = $derived.by(() => {
    void resync;
    return {
      items: SCOPES.map((s) => s.title),
      selected: scopeIndex,
      label: 'Show',
      disabled: !scopeEnabled,
      onChange: (i: number) => {
        const { scope } = SCOPES[i];
        choose({ id: 'view.scope', arg: scope }, () => get(ui).scope === scope);
      }
    };
  });

  function toggleShowHidden() {
    run({ id: 'view.showHidden' });
    // The box toggled natively; show the store's answer.
    showHiddenBox.checked = get(scanStore).showHiddenEntries;
  }

  function onFindKey(e: KeyboardEvent) {
    if (e.isComposing || e.keyCode === IME_KEY_CODE || e.metaKey || e.ctrlKey || e.altKey) return;

    if (e.key === 'Escape') {
      // An open help balloon took this Escape to close itself.
      if (e.defaultPrevented) return;
      e.preventDefault();
      scanStore.setQuery('');
      return;
    }

    if (e.key !== 'Enter') return;
    // Before bindDialogKeys (on window) would press Open.
    e.preventDefault();
    const view = get(activeView);
    if (!view) return;

    const { rows } = get(hostModel);
    const selected = get(scanStore).selectedHostIp;
    const first = rows[0];
    if (first && !rows.some((row) => row.ip === selected)) {
      scanStore.setSelectedHost(first.ip);
      view.reveal(first.ip);
    }
    view.focus();
  }
</script>

<div class="lan-strip">
  <label class="osm-popup-title lan-label lan-row1" class:osm-disabled={!interfaceEnabled} for={INTERFACE_ID}>
    Interface:
  </label>
  <!-- mountPopup writes the title and an aria-label naming the choice. -->
  <!-- svelte-ignore a11y_consider_explicit_label -->
  <button
    type="button"
    class="osm-popup lan-interface"
    id={INTERFACE_ID}
    use:popup={interfaceParams}
    use:balloon={interfaceHelp}
  ></button>

  <label class="osm-popup-title lan-label lan-row1 lan-depth-label" class:osm-disabled={!depthEnabled} for={DEPTH_ID}>
    Depth:
  </label>
  <!-- mountPopup writes the title and an aria-label naming the choice. -->
  <!-- svelte-ignore a11y_consider_explicit_label -->
  <button
    type="button"
    class="osm-popup lan-depth"
    id={DEPTH_ID}
    use:popup={depthParams}
    use:balloon={DEPTH_BALLOON}
  ></button>

  <button
    type="button"
    class="osm-button lan-scan"
    data-width="82"
    disabled={!scanEnabled}
    bind:this={scanButton}
    use:osmButton={() => run({ id: 'scan.toggle' })}
    use:balloon={scanHelp}
  >
    Scan
  </button>

  <label class="osm-popup-title lan-label lan-row2" class:osm-disabled={!scopeEnabled} for={SHOW_ID}>Show:</label>
  <!-- mountPopup writes the title and an aria-label naming the choice. -->
  <!-- svelte-ignore a11y_consider_explicit_label -->
  <button
    type="button"
    class="osm-popup lan-show"
    id={SHOW_ID}
    use:popup={scopeParams}
    use:balloon={SHOW_BALLOON}
  ></button>

  <label
    class="osm-checkbox lan-show-hidden"
    class:osm-disabled={!showHiddenEnabled}
    use:highlight
    use:checkboxBalloon={showHiddenHelp}
  >
    <input
      type="checkbox"
      checked={showHidden}
      disabled={!showHiddenEnabled}
      bind:this={showHiddenBox}
      onchange={toggleShowHidden}
    />
    Show hidden hosts
  </label>

  <label class="lan-find-label" for={FIND_FIELD_ID}>Find:</label>
  <!-- The accessible name starts with the visible label (WCAG 2.5.3, so
       "click Find" reaches it by voice) and keeps the old detail. -->
  <input
    type="text"
    class="osm-edit osm-compact lan-find"
    id={FIND_FIELD_ID}
    aria-label="Find hosts by name, IP, vendor, type, MAC, port or service"
    autocomplete="off"
    autocapitalize="off"
    spellcheck="false"
    bind:value={() => store.query, (query: string) => scanStore.setQuery(query)}
    onkeydown={onFindKey}
    use:balloon={FIND_BALLOON}
  />
</div>

<style>
  /* Positions inside the 64px strip (spec 2.3). Labels are right-aligned
     to x 73 and sit 1px below their pop-up (2px beside the compact
     field), so the baselines meet. */
  .lan-strip > * {
    position: absolute;
  }

  .lan-label {
    right: calc(100% - 74px);
    white-space: nowrap;
  }

  .lan-row1 {
    top: 9px;
  }

  .lan-row2 {
    top: 37px;
  }

  /* "Depth:" ends at x 374. */
  .lan-label.lan-depth-label {
    right: calc(100% - 375px);
  }

  .lan-interface {
    left: 79px;
    top: 8px;
    width: 240px;
  }

  .lan-depth {
    left: 380px;
    top: 8px;
    width: 110px;
  }

  /* 82px wide (data-width): "Stopping…" with the HIG's 8px either side. */
  .lan-scan {
    left: 506px;
    top: 8px;
  }

  .lan-show {
    left: 79px;
    top: 36px;
    width: 120px;
  }

  .lan-show-hidden {
    left: 215px;
    top: 37px;
    white-space: nowrap;
  }

  /* Right-aligned: the field ends 12px from the strip's right edge, its
     label 5px before it. */
  .lan-find-label {
    right: 217px;
    top: 38px;
    font: var(--osm-font-system);
    white-space: nowrap;
  }

  .lan-find {
    right: 12px;
    top: 36px;
    width: 200px;
  }
</style>
