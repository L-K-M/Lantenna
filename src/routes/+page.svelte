<!--
  Owner: scaffold (spec 8.3). Spec: 2.1 to 2.10, 8.3 (page skeleton).
  The one Lantenna window: Osmium's hostWindow draws the frame around
  .osm-content, and the regions stack inside it. This file owns the
  region boxes (the CSS below); each component owns what is inside its
  region.
-->
<svelte:options runes={true} />

<script lang="ts">
  import { onMount } from 'svelte';
  import { get } from 'svelte/store';
  import {
    hostWindow,
    isModal,
    onBalloonHelpChange,
    onModalChange,
    setBalloonHelp,
    type WindowOp
  } from 'osmium-ui';

  import ControlStrip from '$lib/components/ControlStrip.svelte';
  import HostIconView from '$lib/components/HostIconView.svelte';
  import HostInfoPane from '$lib/components/HostInfoPane.svelte';
  import HostList from '$lib/components/HostList.svelte';
  import MenuBar from '$lib/components/MenuBar.svelte';
  import WindowHeader from '$lib/components/WindowHeader.svelte';

  import { applySystemColors } from '$lib/app/colors';
  import { installContextMenuGuard } from '$lib/app/contextMenus';
  import { bindWindow, installFeedback } from '$lib/app/feedback';
  import { installKeyboardHome } from '$lib/app/focus';
  import { installPageKeys } from '$lib/app/keys';
  import { MIN_H, MIN_W } from '$lib/app/layout';
  import { installNativeMenu } from '$lib/app/nativeMenu';
  import { isMac } from '$lib/app/platform';
  import { ui } from '$lib/app/ui';
  import { scheduleUpdateCheck } from '$lib/app/updates';
  import { hostedWindow } from '$lib/app/views';
  import { registerAppSprites } from '$lib/osm/sprites';
  import { scanStore } from '$lib/util/scanStore';
  import { windowManager } from '$lib/windowManager';

  let frame: HTMLDivElement;

  /** hostWindow's window ops go to the Tauri window. The fold is mirrored
   * into ui first, the startup winShade { on: false } included. */
  function post(op: WindowOp) {
    if (op.op === 'winShade') ui.setShaded(op.on);
    windowManager.apply(op);
  }

  onMount(() => {
    const disposers: (() => void)[] = [];

    registerAppSprites();

    // Balloon Help: restore the remembered state, remember changes.
    setBalloonHelp(get(ui).balloons);
    disposers.push(onBalloonHelpChange((state) => ui.setBalloons(state)));

    // `post` makes the page native: the zoom and grow sizes are used only
    // by a browser tab without it, so zoom's standard size is a dummy.
    const hosted = hostWindow(frame, {
      title: 'Lantenna',
      post,
      zoom: { standard: { w: 0, h: 0 } },
      grow: { min: { w: MIN_W, h: MIN_H } },
      escape: 'ignore',
      activation: 'manual'
    });
    hostedWindow.set(hosted);
    bindWindow(hosted);

    // hostWindow unfolds the page itself when the window grows tall
    // again while shaded (an OS resize), without posting an op.
    const syncShade = () => ui.setShaded(hosted.shaded);
    window.addEventListener('resize', syncShade);
    disposers.push(() => window.removeEventListener('resize', syncShade));

    // Active while the OS says so and no alert is up (spec 2.10). The
    // backend's activity event keeps the title bar active during a Linux
    // move grab, which takes the keyboard focus.
    let osActive = true;
    const sync = () => hosted.window.setActive(osActive && !isModal());
    disposers.push(onModalChange(sync));
    disposers.push(
      windowManager.subscribeActivity((active) => {
        osActive = active;
        ui.setActive(active);
        sync();
        if (active) void applySystemColors();
      })
    );

    // Feedback subscribes before init, so no store event is missed.
    disposers.push(installFeedback());
    void scanStore.init();
    void applySystemColors();
    if (isMac) disposers.push(installNativeMenu());
    disposers.push(installPageKeys());
    disposers.push(installContextMenuGuard());
    // The host view takes the keyboard now and whenever it has nowhere
    // else to be (spec 3.2).
    disposers.push(installKeyboardHome(frame));
    disposers.push(scheduleUpdateCheck());
    if (isMac) disposers.push(windowManager.trackGrow(frame));
    disposers.push(windowManager.watchResize());

    return () => {
      for (const dispose of disposers.reverse()) dispose();
      scanStore.destroy();
      hostedWindow.set(null);
      hosted.destroy();
    };
  });
</script>

<div class="osm-page-window" bind:this={frame}>
  <div class="osm-content lan-content">
    {#if !isMac}<MenuBar />{/if}
    <ControlStrip />
    <WindowHeader />
    <div class="lan-main" class:lan-no-pane={!$ui.infoPaneShown}>
      <div class="lan-view">
        {#if $ui.viewMode === 'list'}<HostList />{:else}<HostIconView />{/if}
      </div>
      <HostInfoPane />
    </div>
  </div>
</div>

<style>
  .lan-content {
    display: flex;
    flex-direction: column;
  }

  /* Osmium hides a collapsed window's content with .osm-shaded
     .osm-content; the scoped rule above has the same specificity and
     may load later, so hide it here too. */
  :global(.osm-shaded) .lan-content {
    display: none;
  }

  /* Region boxes (spec 2.3). The regions are rendered by child
     components, hence :global. */
  .lan-content > :global(.lan-menubar) {
    flex: none;
  }

  .lan-content > :global(.lan-strip) {
    flex: none;
    height: 64px;
    position: relative;
  }

  .lan-content > :global(.lan-header) {
    flex: none;
    position: relative;
  }

  .lan-main {
    flex: 1;
    min-height: 0;
    display: flex;
  }

  .lan-view {
    flex: 1;
    min-width: 0;
    position: relative;
    border-right: 1px solid #000;
  }

  .lan-no-pane .lan-view {
    border-right: 0;
  }

  .lan-view > :global(.lan-list),
  .lan-view > :global(.lan-icons) {
    position: absolute;
    inset: 0;
  }

  .lan-main > :global(.lan-pane) {
    flex: none;
    width: 300px;
    position: relative;
    box-shadow: inset 1px 0 #fff;
  }

  .lan-main > :global(.lan-pane[hidden]) {
    display: none;
  }
</style>
