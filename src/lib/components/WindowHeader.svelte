<!--
  Owner: unit D (spec 8.4). Spec: 2.3 (window header), 2.9, 5.2, 5.6.
  The Finder window header (.osm-placard, 21px) under the control strip:
  the reserved 16px slot for chasing arrows (Osmium N1; empty until it
  exists), the header sentence of headerState() centered on a whole
  pixel in Geneva 10, the scan's progress bar at the right, and a
  visually hidden live region that speaks `announce` (5.6).
  The page's CSS owns the region box (.lan-header, position: relative).
-->
<svelte:options runes={true} />

<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { centerText } from 'osmium-ui';
  import { HEADER_BALLOON, PROGRESS_BALLOON } from '$lib/app/balloonTexts';
  import { lastError } from '$lib/app/feedback';
  import { headerState } from '$lib/app/headerText';
  import { hostModel } from '$lib/app/hostModel';
  import { ui } from '$lib/app/ui';
  import { balloon } from '$lib/osm/actions';
  import { findInterfaceByKey, scanProgress, scanStore } from '$lib/util/scanStore';

  /** "today" becomes "yesterday" at midnight without any store change. */
  const CLOCK_TICK_MS = 60_000;

  /** Bumped by the clock tick only to force a recompute; the header
   * reads the clock itself, so a store change never dates a scan by a
   * time up to a tick old (a scan just past midnight would read "on
   * <date>" instead of "today"). */
  let tick = $state(0);
  let text: HTMLSpanElement;

  const header = $derived.by(() => {
    void tick;
    return headerState(
      {
        store: $scanStore,
        progress: $scanProgress,
        model: $hostModel,
        lastError: $lastError,
        selectedInterface: findInterfaceByKey($scanStore.interfaces, $scanStore.selectedInterface),
        balloons: $ui.balloons
      },
      new Date()
    );
  });
  const bar = $derived(header.progress);

  // centerText places the text on a whole pixel (and re-centers when the
  // span resizes, as the bar comes and goes); it needs a call after
  // every text change.
  $effect(() => {
    void header.text;
    untrack(() => centerText(text));
  });

  onMount(() => {
    const timer = setInterval(() => {
      tick += 1;
    }, CLOCK_TICK_MS);
    return () => clearInterval(timer);
  });
</script>

<div class="lan-header osm-placard" use:balloon={HEADER_BALLOON}>
  <span class="lan-arrows" aria-hidden="true"></span>
  <span class="lan-header-text" class:lan-with-bar={bar !== null} bind:this={text}>{header.text}</span>
  {#if bar}
    <div
      class="osm-progress lan-header-progress"
      role="progressbar"
      aria-valuemin="0"
      aria-valuemax={bar.max}
      aria-valuenow={bar.value}
      aria-label={bar.label}
      style:--osm-value={bar.value / bar.max}
      use:balloon={PROGRESS_BALLOON}
    >
      <div class="osm-progress-track"><div class="osm-progress-fill"></div></div>
    </div>
  {/if}
  <div class="lan-announce" role="status" aria-live="polite">{header.announce}</div>
</div>

<style>
  /* Positions inside the 21px header (spec 2.3, content x 0..Wc-1). */
  .lan-arrows {
    position: absolute;
    left: 6px;
    top: 2px;
    width: 16px;
    height: 16px;
  }

  /* x 28..Wc-29, or 28..Wc-138 beside the bar; the placard's Geneva 10
     line box starts 4px down. centerText sets the indent. */
  .lan-header-text {
    position: absolute;
    left: 28px;
    right: 28px;
    top: 4px;
    overflow: hidden;
    white-space: nowrap;
    text-overflow: ellipsis;
  }

  .lan-header-text.lan-with-bar {
    right: 137px;
  }

  /* 120 x 14 at x Wc-129..Wc-10, y 3..16. */
  .lan-header-progress {
    position: absolute;
    right: 9px;
    top: 3px;
    width: 120px;
  }

  .lan-announce {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip-path: inset(50%);
    white-space: nowrap;
  }
</style>
