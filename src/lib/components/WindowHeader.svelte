<!--
  Owner: unit D (spec 8.4). Spec: 2.3 (window header), 2.9, 5.2, 5.6.
  The Finder window header (.osm-placard, 21px) under the control strip:
  Osmium's chasing arrows (N1) at the Finder's spot, turning while
  headerState() says busy, the header sentence centered on a whole
  pixel in Geneva 10, the scan's progress bar at the right (the
  indeterminate barber pole, N2, in the fingerprint phase), and a
  visually hidden live region that speaks `announce` (5.6).
  The page's CSS owns the region box (.lan-header, position: relative).
  The arrows' span belongs to mountChasingArrows: static class only.
-->
<svelte:options runes={true} />

<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { centerText, mountChasingArrows, type OsmiumChasingArrows } from 'osmium-ui';
  import { HEADER_BALLOON, PROGRESS_BALLOON } from '$lib/app/balloonTexts';
  import { lastError } from '$lib/app/feedback';
  import { headerState } from '$lib/app/headerText';
  import { hostModel } from '$lib/app/hostModel';
  import { ui } from '$lib/app/ui';
  import { areaBalloon, balloon } from '$lib/osm/actions';
  import { findInterfaceByKey, scanProgress, scanStore } from '$lib/util/scanStore';

  /** "today" becomes "yesterday" at midnight without any store change. */
  const CLOCK_TICK_MS = 60_000;

  /** Bumped by the clock tick only to force a recompute; the header
   * reads the clock itself, so a store change never dates a scan by a
   * time up to a tick old (a scan just past midnight would read "on
   * <date>" instead of "today"). */
  let tick = $state(0);
  let headerEl: HTMLDivElement;
  let text: HTMLSpanElement;
  let measure: HTMLSpanElement;
  let arrowsSlot: HTMLSpanElement;
  let arrows: OsmiumChasingArrows | null = $state(null);

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
  /** Whether the whole sentence fits; else its optional end is left
   * out (the first-run hint at the minimum width). */
  let fits = $state(true);
  const shown = $derived(
    header.optional && !fits ? header.text.slice(0, header.text.length - header.optional.length) : header.text
  );
  const bar = $derived(header.progress);
  const indeterminate = $derived(bar !== null && 'indeterminate' in bar);
  /** The determinate bar's numbers, for its ARIA values and fill. */
  const counts = $derived(bar !== null && 'max' in bar ? bar : null);

  /** The whole sentence, measured unclipped, against the text's box. */
  function checkFit(): void {
    fits = measure.offsetWidth <= text.clientWidth;
  }

  $effect(() => {
    void header.text;
    untrack(checkFit);
  });

  // centerText places the text on a whole pixel (and re-centers when the
  // span resizes, as the bar comes and goes); it needs a call after
  // every text change.
  $effect(() => {
    void shown;
    untrack(() => centerText(text));
  });

  // The arrows turn while the header reports work under way (5.2 Busy),
  // from the mount on (the launch's "Reading the last scan…" is busy).
  $effect(() => {
    const control = arrows;
    const busy = header.busy;
    if (!control) return;
    untrack(() => (busy ? control.start() : control.stop()));
  });

  onMount(() => {
    arrows = mountChasingArrows(arrowsSlot);
    const timer = setInterval(() => {
      tick += 1;
    }, CLOCK_TICK_MS);
    // The window's width decides what fits.
    const resize = new ResizeObserver(checkFit);
    resize.observe(headerEl);
    return () => {
      resize.disconnect();
      clearInterval(timer);
      arrows?.destroy();
      arrows = null;
    };
  });
</script>

<div class="lan-header osm-placard" bind:this={headerEl} use:areaBalloon={HEADER_BALLOON}>
  <span class="osm-arrows lan-arrows" bind:this={arrowsSlot}></span>
  <span class="lan-header-text" class:lan-with-bar={bar !== null} bind:this={text}>{shown}</span>
  <span class="lan-header-measure" aria-hidden="true" bind:this={measure}>{header.text}</span>
  {#if bar}
    <!-- Without a value the bar is indeterminate, for ARIA as for Osmium. -->
    <div
      class="osm-progress lan-header-progress"
      class:osm-indeterminate={indeterminate}
      role="progressbar"
      aria-valuemin={counts ? 0 : undefined}
      aria-valuemax={counts?.max}
      aria-valuenow={counts?.value}
      aria-label={bar.label}
      style:--osm-value={counts ? counts.value / counts.max : null}
      use:balloon={PROGRESS_BALLOON}
    >
      <div class="osm-progress-track"><div class="osm-progress-fill"></div></div>
    </div>
  {/if}
  <div class="lan-announce" role="status" aria-live="polite">{header.announce}</div>
</div>

<style>
  /* Positions inside the 21px header (spec 2.3, content x 0..Wc-1).
     The arrows keep Osmium's place for them in a placard (4px in, 2px
     down), measured from the Finder 8.0 header; spec 2.3's x 6..21 was
     a reserved slot before that measurement. */

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

  /* The whole sentence on one line, unseen, for checkFit. */
  .lan-header-measure {
    position: absolute;
    left: 0;
    top: 0;
    visibility: hidden;
    white-space: nowrap;
    pointer-events: none;
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
