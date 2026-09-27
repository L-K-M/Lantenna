<!--
  Owner: unit C (spec 8.4). Spec: 2.7 (Fingerprint), 3.1 (1.18, 1.22).
  The Fingerprint panel for `row` (null: no selection): Type, OS, Model
  and the confidence meter, then the fingerprint's sources and notes in
  a read-only Osmium text view.
  The root element is Osmium-owned once HostInfoPane runs mountTabs:
  static class only, and no display on it. The notes view's host
  belongs to mountTextView.
-->
<svelte:options runes={true} />

<script module lang="ts">
  import type { DeviceFingerprint } from '$lib/types';

  /** The notes view's text: "Sources: a, b, c", a blank line, one note
   * per line; "Not identified yet." without a fingerprint (or with
   * nothing in it). */
  export function notesText(fp: DeviceFingerprint | null): string {
    const sources = fp?.sources ?? [];
    const notes = fp?.notes ?? [];
    const parts: string[] = [];

    if (sources.length > 0) parts.push(`Sources: ${sources.join(', ')}`);
    if (notes.length > 0) parts.push(notes.join('\n'));

    return parts.length > 0 ? parts.join('\n\n') : 'Not identified yet.';
  }

  /** Whole percent for the meter, 0 to 100 (the backend clamps to 5..99). */
  export function confidencePercent(fp: DeviceFingerprint): number {
    return Number.isFinite(fp.confidence) ? Math.min(100, Math.max(0, Math.round(fp.confidence))) : 0;
  }
</script>

<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { centerText, mountTextView, type OsmiumTextView } from 'osmium-ui';
  import { NOTES_BALLOON } from '$lib/app/balloonTexts';
  import type { HostRow } from '$lib/app/hostModel';
  import { balloon } from '$lib/osm/actions';

  let { row }: { row: HostRow | null } = $props();

  let notesHost: HTMLDivElement;
  let view: OsmiumTextView | null = null;

  const fp = $derived(row?.host.fingerprint ?? null);
  const notes = $derived(notesText(fp));
  const percent = $derived(fp ? confidencePercent(fp) : null);

  onMount(() => {
    view = mountTextView(notesHost, {
      label: 'Sources and notes',
      text: notes,
      mode: 'read-only',
      font: 'geneva-10'
    });
    const help = balloon(view.textarea, NOTES_BALLOON);

    return () => {
      help.destroy?.();
      view?.destroy();
      view = null;
    };
  });

  $effect(() => {
    const text = notes;
    untrack(() => {
      // setText resets the scroll and the selection: only for new text.
      if (view && view.text !== text) view.setText(text);
    });
  });

  function centered(node: HTMLElement): void {
    centerText(node);
  }
</script>

<div class="lan-info-fingerprint">
  <div class="lan-none osm-small" hidden={row !== null} use:centered>Select a host to see its information.</div>

  <div class="lan-body" hidden={row === null}>
    <div class="osm-fields osm-small lan-fields">
      <span class="osm-label">Type:</span><span class="lan-value">{fp?.device_type || 'Unknown'}</span>
      <span class="osm-label">OS:</span><span class="lan-value">{fp?.os_guess || 'Unknown'}</span>
      <span class="osm-label">Model:</span><span class="lan-value">{fp?.model_guess || 'Unknown'}</span>
      <span class="osm-label">Confidence:</span>
      {#if percent === null}
        <span class="lan-value">n/a</span>
      {:else}
        <div class="lan-confidence">
          <div
            class="osm-progress lan-meter"
            role="meter"
            aria-label="Confidence"
            aria-valuemin="0"
            aria-valuemax="100"
            aria-valuenow={percent}
            style:--osm-value={percent / 100}
          >
            <div class="osm-progress-track"><div class="osm-progress-fill"></div></div>
          </div><span class="lan-percent" aria-hidden="true">{percent}%</span>
        </div>
      {/if}
    </div>

    <div class="osm-separator lan-rule"></div>
    <div class="osm-label osm-small lan-notes-title">Sources and notes:</div>
    <div class="lan-notes" bind:this={notesHost}></div>
  </div>
</div>

<style>
  .lan-info-fingerprint {
    position: absolute;
    inset: 0;
  }

  .lan-none {
    position: absolute;
    left: 0;
    right: 0;
    top: 24px;
    color: #888;
    white-space: nowrap;
    overflow: hidden;
  }

  .lan-body {
    position: absolute;
    inset: 0;
  }

  /* Labels end at x 96, as on the General panel. */
  .lan-fields {
    position: absolute;
    left: 10px;
    right: 10px;
    top: 12px;
    grid-template-columns: minmax(86px, max-content) minmax(0, 1fr);
  }

  .lan-value {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    user-select: text;
    -webkit-user-select: text;
    cursor: text;
  }

  .lan-confidence {
    display: flex;
    align-items: flex-start;
    white-space: nowrap;
  }

  /* The 14px bar on the 17px row, level with the text's box. */
  .lan-meter {
    flex: none;
    width: 100px;
    margin-top: 2px;
  }

  .lan-percent {
    margin-left: 6px;
  }

  .lan-rule {
    position: absolute;
    left: 10px;
    right: 10px;
    top: 88px;
  }

  .lan-notes-title {
    position: absolute;
    left: 10px;
    right: 10px;
    top: 96px;
    line-height: 13px;
  }

  /* A framed scrolling text box: the scroll bar's black edges lie on the
     frame (Osmium puts them 1px outside the host's padding box). The
     document window's bottom strip, which leaves room for a grow box,
     has no place in a panel. */
  .lan-notes {
    position: absolute;
    left: 10px;
    right: 10px;
    top: 112px;
    bottom: 10px;
    border: 1px solid #000;
  }

  .lan-notes > :global(.osm-textview-strip) {
    display: none;
  }

  .lan-notes > :global(.osm-scrollbar) {
    bottom: -1px;
  }

  .lan-notes > :global(textarea),
  .lan-notes > :global(.osm-textview-highlight),
  .lan-notes > :global(.osm-textview-mirror) {
    bottom: 4px;
  }
</style>
