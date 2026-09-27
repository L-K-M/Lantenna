<!--
  Owner: unit C (spec 8.4). Spec: 2.7 (General), 3.1 (1.10 to 1.12,
  1.18, 1.22), 3.2 (name field keys).
  The General panel for `row` (null: no selection): the 32 x 32 icon,
  the name field (the rename control), the icon label, the Get Info
  fields and the Favorite and Hidden checkboxes.
  The root element is Osmium-owned once HostInfoPane runs mountTabs (it
  sets hidden, id, role and aria-labelledby): static class only, and no
  display on it.
-->
<svelte:options runes={true} />

<script lang="ts">
  import { untrack } from 'svelte';
  import { centerText } from 'osmium-ui';
  import { FAVORITE_BALLOON, HIDDEN_BALLOON, NAME_BALLOON } from '$lib/app/balloonTexts';
  import type { HostRow } from '$lib/app/hostModel';
  import { commitName, nameFieldValue } from '$lib/app/nameCommit';
  import { balloon, checkboxBalloon, highlight } from '$lib/osm/actions';
  import { formatLongDate } from '$lib/util/format';
  import { scanStore } from '$lib/util/scanStore';

  let { row }: { row: HostRow | null } = $props();

  let field: HTMLInputElement | undefined = $state();

  // The draft belongs to `draftRow`. `shown` is the value the field last
  // took from the model: the draft differs from it only while the reader
  // has an edit in progress. Without one, the field follows the model (a
  // name cleared from a menu shows at once; BUG-7); with one, a
  // selection change commits it to the host it was typed for.
  let draft = $state('');
  let shown = '';
  let draftRow: HostRow | null = null;

  $effect.pre(() => {
    const next = row;
    untrack(() => follow(next));
  });

  function follow(next: HostRow | null): void {
    const previous = draftRow;
    const sameHost = previous !== null && next !== null && previous.ip === next.ip;
    draftRow = next;

    if (!sameHost && previous !== null && draft !== shown) commit(previous);

    const value = next ? nameFieldValue(next.host, next.customName) : '';
    if (!sameHost || draft === shown) draft = value;
    shown = value;
  }

  /** Apply the draft to `target`'s custom name (2.7's rule) and show
   * the value the model will have. */
  function commit(target: HostRow): void {
    const result = commitName(draft, target.host, target.customName);

    switch (result.action) {
      case 'none':
        draft = shown = nameFieldValue(target.host, target.customName);
        return;
      case 'clear':
        draft = shown = nameFieldValue(target.host, null);
        scanStore.setCustomName(target.ip, '');
        return;
      case 'set':
        draft = shown = result.name;
        scanStore.setCustomName(target.ip, result.name);
        return;
    }
  }

  function onKeydown(e: KeyboardEvent): void {
    // The Return that ends an input method's composition is the method's.
    if (e.isComposing || e.keyCode === 229) return;

    if (e.key === 'Enter') {
      // Keeps bindDialogKeys from pressing Open.
      e.preventDefault();
      if (draftRow && draft !== shown) commit(draftRow);
      return;
    }

    // Escape drops the edit in progress: back to `shown`, which is the
    // value on focus unless a Return commit or the model (a menu's
    // rename or Clear Custom Name) changed the name since. Going back to
    // the older value would let the next commit undo that change.
    if (e.key === 'Escape') {
      // An open help balloon took this Escape to close itself.
      if (e.defaultPrevented) return;
      e.preventDefault();
      draft = shown;
    }
  }

  function onFocusOut(): void {
    if (draftRow && draft !== shown) commit(draftRow);
  }

  /** Host > Rename… (through HostInfoPane's InfoPaneApi). */
  export function focusName(select: boolean): void {
    if (!field) return;

    field.focus();
    if (select) field.select();
  }

  /** Centered on a whole pixel, as Osmium centers a list's placeholder. */
  function centered(node: HTMLElement): void {
    centerText(node);
  }

  function reachableOf(r: HostRow): string {
    if (r.stale) return 'No (not found in the last scan)';
    return r.host.reachable ? 'Yes' : 'No';
  }
</script>

<div class="lan-info-general">
  <div class="lan-none osm-small" hidden={row !== null} use:centered>Select a host to see its information.</div>

  {#if row}
    {@const ip = row.ip}
    <div class="lan-icon" role="img" aria-label={row.icon.label} style:background-image={`url("${row.icon.large}")`}></div>
    <input
      class="osm-edit lan-name"
      type="text"
      aria-label="Name"
      autocomplete="off"
      spellcheck="false"
      bind:this={field}
      bind:value={draft}
      onkeydown={onKeydown}
      onfocusout={onFocusOut}
      use:balloon={NAME_BALLOON}
    />
    <div class="lan-kind osm-small">{row.icon.label}</div>

    <div class="osm-separator lan-rule"></div>

    <div class="osm-fields osm-small lan-fields">
      <span class="osm-label">IP Address:</span><span class="lan-value">{row.ip}</span>
      <span class="osm-label">MAC Address:</span><span class="lan-value">{row.host.fingerprint?.mac_address || 'Unknown'}</span>
      <span class="osm-label">Vendor:</span><span class="lan-value">{row.vendorFull}</span>
      <span class="osm-label">Detected Name:</span><span class="lan-value">{row.host.name || 'None'}</span>
      <span class="osm-label">Reachable:</span><span class="lan-value">{reachableOf(row)}</span>
      <span class="osm-label">Last Seen:</span><span class="lan-value">{formatLongDate(row.host.last_seen)}</span>
    </div>

    <label class="osm-checkbox lan-check lan-favorite" use:highlight use:checkboxBalloon={FAVORITE_BALLOON}>
      <input type="checkbox" checked={row.favorite} onchange={() => scanStore.toggleFavorite(ip)} />Favorite
    </label>
    <label class="osm-checkbox lan-check lan-hidden" use:highlight use:checkboxBalloon={HIDDEN_BALLOON}>
      <input type="checkbox" checked={row.hidden} onchange={() => scanStore.toggleHidden(ip)} />Hidden
    </label>
  {/if}
</div>

<style>
  /* Panel-local coordinates of 2.7: 10px sides, 12px top. */
  .lan-info-general {
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

  .lan-icon {
    position: absolute;
    left: 10px;
    top: 12px;
    width: 32px;
    height: 32px;
    background: center / 32px 32px no-repeat;
    image-rendering: pixelated;
  }

  .lan-name {
    position: absolute;
    left: 52px;
    top: 17px;
    width: calc(100% - 62px);
  }

  .lan-kind {
    position: absolute;
    left: 52px;
    right: 10px;
    top: 43px;
    line-height: 13px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .lan-rule {
    position: absolute;
    left: 10px;
    right: 10px;
    top: 62px;
  }

  /* Labels end at x 96 ("Detected Name:" is 86px wide), the same edge
     as the Fingerprint panel's. */
  .lan-fields {
    position: absolute;
    left: 10px;
    right: 10px;
    top: 72px;
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

  .lan-check {
    position: absolute;
    left: 100px;
    white-space: nowrap;
  }

  .lan-favorite {
    top: 180px;
  }

  .lan-hidden {
    top: 198px;
  }
</style>
