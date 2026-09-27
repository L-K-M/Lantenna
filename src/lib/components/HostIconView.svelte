<!--
  Owner: unit B (spec 8.4). Spec: 2.8, 3.2, 3.3.
  SCAFFOLD STUB: the empty icon grid area.
  Final: the restyled icon grid (role=listbox, roving tabindex, keys on
  the grid, Osmium vertical scroll bar), a HostViewApi published in
  activeView (views.ts). keyboardFocus (focus.ts) classifies focus
  inside .lan-icons as "icons".
  The page's CSS fills .lan-view with it (position: absolute; inset: 0).
-->
<svelte:options runes={true} />

<div class="lan-icons"></div>

<style>
  .lan-icons {
    background: #fff;
  }
</style>
