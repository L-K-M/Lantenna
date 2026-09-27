<!--
  Owner: unit B (spec 8.4). Spec: 2.6, 3.2, 3.3.
  SCAFFOLD STUB: the empty list area.
  Final: mountListView on this (empty) element with the options and
  columns of 2.6, rows from hostModel coalesced per animation frame,
  placeholders via setEmptyText / setLoadingText, a 60 s refresh(), and
  a HostViewApi published in activeView (views.ts). keyboardFocus
  (focus.ts) classifies focus inside .lan-list as "list".
  The page's CSS fills .lan-view with it (position: absolute; inset: 0).
-->
<svelte:options runes={true} />

<div class="lan-list"></div>

<style>
  .lan-list {
    background: #fff;
  }
</style>
