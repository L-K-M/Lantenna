<!--
  Owner: unit E (spec 8.4). Spec: 2.5, 4.3.
  SCAFFOLD STUB: an empty 20px Osmium menu bar.
  Final: mountMenuBar(el, menus, { commandKey: "control" }) on this
  element, menus built from menuBarSpec on every open or key press, the
  antenna as the first title, the bar's screen-corner sprites removed
  (.lan-menubar::before/::after { content: none }). Linux only: the page
  renders it when !isMac. The page's CSS owns the region box (20px).
-->
<svelte:options runes={true} />

<div class="lan-menubar osm-menubar"></div>
