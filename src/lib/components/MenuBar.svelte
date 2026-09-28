<!--
  Owner: unit E (spec 8.4). Spec: 2.5, 4.3.
  The Linux menu bar: Osmium's mountMenuBar inside the window, the
  antenna standing in for the Apple menu, Control as the command key
  (drawn as the command key symbol; aria-keyshortcuts names Control).
  Items are built from menuBarSpec each time a menu opens or a key
  equivalent is typed, so they are always current; dimmed items (no
  action) take no keys. The bar's rounded screen-corner sprites are
  removed: this bar sits inside a window, not along a screen's top.
  Linux only: the page renders it when !isMac, and the page's CSS owns
  the region box (20px). The element is Osmium's: static class only.
-->
<svelte:options runes={true} />

<script lang="ts">
  import { onMount } from 'svelte';
  import { get } from 'svelte/store';
  import { mountMenuBar, type Menu } from 'osmium-ui';
  import { commandContext, menuBarSpec, osmiumMenuEntries, type CommandContext } from '$lib/app/commands';
  import { classifyFocus, type FocusKind } from '$lib/app/focus';

  let bar: HTMLDivElement;

  onMount(() => {
    // Keeps commandContext (and its focus tracking) live while the bar
    // exists, so items() reads the current state without a fresh start.
    const unsubscribe = commandContext.subscribe(() => {});

    // An open menu holds the keyboard, and moving to another title
    // leaves it nowhere, so the Edit items describe where the keyboard
    // was when the menu opened; Osmium gives it back there before an
    // item's action runs.
    let focusAtOpen: FocusKind = 'other';
    const menuOpen = () => bar.querySelector('[aria-expanded="true"]') !== null;
    const remember = () => {
      if (!menuOpen()) focusAtOpen = classifyFocus(document.activeElement);
    };
    bar.addEventListener('pointerdown', remember, true);
    bar.addEventListener('keydown', remember, true);

    const context = (): CommandContext => {
      const ctx = get(commandContext);
      return menuOpen() ? { ...ctx, focus: focusAtOpen } : ctx;
    };

    // The menus and their titles never change; their items do.
    const menus: Menu[] = menuBarSpec(get(commandContext)).map((spec) => ({
      title: spec.title,
      ...(spec.icon === undefined ? {} : { icon: spec.icon }),
      items: () => {
        const ctx = context();
        const current = menuBarSpec(ctx).find((m) => m.id === spec.id);
        return current ? osmiumMenuEntries(current.entries, ctx, 'menubar') : [];
      }
    }));
    mountMenuBar(bar, menus, { commandKey: 'control' });

    // No teardown for the bar itself: removing its element ends it
    // (Osmium drops its document listeners at the next event).
    return unsubscribe;
  });
</script>

<div class="lan-menubar osm-menubar" bind:this={bar}></div>

<style>
  .lan-menubar::before,
  .lan-menubar::after {
    content: none;
  }
</style>
