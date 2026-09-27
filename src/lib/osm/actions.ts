// Owner: scaffold (spec 8.3), complete. Spec: 2.3, 4.5, 8.3 (element rules).
//
// Svelte actions around Osmium controls. The element an action runs on
// belongs to Osmium: give it a static class and leave it empty in the
// template (Osmium writes a pop-up's title and a button's layout into
// it); use class: and style: directives only, never class={...} or
// style={...}, which would wipe what Osmium set.

import type { ActionReturn } from 'svelte/action';
import { attachBalloon, mountPopup, pushButton, trackHighlight } from 'osmium-ui';
import type { BalloonOptions, PopupOptions } from 'osmium-ui';

export interface PopupParams {
  /** Titles, { title, disabled } items (drawn dimmed, can't be chosen)
   * and MENU_SEPARATOR, as Osmium's PopupOptions.items. */
  items: PopupOptions['items'];
  selected: number;
  /** The accessible name, read once at mount. */
  label: string;
  disabled?: boolean;
  onChange(i: number): void;
}

type PopupEntry = PopupOptions['items'][number];

function sameEntry(a: PopupEntry, b: PopupEntry): boolean {
  if (a === b) return true;
  if (typeof a !== 'object' || typeof b !== 'object') return false;
  return a.title === b.title && Boolean(a.disabled) === Boolean(b.disabled);
}

function sameItems(a: PopupOptions['items'], b: PopupOptions['items']): boolean {
  return a === b || (a.length === b.length && a.every((entry, i) => sameEntry(entry, b[i])));
}

/**
 * `<button class="osm-popup" use:popup={{ items, selected, label, onChange }}></button>`.
 * Updates call setItems only when the items really changed (a new array
 * with the same titles is no change), else setSelected when the
 * selection moved, so an open menu isn't rebuilt on every store tick.
 */
export function popup(node: HTMLButtonElement, p: PopupParams): ActionReturn<PopupParams> {
  let params = p;
  node.disabled = Boolean(p.disabled);
  const handle = mountPopup(node, {
    items: p.items,
    selected: p.selected,
    label: p.label,
    onChange: (i) => params.onChange(i)
  });

  return {
    update(next) {
      const previous = params;
      params = next;
      node.disabled = Boolean(next.disabled);

      if (!sameItems(previous.items, next.items)) {
        handle.setItems(next.items, next.selected);
        return;
      }

      if (next.selected !== handle.selected) handle.setSelected(next.selected);
    },
    destroy() {
      handle.destroy();
    }
  };
}

/**
 * `<button class="osm-button" use:osmButton={action}>Title</button>`: press
 * tracking and title layout (pushButton). Change the title with Osmium's
 * setButtonTitle, not the template, so the layout follows. Osmium has no
 * teardown for push buttons; their listeners go with the element.
 */
export function osmButton(node: HTMLButtonElement, action: () => void): ActionReturn<() => void> {
  let current = action;
  pushButton(node, () => current());

  return {
    update(next) {
      current = next;
    }
  };
}

/** `<label class="osm-checkbox" use:highlight>`: the pressed look while a
 * press lasts (trackHighlight); the input toggles natively. */
export function highlight(node: HTMLElement): void {
  trackHighlight(node);
}

/**
 * `use:balloon={content}`: Balloon Help for the element, shown only while
 * Help > Show Balloons is on (trigger "balloon-help"). Attach it to the
 * focusable control itself (a checkbox's input), not a wrapper. A new
 * `content` value replaces the message; the balloon is detached on
 * destroy.
 */
export function balloon(
  node: HTMLElement,
  content: BalloonOptions['content']
): ActionReturn<BalloonOptions['content']> {
  const help = attachBalloon(node, { content, trigger: 'balloon-help' });

  return {
    update(next) {
      help.setContent(next);
    },
    destroy() {
      help.detach();
    }
  };
}
