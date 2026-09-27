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
 * teardown for push buttons; their listeners go with the element. A
 * button `dimmable` dimmed under the keyboard does nothing.
 */
export function osmButton(node: HTMLButtonElement, action: () => void): ActionReturn<() => void> {
  let current = action;
  pushButton(node, () => {
    if (node.getAttribute('aria-disabled') !== 'true') current();
  });

  return {
    update(next) {
      current = next;
    }
  };
}

/**
 * `use:dimmable={dimmed}` on an osmButton, in place of `disabled={dimmed}`:
 * a button that dims while it has the keyboard keeps it. A disabled
 * button can't (Chromium moves the focus to <body>, WebKit leaves it on
 * a control that takes no keys), and the keyboard home then gives it to
 * the host view, where a second press of Space or Return, likely after
 * Wake shows nothing near the button, would star or open the selected
 * host. Until the keyboard leaves, the button is dimmed with
 * aria-disabled instead (drawn dimmed by +layout.svelte, ignored by
 * osmButton), as the WAI-ARIA APG does for controls that become
 * unavailable; then it is disabled as usual, out of the Tab order.
 */
export function dimmable(node: HTMLButtonElement, dimmed: boolean): ActionReturn<boolean> {
  let current = dimmed;

  const apply = () => {
    const keep = current && document.activeElement === node;
    node.disabled = current && !keep;
    if (keep) node.setAttribute('aria-disabled', 'true');
    else node.removeAttribute('aria-disabled');
  };
  // Read once the focus has moved: the window losing OS focus sends
  // focusout too, but the button keeps the DOM focus then. Not in a
  // microtask: during the move the focus is on <body> (Chromium), and
  // the keyboard home, seeing the button dim then, would take the
  // keyboard from the control Tab is moving it to.
  const onBlur = () => setTimeout(apply, 0);

  node.addEventListener('focusout', onBlur);
  apply();

  return {
    update(next) {
      current = next;
      apply();
    },
    destroy() {
      node.removeEventListener('focusout', onBlur);
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
 * focusable control itself, not a wrapper (a checkbox takes
 * checkboxBalloon on its label). A new `content` value replaces the
 * message; the balloon is detached on destroy.
 */
export function balloon(
  node: HTMLElement,
  content: BalloonOptions['content']
): ActionReturn<BalloonOptions['content']> {
  return attachHelp(node, content, { tip: 'anchor' });
}

/**
 * `<label class="osm-checkbox" use:checkboxBalloon={content}><input …>Title</label>`:
 * Balloon Help for a checkbox and its title together, as the Help
 * Manager's hot rectangle for a check box item covers both. On the
 * 14 x 12 box alone the tip lands inside the box and the balloon covers
 * the title, under the pointer that rests there; on the label it points
 * past the title. The message stays the box's description for screen
 * readers (5.6): Osmium names it in the label's aria-describedby, which
 * moves to the input.
 */
export function checkboxBalloon(
  node: HTMLLabelElement,
  content: BalloonOptions['content']
): ActionReturn<BalloonOptions['content']> {
  const help = attachBalloon(node, { content, trigger: 'balloon-help', tip: 'anchor' });
  const input = node.querySelector('input');
  const id = help.element.id;
  node.removeAttribute('aria-describedby');
  input?.setAttribute('aria-describedby', id);

  return {
    update(next) {
      help.setContent(next);
    },
    destroy() {
      help.detach();
      if (input?.getAttribute('aria-describedby') === id) input.removeAttribute('aria-describedby');
    }
  };
}

/**
 * Where a large area's balloon points (the host list, the icon grid, the
 * Ports list, the window header). Osmium's default tip sits 10px in from
 * the target's bottom-right corner, which for a whole list is far from
 * the pointer and flips the balloon over other controls (the Find
 * field). So the tip goes where the pointer rests, and for keyboard
 * focus, which has no pointer, to the area's middle: Osmium clamps an
 * "anchor" inset to the target's center, and this one is larger than
 * any area.
 */
export const AREA_TIP: Required<Pick<BalloonOptions, 'tip' | 'anchor'>> = {
  tip: 'pointer',
  anchor: { x: 1e6, y: 1e6 }
};

/** `use:areaBalloon={content}`: as `balloon`, for a large area (AREA_TIP). */
export function areaBalloon(
  node: HTMLElement,
  content: BalloonOptions['content']
): ActionReturn<BalloonOptions['content']> {
  return attachHelp(node, content, AREA_TIP);
}

function attachHelp(
  node: HTMLElement,
  content: BalloonOptions['content'],
  placement: Pick<BalloonOptions, 'tip' | 'anchor'>
): ActionReturn<BalloonOptions['content']> {
  const help = attachBalloon(node, { content, trigger: 'balloon-help', ...placement });

  return {
    update(next) {
      help.setContent(next);
    },
    destroy() {
      help.detach();
    }
  };
}
