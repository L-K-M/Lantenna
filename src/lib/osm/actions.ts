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
 * `disabled` follows dimmable's rule: a pop-up that dims while it has
 * the keyboard keeps it, dimmed and opening nothing, until it leaves.
 */
export function popup(node: HTMLButtonElement, p: PopupParams): ActionReturn<PopupParams> {
  let params = p;
  // Before mountPopup, so these listeners run ahead of Osmium's.
  const dim = keepKeyboardWhileDimmed(node, Boolean(p.disabled));
  ignorePressesWhileDimmed(node);
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
      dim.set(Boolean(next.disabled));

      if (!sameItems(previous.items, next.items)) {
        handle.setItems(next.items, next.selected);
        return;
      }

      if (next.selected !== handle.selected) handle.setSelected(next.selected);
    },
    destroy() {
      handle.destroy();
      dim.destroy();
    }
  };
}

/**
 * Close any open pop-up menu without choosing, as Escape does. Osmium's
 * pop-up has no close() short of destroy(), so this sends the menu the
 * Escape it listens for; the event doesn't bubble, so no page key
 * handler sees it. Osmium follow-up: a public way to end menu tracking.
 */
export function closePopupMenus(): void {
  for (const menu of document.querySelectorAll('.osm-menu[role="listbox"]')) {
    menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', cancelable: true }));
  }
}

/** Keys that open an Osmium pop-up menu (mountPopup). */
const POPUP_KEYS = new Set(['ArrowDown', 'ArrowUp', ' ', 'Enter']);

/** A pop-up dimmed under the keyboard (aria-disabled, see dimmable)
 * opens no menu: its presses stop here, ahead of Osmium's listeners. */
function ignorePressesWhileDimmed(node: HTMLButtonElement): void {
  const dimmed = () => node.getAttribute('aria-disabled') === 'true';
  const stop = (e: Event) => {
    e.preventDefault();
    e.stopImmediatePropagation();
  };
  node.addEventListener('keydown', (e) => {
    if (dimmed() && POPUP_KEYS.has(e.key)) stop(e);
  });
  node.addEventListener('pointerdown', (e) => {
    if (dimmed()) stop(e);
  });
  node.addEventListener('click', (e) => {
    if (dimmed()) stop(e);
  });
}

/**
 * Return held on the focused `button` presses it once. Browsers click a
 * focused button on every auto-repeated Return keydown (Space clicks on
 * keyup, once); Return elsewhere ignores repeats (the views, Osmium's
 * pop-ups, menus and bindDialogKeys). The listener goes with the element.
 */
export function pressOnceOnReturn(button: HTMLElement): void {
  button.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && e.repeat) e.preventDefault();
  });
}

/**
 * `<button class="osm-button" use:osmButton={action}>Title</button>`: press
 * tracking and title layout (pushButton). Change the title with Osmium's
 * setButtonTitle, not the template, so the layout follows. Osmium has no
 * teardown for push buttons; their listeners go with the element. A
 * button `dimmable` dimmed under the keyboard does nothing, and Return
 * held on it presses it once.
 */
export function osmButton(node: HTMLButtonElement, action: () => void): ActionReturn<() => void> {
  let current = action;
  pushButton(node, () => {
    if (node.getAttribute('aria-disabled') !== 'true') current();
  });
  pressOnceOnReturn(node);

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
 * The popup action applies the same rule to Osmium's pop-ups.
 */
export function dimmable(node: HTMLButtonElement, dimmed: boolean): ActionReturn<boolean> {
  const dim = keepKeyboardWhileDimmed(node, dimmed);

  return {
    update(next) {
      dim.set(next);
    },
    destroy() {
      dim.destroy();
    }
  };
}

/** dimmable's rule for any button: `set(dimmed)` disables it, or, while
 * it has the keyboard, marks it aria-disabled until the keyboard leaves.
 * Pressing it then is its owner's to ignore. */
function keepKeyboardWhileDimmed(
  node: HTMLButtonElement,
  dimmed: boolean
): { set(dimmed: boolean): void; destroy(): void } {
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
    set(next) {
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

/**
 * `use:fieldBalloon={content}`: as `balloon`, for a text field with its
 * label on the same row (Find). The default tip, 10px up from the
 * field's bottom edge, leaves a balloon that flips left (no room on the
 * right) over the label; on the bottom edge the body starts below the
 * label's row.
 */
export function fieldBalloon(
  node: HTMLInputElement,
  content: BalloonOptions['content']
): ActionReturn<BalloonOptions['content']> {
  return attachHelp(node, content, { tip: 'anchor', anchor: { x: 10, y: 0 } });
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
