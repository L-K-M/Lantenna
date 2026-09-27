// Owner: scaffold (spec 8.3), complete. Spec: 3.2, 4.1, 4.2.
//
// Where the keyboard is, as commands need it: Copy and Command-Delete act
// on the host only while the list or the icon grid has the keyboard, and
// the Edit items act on text only while a text field has it. A read-only
// field (the Fingerprint notes view) takes Copy and Select All only.
//
// Class contract: the list view's host element is div.lan-list
// (HostList), the icon grid's is div.lan-icons (HostIconView).
//
// installKeyboardHome() gives the keyboard back to the host view when
// it has nowhere left to be.

import { get, readable, type Readable } from 'svelte/store';
import { isModal, onModalChange } from 'osmium-ui';
import { activeView } from './views';

export type FocusKind = 'list' | 'icons' | 'text' | 'readonly-text' | 'other';

/** Fields that take typing. Checkboxes, sliders and buttons do not. */
const TEXT_SELECTOR =
  'input:not([type=checkbox]):not([type=radio]):not([type=range]):not([type=button])' +
  ':not([type=submit]):not([type=reset]), textarea, [contenteditable]:not([contenteditable=false])';

function isReadOnly(field: Element): boolean {
  return (field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement) && field.readOnly;
}

/** What kind of place `el` is for the keyboard. Text wins over the view
 * around it; anything outside the views is "other". */
export function classifyFocus(el: Element | null): FocusKind {
  if (!el || el === document.body || el === document.documentElement) return 'other';
  const field = el.closest(TEXT_SELECTOR);
  if (field) return isReadOnly(field) ? 'readonly-text' : 'text';
  if (el.closest('.lan-list')) return 'list';
  if (el.closest('.lan-icons')) return 'icons';
  return 'other';
}

/**
 * The kind of the focused element, following focusin and focusout on
 * the document while anything subscribes. Focus leaving for nowhere (a
 * click on the gray) reads "other". The window losing OS focus keeps the
 * last kind, because the element keeps the DOM focus.
 *
 * Focus leaving for nowhere is read a microtask later. Browsers fire
 * that focusout synchronously when the focused element is removed or
 * moved, which Svelte does while it updates the page (switching views,
 * reordering tiles); a store write then reaches components' $state
 * through $commandContext in the middle of Svelte's update, which it
 * refuses (state_unsafe_mutation) and which aborts the update. Moves to
 * another element (focusin) stay synchronous: menus hand the keyboard
 * back and run a command at once, and the command reads this store.
 */
export const keyboardFocus: Readable<FocusKind> = readable<FocusKind>('other', (set) => {
  set(classifyFocus(document.activeElement));

  const onFocusIn = (e: FocusEvent) => {
    set(classifyFocus(e.target instanceof Element ? e.target : null));
  };
  const onFocusOut = (e: FocusEvent) => {
    // A focusin follows when focus moves to another element.
    if (e.relatedTarget !== null) return;
    queueMicrotask(() => set(classifyFocus(document.activeElement)));
  };

  document.addEventListener('focusin', onFocusIn);
  document.addEventListener('focusout', onFocusOut);

  return () => {
    document.removeEventListener('focusin', onFocusIn);
    document.removeEventListener('focusout', onFocusOut);
  };
});

/** What hides an element without removing it: a `hidden` attribute (the
 * pane, a tab's panel) or the collapsed window (Osmium's class). */
const HIDDEN_SELECTOR = '[hidden], .osm-shaded';

/** A text selection outside the fields (pane values are selectable). */
function hasTextSelection(): boolean {
  const selection = window.getSelection();
  return selection !== null && !selection.isCollapsed && selection.toString() !== '';
}

/** Whether the keyboard has no usable place: nowhere (<body>), or an
 * element that is gone, dimmed or hidden. */
function keyboardStranded(): boolean {
  const el = document.activeElement;
  if (!el || el === document.body || el === document.documentElement) return true;
  return !el.isConnected || el.matches(':disabled') || el.closest(HIDDEN_SELECTOR) !== null;
}

/**
 * The host view is the keyboard's home (3.2), as the Finder's front
 * window keeps its list's keyboard: whenever the keyboard has nowhere
 * left to be, the view (the list or the icon grid) takes it. That is at
 * launch, after a click on the gray, when the focused control dims
 * (Wake while sending, Deep Scan while its scan runs, Stop while
 * stopping, the pop-ups during a scan), when its panel or the pane hides,
 * when it goes away (the Hidden checkbox hiding the selected host) and
 * when the window unfolds. Without it the keyboard falls to <body>,
 * where arrows and type-select do nothing and Return presses Open.
 *
 * Not while an alert is up (it holds the keyboard and gives it back as
 * it closes; the check runs again then), while the view can't take it
 * (the window collapsed), and not for a press that selects text in the
 * pane (3.3, for Copy): a press moves the keyboard when it ends, and
 * only if it left no selection, since moving the focus drops the
 * selection (Chromium while the drag starts, WebKit after it).
 *
 * Browsers report these moves differently, so several things start the
 * check, which runs a microtask later, once the page has settled:
 * focusout to nowhere (Chromium sends it for each case, WebKit only for
 * a control that dims); changes to what `frame`'s content holds or hides
 * (WebKit keeps the focus on an element hidden by an ancestor's `hidden`
 * attribute, and moves it to <body> without an event when the element is
 * removed); the frame's class (collapse and expand); and an alert
 * closing. Returns the disposer.
 */
export function installKeyboardHome(frame: HTMLElement): () => void {
  let queued = false;
  /** A pointer button is down in the page (a click or a drag). A press
   * the page never sees end (the OS takes the mouse to move the window)
   * is over by the next key, which checks what that press left. */
  let pressing = false;

  const check = () => {
    queued = false;
    if (pressing || isModal() || !keyboardStranded() || hasTextSelection()) return;

    const view = get(activeView);
    if (!view || view.element.closest(HIDDEN_SELECTOR)) return;
    view.focus();
  };
  const queue = () => {
    if (queued) return;
    queued = true;
    queueMicrotask(check);
  };

  const onFocusOut = (e: FocusEvent) => {
    if (e.relatedTarget === null) queue();
  };
  const onPress = () => {
    pressing = true;
  };
  const onRelease = () => {
    pressing = false;
    queue();
  };
  const onKey = () => {
    if (!pressing) return;
    pressing = false;
    queue();
  };
  document.addEventListener('focusout', onFocusOut);
  document.addEventListener('pointerdown', onPress, true);
  document.addEventListener('pointerup', onRelease, true);
  document.addEventListener('pointercancel', onRelease, true);
  document.addEventListener('keydown', onKey, true);

  const observer = new MutationObserver(queue);
  observer.observe(frame, { attributes: true, attributeFilter: ['class'] });
  const content = frame.querySelector('.osm-content');
  if (content) {
    observer.observe(content, {
      subtree: true,
      childList: true,
      attributes: true,
      attributeFilter: ['hidden', 'disabled']
    });
  }

  const stopModal = onModalChange((modal) => {
    if (!modal) queue();
  });

  // At launch nothing has the keyboard yet.
  queue();

  return () => {
    document.removeEventListener('focusout', onFocusOut);
    document.removeEventListener('pointerdown', onPress, true);
    document.removeEventListener('pointerup', onRelease, true);
    document.removeEventListener('pointercancel', onRelease, true);
    document.removeEventListener('keydown', onKey, true);
    observer.disconnect();
    stopModal();
  };
}
