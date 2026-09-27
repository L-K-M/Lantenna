// Owner: scaffold (spec 8.3), complete. Spec: 3.2, 4.1, 4.2.
//
// Where the keyboard is, as commands need it: Copy and Command-Delete act
// on the host only while the list or the icon grid has the keyboard, and
// the Edit items act on text only while a text field has it. A read-only
// field (the Fingerprint notes view) takes Copy and Select All only.
//
// Class contract: the list view's host element is div.lan-list
// (HostList), the icon grid's is div.lan-icons (HostIconView).

import { readable, type Readable } from 'svelte/store';

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
 */
export const keyboardFocus: Readable<FocusKind> = readable<FocusKind>('other', (set) => {
  set(classifyFocus(document.activeElement));

  const onFocusIn = (e: FocusEvent) => {
    set(classifyFocus(e.target instanceof Element ? e.target : null));
  };
  const onFocusOut = (e: FocusEvent) => {
    // A focusin follows when focus moves to another element.
    if (e.relatedTarget === null) set('other');
  };

  document.addEventListener('focusin', onFocusIn);
  document.addEventListener('focusout', onFocusOut);

  return () => {
    document.removeEventListener('focusin', onFocusIn);
    document.removeEventListener('focusout', onFocusOut);
  };
});
