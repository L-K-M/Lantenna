import { readable, type Readable } from 'svelte/store';

/** Whether the document holds a text selection outside any field (pane
 * values are selectable). A field's own selection doesn't count: the
 * document's selection reads as empty text then. */
export function hasTextSelection(): boolean {
  const selection = window.getSelection();
  return selection !== null && !selection.isCollapsed && selection.toString() !== '';
}

/** hasTextSelection(), kept current by selectionchange: the Edit menu's
 * Copy copies a selected pane value (3.3), with the keyboard on <body>. */
export const textSelection: Readable<boolean> = readable(false, (set) => {
  const update = () => set(hasTextSelection());
  update();
  document.addEventListener('selectionchange', update);
  return () => document.removeEventListener('selectionchange', update);
});
