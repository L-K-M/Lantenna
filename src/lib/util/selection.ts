/** Whether the document holds a text selection outside any field (pane
 * values are selectable). A field's own selection doesn't count: the
 * document's selection reads as empty text then. */
export function hasTextSelection(): boolean {
  const selection = window.getSelection();
  return selection !== null && !selection.isCollapsed && selection.toString() !== '';
}
