/** keyCode of a key an input method is composing with. Safari sends the
 * key that ends a composition (Return, say) with isComposing false and
 * this code. */
const IME_KEY_CODE = 229;

/** Whether `e` belongs to an input method's composition: text fields
 * leave those keys, Return and Escape included, to the method. */
export function isImeKey(e: KeyboardEvent): boolean {
  return e.isComposing || e.keyCode === IME_KEY_CODE;
}
