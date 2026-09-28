// Owner: unit D (spec 8.4). Spec: 3.5 (Robustness).
//
// Every localStorage read and write in Lantenna goes through here. None
// of these functions throws: storage can be missing (a private window,
// a sandbox), full (a quota error) or hold text an older or newer
// version wrote. A failed write logs one
// console.warn('Lantenna couldn’t save <key>:', e) and is dropped; a
// failed read logs one warning and reads as absent; a malformed value
// (bad JSON, or JSON the guard rejects) reads as absent without a
// warning, so the caller falls back to its default.

/** The page's localStorage; null outside a browser (no window at all),
 * which is not a failure. Throws where the browser refuses access. */
function localStore(): Storage | null {
  return typeof window === 'undefined' ? null : window.localStorage;
}

/** The stored string for `key`, or null when absent or unreadable. */
export function readString(key: string): string | null {
  try {
    return localStore()?.getItem(key) ?? null;
  } catch (error) {
    console.warn(`Lantenna couldn’t read ${key}:`, error);
    return null;
  }
}

/** Store `value` under `key`; null removes the key. */
export function writeString(key: string, value: string | null): void {
  try {
    const store = localStore();
    if (value === null) store?.removeItem(key);
    else store?.setItem(key, value);
  } catch (error) {
    console.warn(`Lantenna couldn’t save ${key}:`, error);
  }
}

/** The parsed JSON under `key` when `guard` accepts it, else null. */
export function readJson<T>(key: string, guard: (v: unknown) => v is T): T | null {
  const raw = readString(key);
  if (raw === null) return null;

  try {
    const value: unknown = JSON.parse(raw);
    return guard(value) ? value : null;
  } catch {
    return null;
  }
}

/** Store `value` as JSON under `key`. */
export function writeJson(key: string, value: unknown): void {
  let text: string | undefined;
  try {
    // undefined for undefined and functions, which JSON can't hold.
    text = JSON.stringify(value);
    if (text === undefined) throw new TypeError(`${typeof value} is not JSON`);
  } catch (error) {
    console.warn(`Lantenna couldn’t save ${key}:`, error);
    return;
  }

  writeString(key, text);
}
