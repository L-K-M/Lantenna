// Owner: unit D (spec 8.4). Spec: 3.5 (Robustness).
//
// SCAFFOLD STUB: reads return null and writes are dropped, so every
// setting behaves as its default until unit D implements this file.
// Final contract: never throws; logs one
// console.warn('Lantenna couldn’t save <key>:', e) per failed write;
// a failed or malformed read returns null.

/** The stored string for `key`, or null when absent or unreadable. */
export function readString(key: string): string | null {
  return null;
}

/** Store `value` under `key`; null removes the key. */
export function writeString(key: string, value: string | null): void {}

/** The parsed JSON under `key` when `guard` accepts it, else null. */
export function readJson<T>(key: string, guard: (v: unknown) => v is T): T | null {
  return null;
}

/** Store `value` as JSON under `key`. */
export function writeJson(key: string, value: unknown): void {}
