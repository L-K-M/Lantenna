// Owner: unit D (spec 8.4). Test support only (imported by tests, never
// by the app).
//
// happy-dom's localStorage can't be spied on: vi.spyOn replaces a method
// but restoring it leaves the spy in place. Tests that need a refusing
// storage swap window.localStorage for a wrapper instead, and put the
// real one back with the returned function.

type Method = 'getItem' | 'setItem' | 'removeItem';

/** Make the listed methods throw the given errors; the rest reach the
 * real storage. Returns the function that restores it. */
export function refuseStorage(errors: Partial<Record<Method, unknown>>): () => void {
  const real = window.localStorage;
  const descriptor = Object.getOwnPropertyDescriptor(window, 'localStorage');
  const guard =
    <A extends unknown[], R>(method: Method, call: (...args: A) => R) =>
    (...args: A): R => {
      if (method in errors) throw errors[method];
      return call(...args);
    };

  const wrapper: Storage = {
    getItem: guard('getItem', (key: string) => real.getItem(key)),
    setItem: guard('setItem', (key: string, value: string) => real.setItem(key, value)),
    removeItem: guard('removeItem', (key: string) => real.removeItem(key)),
    clear: () => real.clear(),
    key: (index: number) => real.key(index),
    get length() {
      return real.length;
    }
  };

  Object.defineProperty(window, 'localStorage', { configurable: true, get: () => wrapper });
  return () => {
    if (descriptor) Object.defineProperty(window, 'localStorage', descriptor);
    else delete (window as { localStorage?: Storage }).localStorage;
  };
}
