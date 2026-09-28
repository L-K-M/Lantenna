// Owner: scaffold (spec 8.3), complete. Spec: 5.1 to 5.5.
//
// What the scan store has to tell the user about, now that it no longer
// raises toasts. The store emits; feedback.ts (unit D) turns each event
// into the window header, the host status line or a stop alert.

export type ScanEvent =
  | { type: 'init-failed'; message: string }
  | { type: 'start-failed'; message: string }
  | { type: 'no-interface' }
  | { type: 'scan-error'; message: string }
  | { type: 'scan-complete'; hostCount: number; cancelled: boolean }
  | { type: 'cancel-failed'; message: string }
  | { type: 'deep-scan-busy'; ip: string }
  | { type: 'deep-scan-done'; ip: string; openPorts: number }
  | { type: 'deep-scan-failed'; ip: string; message: string };

type Listener = (e: ScanEvent) => void;

const listeners = new Set<Listener>();

export const scanEvents: {
  emit(e: ScanEvent): void;
  subscribe(fn: (e: ScanEvent) => void): () => void;
} = {
  /**
   * Delivers `e` to every subscriber synchronously. Events are not
   * buffered: one emitted with no subscriber is dropped. A subscriber
   * that throws is reported and does not stop the others or the store.
   */
  emit(e) {
    for (const fn of [...listeners]) {
      try {
        fn(e);
      } catch (error) {
        console.error('Lantenna scan event listener failed:', error);
      }
    }
  },
  subscribe(fn) {
    listeners.add(fn);
    return () => {
      listeners.delete(fn);
    };
  }
};
