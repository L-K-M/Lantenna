import { afterEach, expect, it, vi } from 'vitest';
import { scanEvents } from './scanEvents';

const stops: (() => void)[] = [];

afterEach(() => {
  while (stops.length) stops.pop()!();
  vi.restoreAllMocks();
});

it('delivers each event to every subscriber until it unsubscribes', () => {
  const first = vi.fn();
  const second = vi.fn();
  const stopFirst = scanEvents.subscribe(first);
  stops.push(scanEvents.subscribe(second));

  scanEvents.emit({ type: 'no-interface' });
  stopFirst();
  scanEvents.emit({ type: 'deep-scan-busy', ip: '192.168.1.2' });

  expect(first.mock.calls).toEqual([[{ type: 'no-interface' }]]);
  expect(second.mock.calls).toEqual([
    [{ type: 'no-interface' }],
    [{ type: 'deep-scan-busy', ip: '192.168.1.2' }]
  ]);
});

it('reports a failing subscriber and still reaches the others', () => {
  const error = new Error('listener failed');
  const report = vi.spyOn(console, 'error').mockImplementation(() => {});
  const after = vi.fn();
  stops.push(scanEvents.subscribe(() => { throw error; }));
  stops.push(scanEvents.subscribe(after));

  scanEvents.emit({ type: 'scan-complete', hostCount: 3, cancelled: false });

  expect(report).toHaveBeenCalledWith('Lantenna scan event listener failed:', error);
  expect(after).toHaveBeenCalledOnce();
});
