// Owner: unit D (spec 8.4). Spec: 3.5 (storage never throws).
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { readJson, readString, writeJson, writeString } from './storage';
import { refuseStorage } from './storage.fixture';

const isNumberList = (v: unknown): v is number[] => Array.isArray(v) && v.every((n) => typeof n === 'number');

let warn: ReturnType<typeof vi.spyOn>;
let restoreStorage: (() => void) | null = null;

beforeEach(() => {
  localStorage.clear();
  warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
});

afterEach(() => {
  restoreStorage?.();
  restoreStorage = null;
  vi.restoreAllMocks();
});

it('reads and writes strings; null removes the key', () => {
  expect(readString('lantenna.viewMode')).toBeNull();

  writeString('lantenna.viewMode', 'icons');
  expect(localStorage.getItem('lantenna.viewMode')).toBe('icons');
  expect(readString('lantenna.viewMode')).toBe('icons');

  writeString('lantenna.viewMode', null);
  expect(localStorage.getItem('lantenna.viewMode')).toBeNull();
  expect(warn).not.toHaveBeenCalled();
});

it('reads JSON the guard accepts and nothing else, without warnings', () => {
  writeJson('k', [1, 2]);
  expect(localStorage.getItem('k')).toBe('[1,2]');
  expect(readJson('k', isNumberList)).toEqual([1, 2]);

  localStorage.setItem('k', '["a"]');
  expect(readJson('k', isNumberList)).toBeNull();

  localStorage.setItem('k', '{not json');
  expect(readJson('k', isNumberList)).toBeNull();

  expect(readJson('absent', isNumberList)).toBeNull();
  expect(warn).not.toHaveBeenCalled();
});

it('treats a guard that throws as a rejection', () => {
  localStorage.setItem('k', 'null');
  const throwing = (v: unknown): v is object => (v as object).constructor !== undefined;

  expect(readJson('k', throwing)).toBeNull();
});

it('never throws on a failed write and warns once per failure', () => {
  const quota = new DOMException('The quota has been exceeded.', 'QuotaExceededError');
  restoreStorage = refuseStorage({ setItem: quota });

  expect(() => writeString('lantenna.favoriteIps', 'x')).not.toThrow();
  expect(() => writeJson('lantenna.hiddenIps', ['192.168.1.1'])).not.toThrow();

  expect(warn.mock.calls).toEqual([
    ['Lantenna couldn’t save lantenna.favoriteIps:', quota],
    ['Lantenna couldn’t save lantenna.hiddenIps:', quota]
  ]);
});

it('never throws on a failed removal', () => {
  restoreStorage = refuseStorage({ removeItem: new Error('denied') });

  expect(() => writeString('lantenna.selectedInterface', null)).not.toThrow();
  expect(warn).toHaveBeenCalledOnce();
});

it('drops a value JSON can’t hold with one warning', () => {
  const cyclic: Record<string, unknown> = {};
  cyclic.self = cyclic;

  expect(() => writeJson('k', cyclic)).not.toThrow();
  expect(() => writeJson('k', undefined)).not.toThrow();

  expect(warn).toHaveBeenCalledTimes(2);
  expect(localStorage.getItem('k')).toBeNull();
});

it('reads a refused storage as absent', () => {
  restoreStorage = refuseStorage({ getItem: new DOMException('The operation is insecure.', 'SecurityError') });

  expect(readString('lantenna.infoTab')).toBeNull();
  expect(readJson('lantenna.listSort', isNumberList)).toBeNull();
  expect(warn).toHaveBeenCalledTimes(2);
  expect(warn.mock.calls[0][0]).toBe('Lantenna couldn’t read lantenna.infoTab:');
});

it('survives a page where localStorage itself is refused', () => {
  const descriptor = Object.getOwnPropertyDescriptor(window, 'localStorage');
  Object.defineProperty(window, 'localStorage', {
    configurable: true,
    get() {
      throw new DOMException('Access is denied.', 'SecurityError');
    }
  });

  try {
    expect(readString('k')).toBeNull();
    expect(() => writeString('k', 'v')).not.toThrow();
    expect(() => writeJson('k', { a: 1 })).not.toThrow();
  } finally {
    if (descriptor) Object.defineProperty(window, 'localStorage', descriptor);
  }
});
