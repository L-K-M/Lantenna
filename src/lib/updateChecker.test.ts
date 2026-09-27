// Owner: unit D (spec 8.4). Spec: 3.5 (storage guards), 5.4 (manual check).
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const native = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: native.invoke }));

import { checkForUpdate, checkForUpdateNow, openReleasePage, skipVersion } from './updateChecker';
import { refuseStorage } from './util/storage.fixture';

const RELEASE = { version: '1.1.0', url: 'https://github.com/L-K-M/Lantenna/releases/tag/v1.1.0', notes: null };
const DAY = 24 * 60 * 60 * 1000;

beforeEach(() => {
  localStorage.clear();
  native.invoke.mockReset();
  native.invoke.mockResolvedValue(RELEASE);
});

afterEach(() => {
  vi.restoreAllMocks();
});

it('checks once a day, remembers the check and honors a skipped version', async () => {
  await expect(checkForUpdate()).resolves.toEqual(RELEASE);
  expect(Number(localStorage.getItem('updateChecker.lastCheck'))).toBeGreaterThan(Date.now() - 1000);

  await expect(checkForUpdate()).resolves.toBeNull();
  expect(native.invoke).toHaveBeenCalledOnce();

  localStorage.setItem('updateChecker.lastCheck', String(Date.now() - DAY - 1));
  skipVersion('1.1.0');
  expect(localStorage.getItem('updateChecker.skippedVersion')).toBe('1.1.0');
  await expect(checkForUpdate()).resolves.toBeNull();
  await expect(checkForUpdate({ force: true })).resolves.toEqual(RELEASE);
});

it('fails silently at launch and retries next time', async () => {
  const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
  native.invoke.mockRejectedValueOnce('GitHub returned HTTP 503');

  await expect(checkForUpdate()).resolves.toBeNull();
  expect(localStorage.getItem('updateChecker.lastCheck')).toBeNull();
  expect(warn).toHaveBeenCalledWith('Update check failed:', 'GitHub returned HTTP 503');
});

it('keeps working when localStorage refuses reads and writes', async () => {
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  const restore = refuseStorage({
    getItem: new DOMException('denied', 'SecurityError'),
    setItem: new DOMException('full', 'QuotaExceededError')
  });

  try {
    await expect(checkForUpdate()).resolves.toEqual(RELEASE);
    await expect(checkForUpdateNow()).resolves.toEqual(RELEASE);
    expect(() => skipVersion('1.1.0')).not.toThrow();
  } finally {
    restore();
  }
});

it('checks now past the throttle and the skip list, and rejects on failure', async () => {
  localStorage.setItem('updateChecker.lastCheck', String(Date.now()));
  skipVersion('1.1.0');

  await expect(checkForUpdateNow()).resolves.toEqual(RELEASE);

  native.invoke.mockResolvedValueOnce(null);
  await expect(checkForUpdateNow()).resolves.toBeNull();

  native.invoke.mockRejectedValueOnce('GitHub returned HTTP 503');
  await expect(checkForUpdateNow()).rejects.toBe('GitHub returned HTTP 503');
});

it('opens the release page and reports a refusal', async () => {
  native.invoke.mockResolvedValueOnce(null);
  await openReleasePage(RELEASE.url);
  expect(native.invoke).toHaveBeenCalledWith('open_release_url', { url: RELEASE.url });

  native.invoke.mockRejectedValueOnce('Only http(s) URLs may be opened');
  await expect(openReleasePage('ftp://example.com')).rejects.toBe('Only http(s) URLs may be opened');
});
