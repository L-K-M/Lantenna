// Owner: unit C (spec 8.4): the General panel renders its values (stale
// favorites included) and its name field commits on Return, focusout and
// a selection change, and reverts on Escape (2.7).
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/svelte';
import { tick } from 'svelte';
import { formatLongDate } from '$lib/util/format';
import { fingerprint, host, hostRow } from './hostRow.fixture';
import InfoGeneral from './InfoGeneral.svelte';

const store = vi.hoisted(() => ({
  setCustomName: vi.fn(),
  toggleFavorite: vi.fn(),
  toggleHidden: vi.fn()
}));
vi.mock('$lib/util/scanStore', () => ({ scanStore: store }));

const printer = hostRow();
const router = hostRow(host({ ip: '192.168.1.1', name: 'router', fingerprint: null, open_ports: [] }));

function nameField(): HTMLInputElement {
  return screen.getByRole('textbox', { name: 'Name' });
}

/** Type into the field as the reader would: focus, then input. */
async function typeName(text: string): Promise<HTMLInputElement> {
  const field = nameField();
  await fireEvent.focusIn(field);
  await fireEvent.input(field, { target: { value: text } });
  return field;
}

function value(label: string): string | null | undefined {
  const labelEl = screen.getByText(`${label}:`);
  return labelEl.nextElementSibling?.textContent;
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('without a selection', () => {
  it('shows only the prompt', () => {
    render(InfoGeneral, { props: { row: null } });
    const prompt = screen.getByText('Select a host to see its information.');
    expect(prompt.hidden).toBe(false);
    expect(screen.queryByRole('textbox')).toBeNull();
  });
});

describe('values', () => {
  it('shows the Get Info fields', () => {
    render(InfoGeneral, { props: { row: printer } });

    expect(screen.getByText('Select a host to see its information.').hidden).toBe(true);
    expect(screen.getByRole('img', { name: 'Printer' })).toBeTruthy();
    expect(value('IP Address')).toBe('192.168.1.31');
    expect(value('MAC Address')).toBe('30:05:5C:12:34:56');
    expect(value('Vendor')).toBe('Brother Industries, Ltd.');
    expect(value('Detected Name')).toBe('BRN30055C123456.local');
    expect(value('Reachable')).toBe('Yes');
    expect(value('Last Seen')).toBe(formatLongDate('2026-09-27T13:42:00Z'));
  });

  it('fills in what is unknown', () => {
    render(InfoGeneral, {
      props: {
        row: hostRow(host({ name: null, reachable: false, last_seen: '', fingerprint: null }), { vendorFull: 'Unknown' })
      }
    });

    expect(value('MAC Address')).toBe('Unknown');
    expect(value('Vendor')).toBe('Unknown');
    expect(value('Detected Name')).toBe('None');
    expect(value('Reachable')).toBe('No');
    expect(value('Last Seen')).toBe('--');
  });

  it('shows the model’s full vendor name (hostModel.test.ts has its rule)', async () => {
    const privateMac = host({ fingerprint: fingerprint({ vendor: null, mac_address: '3a:11:22:33:44:55' }) });
    const { rerender } = render(InfoGeneral, { props: { row: hostRow(privateMac, { vendorFull: 'Private address' }) } });
    expect(value('Vendor')).toBe('Private address');

    await rerender({ row: hostRow(host(), { vendorFull: 'Synology' }) });
    expect(value('Vendor')).toBe('Synology');
  });

  it('says a stale favorite was not found in the last scan', () => {
    render(InfoGeneral, { props: { row: hostRow(host(), { stale: true, favorite: true }) } });
    expect(value('Reachable')).toBe('No (not found in the last scan)');
  });
});

describe('checkboxes', () => {
  it('show and toggle Favorite and Hidden', async () => {
    render(InfoGeneral, { props: { row: hostRow(host(), { favorite: true }) } });
    const favorite = screen.getByRole('checkbox', { name: 'Favorite' }) as HTMLInputElement;
    const hidden = screen.getByRole('checkbox', { name: 'Hidden' }) as HTMLInputElement;
    expect(favorite.checked).toBe(true);
    expect(hidden.checked).toBe(false);

    await fireEvent.click(favorite);
    await fireEvent.click(hidden);
    expect(store.toggleFavorite).toHaveBeenCalledWith('192.168.1.31');
    expect(store.toggleHidden).toHaveBeenCalledWith('192.168.1.31');
  });
});

describe('the name field', () => {
  it('shows the custom name, else the detected name without .local, else nothing', async () => {
    const { rerender } = render(InfoGeneral, { props: { row: hostRow(host(), { customName: 'Office Printer' }) } });
    expect(nameField().value).toBe('Office Printer');

    await rerender({ row: printer });
    expect(nameField().value).toBe('BRN30055C123456');

    await rerender({ row: hostRow(host({ name: null })) });
    expect(nameField().value).toBe('');
    expect(nameField().placeholder).toBe('');
  });

  it('commits on Return, trimmed, without letting Return reach Open', async () => {
    render(InfoGeneral, { props: { row: printer } });
    const field = await typeName('  Office Printer ');

    const notPrevented = await fireEvent.keyDown(field, { key: 'Enter' });

    expect(notPrevented).toBe(false);
    expect(store.setCustomName).toHaveBeenCalledWith('192.168.1.31', 'Office Printer');
    expect(field.value).toBe('Office Printer');
  });

  it('clears the custom name when emptied, showing the detected name again', async () => {
    render(InfoGeneral, { props: { row: hostRow(host(), { customName: 'Office Printer' }) } });
    const field = await typeName('');
    await fireEvent.keyDown(field, { key: 'Enter' });

    expect(store.setCustomName).toHaveBeenCalledWith('192.168.1.31', '');
    expect(field.value).toBe('BRN30055C123456');
  });

  it('leaves the detected name alone when it is committed unchanged', async () => {
    render(InfoGeneral, { props: { row: printer } });
    const field = await typeName(' BRN30055C123456 ');
    await fireEvent.keyDown(field, { key: 'Enter' });
    await fireEvent.focusOut(field);

    expect(store.setCustomName).not.toHaveBeenCalled();
    expect(field.value).toBe('BRN30055C123456');
  });

  it('commits when the field loses the keyboard', async () => {
    render(InfoGeneral, { props: { row: printer } });
    const field = await typeName('Office Printer');
    await fireEvent.focusOut(field);
    expect(store.setCustomName).toHaveBeenCalledWith('192.168.1.31', 'Office Printer');
  });

  it('reverts to the value it had on focus with Escape, and commits nothing', async () => {
    render(InfoGeneral, { props: { row: hostRow(host(), { customName: 'Office Printer' }) } });
    const field = await typeName('Office Pri');

    const notPrevented = await fireEvent.keyDown(field, { key: 'Escape' });
    await fireEvent.focusOut(field);

    expect(notPrevented).toBe(false);
    expect(field.value).toBe('Office Printer');
    expect(store.setCustomName).not.toHaveBeenCalled();
  });

  it('keeps the draft when an open balloon took the Escape', async () => {
    render(InfoGeneral, { props: { row: printer } });
    const field = await typeName('Office Pri');

    // Osmium's balloon closes on Escape and only calls preventDefault.
    const taken = new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true });
    taken.preventDefault();
    field.dispatchEvent(taken);
    await tick();
    expect(field.value).toBe('Office Pri');

    await fireEvent.keyDown(field, { key: 'Escape' });
    expect(field.value).toBe('BRN30055C123456');
  });

  it('keeps a name committed with Return when Escape follows', async () => {
    const { rerender } = render(InfoGeneral, { props: { row: printer } });
    const field = await typeName('Office Printer');
    await fireEvent.keyDown(field, { key: 'Enter' });
    // The model feeds the new name back, as scanStore would.
    await rerender({ row: hostRow(host(), { customName: 'Office Printer' }) });

    await fireEvent.keyDown(field, { key: 'Escape' });
    await fireEvent.focusOut(field);

    expect(field.value).toBe('Office Printer');
    expect(store.setCustomName).toHaveBeenCalledTimes(1);
    expect(store.setCustomName).toHaveBeenCalledWith('192.168.1.31', 'Office Printer');
  });

  it('reverts to a name a menu set while the field had the keyboard', async () => {
    const named = hostRow(host(), { customName: 'Office Printer' });
    const { rerender } = render(InfoGeneral, { props: { row: named } });

    // Clear Custom Name while the field is focused and untouched.
    const field = nameField();
    await fireEvent.focusIn(field);
    await rerender({ row: printer });
    await fireEvent.keyDown(field, { key: 'Escape' });
    await fireEvent.focusOut(field);
    expect(field.value).toBe('BRN30055C123456');

    // The same with an edit in progress.
    await rerender({ row: named });
    await typeName('Office');
    await rerender({ row: printer });
    await fireEvent.keyDown(field, { key: 'Escape' });
    await fireEvent.focusOut(field);
    expect(field.value).toBe('BRN30055C123456');

    expect(store.setCustomName).not.toHaveBeenCalled();
  });

  it('commits a draft to its own host when the selection changes', async () => {
    const { rerender } = render(InfoGeneral, { props: { row: printer } });
    await typeName('Office Printer');

    await rerender({ row: router });

    expect(store.setCustomName).toHaveBeenCalledWith('192.168.1.31', 'Office Printer');
    expect(nameField().value).toBe('router');
  });

  it('commits a draft when the selection goes away', async () => {
    const { rerender } = render(InfoGeneral, { props: { row: printer } });
    await typeName('Office Printer');

    await rerender({ row: null });

    expect(store.setCustomName).toHaveBeenCalledWith('192.168.1.31', 'Office Printer');
  });

  it('follows the model while untouched, and keeps an edit in progress', async () => {
    const named = hostRow(host(), { customName: 'Office Printer' });
    const { rerender } = render(InfoGeneral, { props: { row: named } });

    // Clear Custom Name from a menu: the field shows the detected name.
    await rerender({ row: printer });
    expect(nameField().value).toBe('BRN30055C123456');

    // A rescan updates the host while the reader types: the draft stays.
    await typeName('Office');
    await rerender({ row: hostRow(host({ name: 'BRN30055C123456.lan' })) });
    expect(nameField().value).toBe('Office');
    expect(store.setCustomName).not.toHaveBeenCalled();
  });

  it('takes the keyboard for Rename…, its text selected', async () => {
    const { component } = render(InfoGeneral, { props: { row: printer } });
    component.focusName(true);

    const field = nameField();
    expect(document.activeElement).toBe(field);
    expect([field.selectionStart, field.selectionEnd]).toEqual([0, 'BRN30055C123456'.length]);
  });
});
