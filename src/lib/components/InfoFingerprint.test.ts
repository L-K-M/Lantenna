// Owner: unit C (spec 8.4): the Fingerprint panel's fields, confidence
// meter and read-only sources-and-notes view (2.7).
import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import { fingerprint, host, hostRow } from './hostRow.fixture';
import InfoFingerprint, { confidencePercent, notesText } from './InfoFingerprint.svelte';

function value(label: string): string | null | undefined {
  return screen.getByText(`${label}:`).nextElementSibling?.textContent;
}

function notesView(): HTMLTextAreaElement {
  return screen.getByRole('textbox', { name: 'Sources and notes' }) as HTMLTextAreaElement;
}

describe('notes text', () => {
  it('lists the sources, a blank line, then one note per line', () => {
    expect(notesText(fingerprint())).toBe(
      'Sources: arp-table, mdns\n\nmDNS service: _ipp._tcp\nPrinter service detected via mDNS'
    );
    expect(notesText(fingerprint({ notes: [] }))).toBe('Sources: arp-table, mdns');
    expect(notesText(fingerprint({ sources: [] }))).toBe(
      'mDNS service: _ipp._tcp\nPrinter service detected via mDNS'
    );
  });

  it('says the host is not identified yet without a fingerprint', () => {
    expect(notesText(null)).toBe('Not identified yet.');
    expect(notesText(fingerprint({ sources: [], notes: [] }))).toBe('Not identified yet.');
  });

  it('rounds and bounds the confidence', () => {
    expect(confidencePercent(fingerprint({ confidence: 86.6 }))).toBe(87);
    expect(confidencePercent(fingerprint({ confidence: 140 }))).toBe(100);
    expect(confidencePercent(fingerprint({ confidence: Number.NaN }))).toBe(0);
  });
});

describe('the panel', () => {
  it('shows the prompt without a selection', () => {
    render(InfoFingerprint, { props: { row: null } });
    expect(screen.getByText('Select a host to see its information.').hidden).toBe(false);
    expect((document.querySelector('.lan-body') as HTMLElement).hidden).toBe(true);
  });

  it('shows the guesses, the confidence meter and the notes', () => {
    render(InfoFingerprint, { props: { row: hostRow() } });

    expect(value('Type')).toBe('Printer');
    expect(value('OS')).toBe('Linux-like');
    expect(value('Model')).toBe('HL-L2350DW');

    const meter = screen.getByRole('meter', { name: 'Confidence' });
    expect(meter.getAttribute('aria-valuenow')).toBe('87');
    expect(meter.getAttribute('aria-valuemax')).toBe('100');
    expect(meter.style.getPropertyValue('--osm-value')).toBe('0.87');
    expect(value('Confidence')).toBe('87%');

    const notes = notesView();
    expect(notes.readOnly).toBe(true);
    expect(notes.value).toBe(notesText(fingerprint()));
  });

  it('says Unknown and n/a without a fingerprint, with no meter', () => {
    render(InfoFingerprint, { props: { row: hostRow(host({ fingerprint: null })) } });

    expect(value('Type')).toBe('Unknown');
    expect(value('OS')).toBe('Unknown');
    expect(value('Model')).toBe('Unknown');
    expect(value('Confidence')).toBe('n/a');
    expect(screen.queryByRole('meter')).toBeNull();
    expect(notesView().value).toBe('Not identified yet.');
  });

  it('follows the selection into the notes view', async () => {
    const { rerender } = render(InfoFingerprint, { props: { row: hostRow() } });
    await rerender({ row: hostRow(host({ fingerprint: fingerprint({ sources: ['arp-table'], notes: [] }) })) });
    expect(notesView().value).toBe('Sources: arp-table');
  });
});
