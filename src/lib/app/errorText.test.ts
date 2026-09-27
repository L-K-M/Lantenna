// Owner: unit D (spec 8.4). Spec: 5.4 (the explainError table).
import { expect, it } from 'vitest';
import { explainError } from './errorText';

it.each([
  [
    "Interface 'en0' not found",
    'The interface en0 is no longer available. Choose another interface, then click Scan.'
  ],
  [
    "Invalid subnet '192.168.1.0/33'",
    'The subnet 192.168.1.0/33 can’t be scanned. Choose another interface, then click Scan.'
  ],
  ['No target hosts found in subnet 10.0.0.1/32', 'The subnet 10.0.0.1/32 has no other addresses to scan.'],
  [
    'Failed to list network interfaces',
    'Lantenna couldn’t read this computer’s network interfaces. Try again in a moment.'
  ],
  [
    'The scanner stopped unexpectedly: index out of bounds',
    'The scanner stopped unexpectedly (index out of bounds). Click Scan to try again.'
  ],
  ['A scan is already running', 'Another scan is still running. Wait for it to finish, then try again.'],
  ["Invalid IPv4 address '192.168.1.300'", '“192.168.1.300” isn’t a valid IPv4 address.'],
  ["Invalid MAC address '30:05:5C'", '“30:05:5C” isn’t a valid MAC address.'],
  ['Unsupported URL scheme', 'Lantenna opens only web, file sharing, remote login and screen sharing addresses.']
])('explains %j', (raw, explanation) => {
  expect(explainError(raw)).toBe(explanation);
});

it('keeps a detail after the interface-list failure', () => {
  expect(explainError('Failed to list network interfaces: permission denied')).toBe(
    'Lantenna couldn’t read this computer’s network interfaces. Try again in a moment.'
  );
});

it('shows unknown text as is, as a sentence', () => {
  expect(explainError('GitHub returned HTTP 503')).toBe('GitHub returned HTTP 503.');
  expect(explainError('  Failed to initialize scanner  ')).toBe('Failed to initialize scanner.');
  expect(explainError('Clipboard is not available.')).toBe('Clipboard is not available.');
  expect(explainError('Is the network up?')).toBe('Is the network up?');
  expect(explainError('')).toBe('');
});

it('matches whole messages only', () => {
  expect(explainError('A scan is already running elsewhere')).toBe('A scan is already running elsewhere.');
  expect(explainError("Error: Interface 'en0' not found")).toBe("Error: Interface 'en0' not found.");
});
