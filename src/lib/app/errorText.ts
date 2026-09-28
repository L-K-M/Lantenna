// Owner: unit D (spec 8.4). Spec: 5.4 (explainError table).
//
// Pure. The backend reports failures as plain English strings (Rust
// `anyhow` messages and `format!`s, see inventory 3). The known ones
// become an explanation that says what happened and what to do next,
// for a stop alert's explanation and the header's error line (5.2), so
// both say the same thing. Anything else is shown as is, as a sentence.

type Rule = readonly [pattern: RegExp, explain: (m: RegExpMatchArray) => string];

const RULES: readonly Rule[] = [
  [
    /^Interface '(.*)' not found$/s,
    (m) => `The interface ${m[1]} is no longer available. Choose another interface, then click Scan.`
  ],
  [
    /^Invalid subnet '(.*)'$/s,
    (m) => `The subnet ${m[1]} can’t be scanned. Choose another interface, then click Scan.`
  ],
  [/^No target hosts found in subnet (.*)$/s, (m) => `The subnet ${m[1]} has no other addresses to scan.`],
  // The backend's context message; a detail may follow it.
  [
    /^Failed to list network interfaces\b/,
    () => 'Lantenna couldn’t read this computer’s network interfaces. Try again in a moment.'
  ],
  [
    /^The scanner stopped unexpectedly: (.*)$/s,
    (m) => `The scanner stopped unexpectedly (${m[1]}). Click Scan to try again.`
  ],
  [/^A scan is already running$/, () => 'Another scan is still running. Wait for it to finish, then try again.'],
  [/^Invalid IPv4 address '(.*)'$/s, (m) => `“${m[1]}” isn’t a valid IPv4 address.`],
  [/^Invalid MAC address '(.*)'$/s, (m) => `“${m[1]}” isn’t a valid MAC address.`],
  [
    /^Unsupported URL scheme$/,
    () => 'Lantenna opens only web, file sharing, remote login and screen sharing addresses.'
  ],
  // The open crate: every launcher (xdg-open, gio, …) ran and refused,
  // likely on a Linux system with no default application set.
  [/^Launcher .* failed with /s, () => 'No application is set up to open this address.'],
  // reqwest's connection failure (DNS, refused, TLS, timeout), as the
  // update check reports it.
  [
    /^error sending request for url \((?:[a-z]+:\/\/)?([^/:)]+)/,
    (m) => `Lantenna couldn’t reach ${m[1]}. Check your Internet connection, then try again.`
  ]
];

/** Ends like a sentence already. */
const FINAL_PUNCTUATION = /[.!?…]$/;

/** The explanation for a backend error string (table 5.4); unknown text
 * as is, with a final period added. Empty text gives "". */
export function explainError(raw: string): string {
  const text = raw.trim();
  if (text === '') return '';

  for (const [pattern, explain] of RULES) {
    const m = text.match(pattern);
    if (m) return explain(m);
  }

  return FINAL_PUNCTUATION.test(text) ? text : `${text}.`;
}
