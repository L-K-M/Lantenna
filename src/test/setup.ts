// Owner: scaffold (spec 8.3, 8.5). Test environment for Osmium UI under
// happy-dom, which lacks what Osmium's installOsmium() and controls use:
//
// - FontFace and document.fonts: installOsmium() builds the bitmap fonts
//   as FontFaces and adds them to document.fonts. Without them it rejects
//   and every mountWindow logs "Osmium fonts unavailable".
// - Canvas 2D: text measurement (textWidth) asks for a context; null is
//   Osmium's "can't measure" path (widths 0), taken quietly.
// - document.execCommand: the clipboard fallback and Linux Edit menu
//   clicks call it. It returns false (not done), as a browser does for an
//   unsupported command; spy on it to test the other outcome.
//
// Only what is missing is added, so a happy-dom that grows these keeps
// its own.

class FontFaceStub {
  readonly family: string;
  readonly status = 'loaded';

  constructor(family: string) {
    this.family = family;
  }

  load(): Promise<this> {
    return Promise.resolve(this);
  }
}

if (typeof globalThis.FontFace === 'undefined') {
  globalThis.FontFace = FontFaceStub as unknown as typeof FontFace;
}

if (!('fonts' in document)) {
  const faces = new Set<unknown>();
  Object.defineProperty(document, 'fonts', {
    configurable: true,
    value: {
      add: (face: unknown) => faces.add(face),
      delete: (face: unknown) => faces.delete(face),
      check: () => true,
      load: () => Promise.resolve([]),
      ready: Promise.resolve()
    }
  });
}

HTMLCanvasElement.prototype.getContext = function getContext() {
  return null;
} as typeof HTMLCanvasElement.prototype.getContext;

if (typeof document.execCommand !== 'function') {
  Object.defineProperty(document, 'execCommand', {
    configurable: true,
    writable: true,
    value: (): boolean => false
  });
}
