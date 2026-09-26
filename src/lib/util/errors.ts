/**
 * Message for a caught error. Tauri's `invoke` rejects with the command's
 * error value, which for Lantenna's commands is a plain string, not an
 * `Error`, so `error instanceof Error` alone would drop the real message.
 */
export function errorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message) {
    return error.message;
  }

  if (typeof error === 'string' && error.trim()) {
    return error;
  }

  return fallback;
}
