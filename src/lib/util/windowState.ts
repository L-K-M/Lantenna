import { writable } from 'svelte/store';

// Active decorations, not keyboard focus (native drags can temporarily take it).
export const windowFocused = writable(true);
