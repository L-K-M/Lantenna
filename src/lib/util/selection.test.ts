import { get } from 'svelte/store';
import { afterEach, expect, it } from 'vitest';
import { textSelection } from './selection';

afterEach(() => {
  getSelection()?.removeAllRanges();
  document.body.textContent = '';
});

it('follows the document’s text selection', async () => {
  const value = document.createElement('span');
  value.textContent = '30:05:5C:12:34:56';
  document.body.append(value);
  const seen: boolean[] = [];
  const stop = textSelection.subscribe((selected) => seen.push(selected));

  getSelection()?.selectAllChildren(value);
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect(get(textSelection)).toBe(true);

  getSelection()?.removeAllRanges();
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect(seen).toEqual([false, true, false]);
  stop();
});
