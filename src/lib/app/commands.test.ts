import { afterEach, expect, it } from 'vitest';
import { get } from 'svelte/store';
import { isModal, showAlert, type OsmiumAlert } from 'osmium-ui';
import { commandContext } from './commands';

let alert: OsmiumAlert | null = null;

afterEach(async () => {
  alert?.close();
  await alert?.result;
  alert = null;
});

it('sees an alert that opened while nothing read the context', async () => {
  expect(get(commandContext).modal).toBe(false);

  alert = showAlert({ kind: 'stop', message: 'Lantenna couldn’t start its scanner.' });
  expect(isModal()).toBe(true);
  expect(get(commandContext).modal).toBe(true);

  alert.close();
  await alert.result;
  expect(get(commandContext).modal).toBe(false);
});
