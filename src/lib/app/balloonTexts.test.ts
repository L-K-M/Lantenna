import { expect, it } from 'vitest';
import { COLUMN_IDS } from './columns';
import { columnBalloon, openBalloon, scanBalloon, showHiddenBalloon, wakeBalloon } from './balloonTexts';
import { cmdName } from './platform';

it('adds the dimmed note only for its own reason', () => {
  expect(wakeBalloon(null)).not.toContain('Not available');
  expect(wakeBalloon('noMac')).toMatch(/\n\nNot available because this host’s MAC address is unknown\.$/);
  expect(openBalloon('noTarget')).toMatch(/offers no service Lantenna can open\.$/);
  expect(showHiddenBalloon('noneHidden')).toMatch(/no hosts are hidden\.$/);
});

it('names the platform’s command key and follows the scan state', () => {
  expect(scanBalloon('idle')).toContain(`Keyboard: ${cmdName}-R.`);
  expect(scanBalloon('stop')).toMatch(/^Stop button\n\n/);
  expect(scanBalloon('stop')).toContain(`${cmdName}-period`);
  expect(scanBalloon('noInterface')).toContain('no network interface');
});

it('describes every column header', () => {
  for (const id of COLUMN_IDS) expect(columnBalloon(id)).toMatch(/ column\n\nClick here to /);
  expect(columnBalloon('ip')).toContain('sort the list by IP address.');
  expect(columnBalloon('favorite')).toMatch(/^Favorites column/);
});
