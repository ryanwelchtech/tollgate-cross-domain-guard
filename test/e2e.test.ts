import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

test('end-to-end: real processes, real UDP diode, 20% frame loss', () => {
  const r = spawnSync(process.execPath, [join(import.meta.dirname, '../services/demo.ts')], {
    env: { ...process.env, TG_SIM_LOSS: '0.20' }, encoding: 'utf8', timeout: 60_000,
  });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /3\/3 released transfers accepted/);
});
