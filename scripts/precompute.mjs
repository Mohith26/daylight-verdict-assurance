// Precomputes the headline results (data/results.json) from data/incidents.json with src/core.js.
// Deterministic. tests/core.test.mjs recomputes and compares.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as C from '../src/core.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
export const DEFAULTS = { risk: 'leak', alpha: 0.005, delta: 0.05, window: 7, firstDay: 9, lastDay: 16, staticCutoffDay: 10 };

export function load() {
  return C.unpack(JSON.parse(fs.readFileSync(path.join(root, 'data/incidents.json'), 'utf8')));
}

export function compute() {
  const { meta, incidents } = load();
  const inc = incidents.filter((x) => x.minute >= 0);
  const D = DEFAULTS, out = { defaults: D, orgs: meta.orgs, modes: {} };
  const r4 = (x) => Math.round(x * 1e5) / 1e5;
  for (const mode of ['customer', 'plugin', 'fleet']) {
    const rows = C.rolling(inc, { risk: D.risk, alpha: D.alpha, delta: D.delta, mode, firstDay: D.firstDay, lastDay: D.lastDay, window: D.window });
    const s = C.summarize(rows, D.alpha);
    out.modes[mode] = { summary: { ...s, autoShare: r4(s.autoShare), miss: r4(s.miss), leak: r4(s.leak) },
      rows: rows.map((r) => ({ org: r.org, n: r.n, tp: r.tp, closed: r.closed, missed: r.closedTP, autoShare: r4(r.autoShare), risk: r4(r.risk), sigBreach: r.sigBreach })) };
  }
  const { test } = C.split(inc, D.staticCutoffDay * 1440);
  out.test_auc = r4(C.auc(test));
  out.incidents = inc.length;
  out.rolling_incidents = out.modes.customer.summary.n;
  return out;
}

if (process.argv[1] && process.argv[1].endsWith('precompute.mjs')) {
  const r = compute();
  fs.writeFileSync(path.join(root, 'data/results.json'), JSON.stringify(r));
  for (const [m, v] of Object.entries(r.modes)) console.log(m, JSON.stringify(v.summary));
  console.log('auc', r.test_auc, 'n', r.incidents, r.rolling_incidents);
}
