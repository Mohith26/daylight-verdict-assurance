import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as C from '../src/core.js';
import { compute, load, DEFAULTS } from '../scripts/precompute.mjs';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const { meta, incidents } = load();
const INC = incidents.filter((x) => x.minute >= 0);

function lchoose(n, k) { let s = 0; for (let i = 0; i < k; i++) s += Math.log(n - i) - Math.log(i + 1); return s; }
function naiveCdf(k, n, p) { let s = 0; for (let i = 0; i <= k; i++) s += Math.exp(lchoose(n, i) + i * Math.log(p) + (n - i) * Math.log(1 - p)); return s; }

test('data: 14 GUIDE organisations, labels and scores well formed', () => {
  assert.equal(meta.orgs.length, 14);
  assert.equal(incidents.length, meta.n);
  for (const x of incidents.slice(0, 5000)) {
    assert.ok(x.score > 0 && x.score < 1);
    assert.ok(['T', 'B', 'F'].includes(x.grade));
    assert.equal(x.tp, x.grade === 'T' ? 1 : 0);
  }
});

test('binomial CDF matches direct summation and handles edges', () => {
  const rnd = C.mulberry32(1);
  for (let t = 0; t < 200; t++) {
    const n = 1 + Math.floor(rnd() * 300), k = Math.floor(rnd() * n), p = 0.001 + rnd() * 0.3;
    assert.ok(Math.abs(C.binomCdf(k, n, p) - naiveCdf(k, n, p)) < 1e-9);
  }
  assert.equal(C.binomCdf(-1, 10, 0.1), 0);
  assert.equal(C.binomCdf(10, 10, 0.1), 1);
  assert.ok(C.binomCdf(0, 50000, 0.005) < 1e-100);
});

test('Clopper-Pearson upper bound: P(Bin(n, ub) <= k) = 1 - conf', () => {
  for (const [k, n] of [[0, 100], [3, 200], [12, 1000]]) {
    const ub = C.cpUpper(k, n, 0.95);
    assert.ok(Math.abs(C.binomCdf(k, n, ub) - 0.05) < 1e-6);
    assert.ok(ub > k / n);
  }
});

test('sweep counts equal direct counts at every grid point', () => {
  const xs = INC.filter((x) => x.org === '55').slice(0, 400);
  const sw = C.sweep(xs);
  for (const g of [0, 100, 400, 600, 800]) {
    const c = C.counts(xs, C.GRID[g]);
    assert.deepEqual([sw[g].closed, sw[g].closedTP, sw[g].tp, sw[g].n], [c.closed, c.closedTP, c.tp, c.n]);
  }
});

test('certify: certified threshold is on the grid, p-values below delta up to it', () => {
  const xs = INC.filter((x) => x.org === '38' && x.minute < 9 * 1440);
  const r = C.certify(xs, { risk: 'leak', alpha: 0.005, delta: 0.05 });
  assert.ok(r.index >= 0 && r.lambda === C.GRID[r.index]);
  for (let g = 0; g <= r.index; g++) assert.ok(r.pvalues[g] <= 0.05);
  assert.ok(r.index < C.GRID.length - 1 && r.pvalues[r.index + 1] > 0.05); // stopped at the first non-rejection
});

test('certify never auto-closes with no evidence, and is at least as strict as the plug-in rule', () => {
  assert.equal(C.certify([], { risk: 'miss' }).lambda, 0);
  for (const org of meta.orgs) {
    const xs = INC.filter((x) => x.org === org && x.minute < 9 * 1440);
    for (const risk of ['miss', 'leak']) {
      const a = risk === 'miss' ? 0.02 : 0.005;
      assert.ok(C.certify(xs, { risk, alpha: a }).lambda <= C.plugIn(xs, { risk, alpha: a }).lambda);
    }
  }
});

test('monotone: a looser bound or lower confidence never shrinks the certified threshold', () => {
  const xs = INC.filter((x) => x.org === '6' && x.minute < 9 * 1440);
  const l = (alpha, delta) => C.certify(xs, { risk: 'leak', alpha, delta }).lambda;
  assert.ok(l(0.002, 0.05) <= l(0.005, 0.05) && l(0.005, 0.05) <= l(0.01, 0.05));
  assert.ok(l(0.005, 0.01) <= l(0.005, 0.05) && l(0.005, 0.05) <= l(0.005, 0.1));
});

test('property: Learn-then-Test controls the true risk with probability >= 1 - delta (simulation)', () => {
  // Synthetic world with a known score distribution: threats score high, benign low, 15% threats.
  const rnd = C.mulberry32(42);
  const draw = () => { const tp = rnd() < 0.15 ? 1 : 0; const z = tp ? 1.2 + 1.3 * gauss() : -2.5 + 1.6 * gauss(); return { tp, score: 1 / (1 + Math.exp(-z)) }; };
  function gauss() { let u = 0, v = 0; while (u === 0) u = rnd(); while (v === 0) v = rnd(); return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v); }
  const big = Array.from({ length: 200000 }, draw); // population to measure true risk
  const bigSw = C.sweep(big);
  const trueMiss = (lambda) => { const g = C.GRID.indexOf(lambda); if (g < 0) return 0; return C.riskValue(bigSw[g], 'miss'); };
  let fail = 0; const trials = 150, alpha = 0.05, delta = 0.1;
  for (let t = 0; t < trials; t++) {
    const cal = Array.from({ length: 600 }, draw);
    const lam = C.certify(cal, { risk: 'miss', alpha, delta }).lambda;
    if (lam > 0 && trueMiss(lam) > alpha) fail++;
  }
  assert.ok(fail / trials <= delta + 0.03, 'failure rate ' + fail / trials);
});

test('plug-in threshold overshoots the bound far more often than the certified one (same simulation)', () => {
  const rnd = C.mulberry32(7);
  const gauss = () => { let u = 0, v = 0; while (u === 0) u = rnd(); while (v === 0) v = rnd(); return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v); };
  const draw = () => { const tp = rnd() < 0.15 ? 1 : 0; const z = tp ? 1.2 + 1.3 * gauss() : -2.5 + 1.6 * gauss(); return { tp, score: 1 / (1 + Math.exp(-z)) }; };
  const bigSw = C.sweep(Array.from({ length: 200000 }, draw));
  const tr = (lam) => C.riskValue(bigSw[C.GRID.indexOf(lam)] || { closedTP: 0, tp: 1 }, 'miss');
  let fc = 0, fp = 0;
  for (let t = 0; t < 120; t++) {
    const cal = Array.from({ length: 600 }, draw);
    const a = C.certify(cal, { risk: 'miss', alpha: 0.05, delta: 0.1 }).lambda, b = C.plugIn(cal, { risk: 'miss', alpha: 0.05 }).lambda;
    if (a > 0 && tr(a) > 0.05) fc++;
    if (b > 0 && tr(b) > 0.05) fp++;
  }
  assert.ok(fp > 3 * fc && fp / 120 > 0.3, `plug-in ${fp}, certified ${fc}`);
});

test('policyTable + summarize add up', () => {
  const { cal, test: te } = C.split(INC, 10 * 1440);
  const rows = C.policyTable(cal, te, { risk: 'leak', alpha: 0.005, orgs: meta.orgs });
  const s = C.summarize(rows, 0.005);
  assert.equal(s.n, te.length);
  assert.equal(s.closed, rows.reduce((a, r) => a + r.closed, 0));
  assert.equal(s.customers, 14);
});

test('rolling deployment equals per-day policy tables summed', () => {
  const o = { risk: 'leak', alpha: 0.005, delta: 0.05, mode: 'customer', firstDay: 12, lastDay: 13, window: 5, orgs: meta.orgs };
  const rows = C.rolling(INC, o);
  let closed = 0, missed = 0;
  for (let d = 12; d <= 13; d++) {
    const cal = INC.filter((x) => x.minute >= (d - 5) * 1440 && x.minute < d * 1440), te = INC.filter((x) => x.minute >= d * 1440 && x.minute < (d + 1) * 1440);
    for (const r of C.policyTable(cal, te, o)) { closed += r.closed; missed += r.closedTP; }
  }
  assert.equal(rows.reduce((a, r) => a + r.closed, 0), closed);
  assert.equal(rows.reduce((a, r) => a + r.closedTP, 0), missed);
});

test('stand-in triage model ranks well on held-out organisations (AUC > 0.95)', () => {
  assert.ok(C.auc(INC) > 0.95);
});

test('headline: committed results.json is reproduced exactly', () => {
  const committed = JSON.parse(fs.readFileSync(path.join(root, 'data/results.json'), 'utf8'));
  assert.deepEqual(JSON.parse(JSON.stringify(compute())), committed);
  const c = committed.modes.customer.summary, p = committed.modes.plugin.summary;
  assert.equal(DEFAULTS.alpha, 0.005);
  assert.equal(c.n, 28351);
  assert.equal(Math.round(c.autoShare * 1000) / 10, 41.2); // 41.2% taken off the expert queue
  assert.equal(c.missed, 42);
  assert.equal(c.sigBreaches, 0);
  assert.equal(p.missed, 79);
  assert.equal(p.sigBreaches, 3);
});

test('toCSV escapes', () => {
  assert.equal(C.toCSV([{ a: 'x,y', b: '"q"' }]), 'a,b\n"x,y","""q"""');
});
