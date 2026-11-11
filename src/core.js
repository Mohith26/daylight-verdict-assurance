// Verdict assurance: certified expert-routing thresholds for AI triage verdicts. No DOM.
//
// Setting. Each incident gets an AI verdict confidence s in [0, 1] (probability it is a true
// positive). Incidents with s < lambda are closed by the agent (benign verdict, documented); the
// rest go to a security expert. We want the largest lambda (most work taken off experts) such that
// a stated risk stays below alpha, with probability at least 1 - delta over the calibration data:
//
//   miss  : share of real threats (TruePositive) that get auto-closed            P(s < lambda | TP)
//   leak  : real threats auto-closed per incident handled                       P(TP and s < lambda)
//
// Method: Learn then Test (Angelopoulos, Bates, Candes, Jordan, Lei 2021). For each lambda on a
// FIXED grid (chosen before seeing data) test H0: risk(lambda) > alpha with an exact binomial
// p-value, walking the grid from the most conservative lambda upward (fixed-sequence testing,
// which controls the family-wise error at delta). The certified lambda is the last rejection.
// Calibration is per customer (Mondrian): every customer gets its own guarantee.

export const GRID = Object.freeze(Array.from({ length: 801 }, (_, i) => 1 / (1 + Math.exp(-(-12 + i * 0.02)))));

// ---------- data ----------

export function unpack(json) {
  const { meta, cols } = json;
  const n = meta.n;
  const inc = new Array(n);
  for (let i = 0; i < n; i++) {
    inc[i] = { i, org: meta.orgs[cols.org[i]], iid: cols.iid[i], grade: cols.grade[i], tp: cols.grade[i] === 'T' ? 1 : 0,
      minute: cols.minute[i], score: cols.score[i], alerts: cols.alerts[i], evidence: cols.evidence[i],
      title: meta.titles[cols.title[i]], category: meta.categories[cols.category[i]],
      mitre: cols.mitre[i].map((m) => meta.mitre[m]), verdict: meta.verdicts[cols.verdict[i]], entities: meta.entities[cols.ent[i]] };
  }
  return { meta, incidents: inc };
}

export function split(incidents, cutoffMinute) {
  const cal = [], test = [];
  for (const x of incidents) (x.minute < cutoffMinute ? cal : test).push(x);
  return { cal, test };
}

export function byOrg(incidents) {
  const m = new Map();
  for (const x of incidents) { if (!m.has(x.org)) m.set(x.org, []); m.get(x.org).push(x); }
  return m;
}

// ---------- exact binomial tail ----------

function logAdd(a, b) { if (a === -Infinity) return b; if (b === -Infinity) return a; const m = Math.max(a, b); return m + Math.log(Math.exp(a - m) + Math.exp(b - m)); }

/** P(Bin(n, p) <= k), exact, computed in log space (stable for n in the hundreds of thousands). */
export function binomCdf(k, n, p) {
  if (k < 0) return 0;
  if (k >= n) return 1;
  if (p <= 0) return 1;
  if (p >= 1) return 0;
  const lp = Math.log(p), lq = Math.log1p(-p);
  let lpmf = n * lq, acc = lpmf;
  for (let i = 0; i < k; i++) {
    lpmf += Math.log(n - i) - Math.log(i + 1) + lp - lq;
    acc = logAdd(acc, lpmf);
  }
  return Math.min(1, Math.exp(acc));
}

/** Clopper-Pearson upper confidence bound for a binomial proportion. */
export function cpUpper(k, n, conf) {
  if (n === 0) return 1;
  if (k >= n) return 1;
  let lo = k / n, hi = 1;
  for (let it = 0; it < 60; it++) { const mid = (lo + hi) / 2; if (binomCdf(k, n, mid) > 1 - conf) lo = mid; else hi = mid; }
  return hi;
}

// ---------- risk counts ----------

/** Counts at threshold lambda: auto-closed = score < lambda. */
export function counts(xs, lambda) {
  let closed = 0, closedTP = 0, tp = 0;
  for (const x of xs) {
    if (x.tp) tp++;
    if (x.score < lambda) { closed++; if (x.tp) closedTP++; }
  }
  return { n: xs.length, closed, closedTP, tp };
}

/** (k, n) for the binomial test of each risk. */
export function riskKN(c, risk) {
  return risk === 'miss' ? { k: c.closedTP, n: c.tp } : { k: c.closedTP, n: c.n };
}

export function riskValue(c, risk) {
  const { k, n } = riskKN(c, risk);
  return n ? k / n : 0;
}

/** Sorted-score sweep: counts for every grid point in one pass. */
export function sweep(xs, grid = GRID) {
  const s = xs.map((x) => [x.score, x.tp]).sort((a, b) => a[0] - b[0]);
  const tp = s.reduce((a, v) => a + v[1], 0);
  const out = new Array(grid.length);
  let j = 0, closed = 0, closedTP = 0;
  for (let g = 0; g < grid.length; g++) {
    while (j < s.length && s[j][0] < grid[g]) { closed++; closedTP += s[j][1]; j++; }
    out[g] = { lambda: grid[g], n: s.length, closed, closedTP, tp };
  }
  return out;
}

// ---------- Learn then Test (fixed sequence) ----------

/**
 * Certified threshold. Walk the grid upward; at each lambda reject H0: risk > alpha when the exact
 * binomial p-value P(Bin(n, alpha) <= k) <= delta. Stop at the first non-rejection.
 * Returns { lambda, index, pvalues } ; lambda = 0 means nothing may be auto-closed.
 */
export function certify(xs, { risk = 'miss', alpha = 0.01, delta = 0.05, grid = GRID } = {}) {
  const sw = sweep(xs, grid);
  let idx = -1;
  const pvalues = [];
  for (let g = 0; g < sw.length; g++) {
    const { k, n } = riskKN(sw[g], risk);
    const p = n === 0 ? 1 : binomCdf(k, n, alpha); // no evidence -> cannot certify
    pvalues.push(p);
    if (p <= delta) idx = g; else break;
  }
  return { lambda: idx >= 0 ? grid[idx] : 0, index: idx, pvalues, sweep: sw };
}

/** Uncorrected baseline: largest grid lambda (walking upward) whose empirical risk is <= alpha. */
export function plugIn(xs, { risk = 'miss', alpha = 0.01, grid = GRID } = {}) {
  const sw = sweep(xs, grid);
  let idx = -1;
  for (let g = 0; g < sw.length; g++) { if (riskValue(sw[g], risk) <= alpha) idx = g; else break; }
  return { lambda: idx >= 0 ? grid[idx] : 0, index: idx, sweep: sw };
}

/** Outcome of a threshold on (test) incidents. */
export function evaluate(xs, lambda, risk = 'miss') {
  const c = counts(xs, lambda);
  return { ...c, autoShare: c.n ? c.closed / c.n : 0, risk: riskValue(c, risk), missed: c.closedTP, miss: c.tp ? c.closedTP / c.tp : 0, leak: c.n ? c.closedTP / c.n : 0 };
}

/**
 * Per-customer policy table. mode: 'customer' (LTT per customer), 'fleet' (one LTT threshold for all
 * customers), 'plugin' (per-customer, no correction).
 */
export function policyTable(cal, test, { risk = 'miss', alpha = 0.01, delta = 0.05, mode = 'customer', orgs } = {}) {
  const calBy = byOrg(cal), testBy = byOrg(test);
  const fleet = mode === 'fleet' ? certify(cal, { risk, alpha, delta }).lambda : null;
  const rows = [];
  for (const org of orgs || [...calBy.keys()]) {
    const c = calBy.get(org) || [], t = testBy.get(org) || [];
    const lambda = mode === 'fleet' ? fleet : mode === 'plugin' ? plugIn(c, { risk, alpha }).lambda : certify(c, { risk, alpha, delta }).lambda;
    const calC = counts(c, lambda);
    const ev = evaluate(t, lambda, risk);
    const { k, n } = riskKN(ev, risk);
    // one-sided exact test that the TRUE test-week risk exceeds alpha (a realized rate a hair above
    // alpha is expected half the time even when the bound holds exactly)
    const pBreach = n ? 1 - binomCdf(k - 1, n, alpha) : 1;
    rows.push({ org, lambda, calN: c.length, calTP: calC.tp, calRisk: riskValue(calC, risk), ...ev, ok: ev.risk <= alpha + 1e-12, pBreach, sigBreach: pBreach < 0.05 });
  }
  return rows;
}

/**
 * Rolling deployment: every day d in [firstDay, lastDay], recalibrate each customer on the trailing
 * `window` days and apply that threshold to day d. Returns per-customer rows aggregated over days.
 */
export function rolling(incidents, { risk = 'miss', alpha = 0.01, delta = 0.05, mode = 'customer', firstDay, lastDay, window = 7, orgs } = {}) {
  const acc = new Map();
  for (let d = firstDay; d <= lastDay; d++) {
    const cal = incidents.filter((x) => x.minute >= (d - window) * 1440 && x.minute < d * 1440);
    const test = incidents.filter((x) => x.minute >= d * 1440 && x.minute < (d + 1) * 1440);
    for (const r of policyTable(cal, test, { risk, alpha, delta, mode, orgs })) {
      const a = acc.get(r.org) || { org: r.org, n: 0, closed: 0, closedTP: 0, tp: 0, lambdas: [] };
      a.n += r.n; a.closed += r.closed; a.closedTP += r.closedTP; a.tp += r.tp; a.lambdas.push(r.lambda);
      acc.set(r.org, a);
    }
  }
  return [...acc.values()].map((a) => {
    const risk_ = risk === 'miss' ? (a.tp ? a.closedTP / a.tp : 0) : (a.n ? a.closedTP / a.n : 0);
    const { k, n } = riskKN(a, risk);
    const pBreach = n ? 1 - binomCdf(k - 1, n, alpha) : 1;
    return { ...a, lambda: a.lambdas[a.lambdas.length - 1], autoShare: a.n ? a.closed / a.n : 0, risk: risk_, miss: a.tp ? a.closedTP / a.tp : 0, leak: a.n ? a.closedTP / a.n : 0, pBreach, sigBreach: pBreach < 0.05, ok: risk_ <= alpha + 1e-12 };
  });
}

export function summarize(rows, alpha) {
  const n = rows.reduce((a, r) => a + r.n, 0), closed = rows.reduce((a, r) => a + r.closed, 0);
  const tp = rows.reduce((a, r) => a + r.tp, 0), missed = rows.reduce((a, r) => a + r.closedTP, 0);
  return { n, closed, autoShare: n ? closed / n : 0, tp, missed, miss: tp ? missed / tp : 0, leak: n ? missed / n : 0,
    breaches: rows.filter((r) => r.risk > alpha + 1e-12).length, sigBreaches: rows.filter((r) => r.sigBreach).length, customers: rows.length, certified: rows.filter((r) => r.lambda > 0).length };
}

// ---------- utilities ----------

export function auc(xs) {
  const s = xs.map((x) => [x.score, x.tp]).sort((a, b) => a[0] - b[0]);
  const pos = s.reduce((a, v) => a + v[1], 0), neg = s.length - pos;
  let rank = 0, i = 0;
  while (i < s.length) {
    let j = i; while (j < s.length && s[j][0] === s[i][0]) j++;
    const avg = (i + j + 1) / 2; for (let q = i; q < j; q++) if (s[q][1]) rank += avg;
    i = j;
  }
  return pos && neg ? (rank - pos * (pos + 1) / 2) / (pos * neg) : NaN;
}

export function mulberry32(seed) {
  let a = seed >>> 0;
  return () => { a = (a + 0x6d2b79f5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}

export function toCSV(rows) {
  if (!rows.length) return '';
  const cols = Object.keys(rows[0]);
  const esc = (v) => { const s = String(v ?? ''); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  return [cols.join(','), ...rows.map((r) => cols.map((c) => esc(r[c])).join(','))].join('\n');
}
