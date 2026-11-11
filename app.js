// UI for Verdict assurance. Every number is computed in the browser by src/core.js from data/incidents.json.
import * as C from './src/core.js';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const pct = (x, d = 1) => (Number.isFinite(x) ? (100 * x).toFixed(d) + '%' : '–');
const fmt = (n) => n.toLocaleString('en-US');
const DAY0 = Date.UTC(2024, 5, 1);
const dayLabel = (d) => new Date(DAY0 + d * 86400000).toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' });
const timeLabel = (m) => new Date(DAY0 + m * 60000).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'UTC' }) + ' UTC';
const STORE = 'daylight-verdict-assurance/v1';
const FIRST = 9, LAST = 16; // replay days (Jun 10 - Jun 17, 2024)
const DEF = { risk: 'leak', alpha: 0.005, conf: 95, window: 7, org: '', filter: 'all', inc: '' };
const ALPHAS = { leak: [0.001, 0.002, 0.005, 0.01], miss: [0.005, 0.01, 0.02, 0.05] };
const RISK_LABEL = { leak: 'Threats closed per incident', miss: 'Share of threats closed' };

let DATA = null, RESULTS = null;
let state = { view: 'overview', ...DEF };
let policies = [];
const cache = new Map();

// ---------- URL state ----------
function readHash() {
  const [v, qs] = location.hash.replace(/^#/, '').split('?');
  const p = new URLSearchParams(qs || '');
  const s = { ...DEF, view: ['overview', 'customer', 'policies', 'method'].includes(v) ? v : 'overview' };
  for (const k of Object.keys(DEF)) if (p.has(k)) s[k] = ['alpha', 'conf', 'window'].includes(k) ? Number(p.get(k)) : p.get(k);
  if (!['leak', 'miss'].includes(s.risk)) s.risk = 'leak';
  if (!ALPHAS[s.risk].includes(s.alpha)) s.alpha = ALPHAS[s.risk][2];
  if (![90, 95, 99].includes(s.conf)) s.conf = 95;
  if (![3, 5, 7].includes(s.window)) s.window = 7;
  if (s.view === 'customer' && !DATA.meta.orgs.includes(s.org)) s.view = 'overview';
  return s;
}
function writeHash(push) {
  const p = new URLSearchParams();
  for (const k of Object.keys(DEF)) if (state[k] !== '' && String(state[k]) !== String(DEF[k])) p.set(k, state[k]);
  const url = '#' + state.view + (p.toString() ? '?' + p : '');
  if (url !== location.hash) history[push ? 'pushState' : 'replaceState'](null, '', url);
}
function set(patch, push = false) { state = { ...state, ...patch }; writeHash(push); render(); }

// ---------- computation ----------
const opts = (s, mode) => ({ risk: s.risk, alpha: s.alpha, delta: 1 - s.conf / 100, mode, firstDay: FIRST, lastDay: LAST, window: s.window, orgs: DATA.meta.orgs });
function key(s, extra = '') { return [s.risk, s.alpha, s.conf, s.window, extra].join('|'); }
function rollingOf(s, mode) { const k = 'R' + key(s, mode); if (!cache.has(k)) cache.set(k, C.rolling(DATA.inc, opts(s, mode))); return cache.get(k); }
/** Per-day certified thresholds: Map(day -> Map(org -> lambda)) for routing individual incidents. */
function dailyLambdas(s, mode = 'customer') {
  const k = 'D' + key(s, mode);
  if (!cache.has(k)) {
    const m = new Map();
    for (let d = FIRST; d <= LAST; d++) {
      const cal = DATA.inc.filter((x) => x.minute >= (d - s.window) * 1440 && x.minute < d * 1440);
      const rows = C.policyTable(cal, [], { risk: s.risk, alpha: s.alpha, delta: 1 - s.conf / 100, mode, orgs: DATA.meta.orgs });
      m.set(d, new Map(rows.map((r) => [r.org, r.lambda])));
    }
    cache.set(k, m);
  }
  return cache.get(k);
}
function calWindow(s, day) { return DATA.inc.filter((x) => x.minute >= (day - s.window) * 1440 && x.minute < day * 1440); }

// ---------- helpers ----------
let toastT;
function toast(m) { const t = $('toast'); t.textContent = m; t.classList.add('on'); clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove('on'), 2200); }
function download(name, text, type = 'text/csv') { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; document.body.appendChild(a); a.click(); a.remove(); }
const I = {
  arrow: '<svg viewBox="0 0 12 12" fill="currentColor" aria-hidden="true"><path d="M3 1.5 10 6 3 10.5z"/></svg>',
  shield: '<svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 1 14 3.2v4.3c0 3.6-2.6 6.2-6 7.5-3.4-1.3-6-3.9-6-7.5V3.2z"/><path d="m8 4.6.9 1.9 2 .3-1.5 1.4.4 2L8 9.2l-1.8 1 .4-2-1.5-1.4 2-.3z" fill="#fff"/></svg>',
  up: '<svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M6 10V2.5M2.8 5.5 6 2.3l3.2 3.2"/></svg>',
  check: '<svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="m2.5 6.2 2.3 2.3 4.7-5"/></svg>',
  tri_up: '<svg viewBox="0 0 14 14" fill="none" stroke="#e5484d" stroke-width="1.4" aria-hidden="true"><path d="M7 2 12.5 12h-11z"/></svg>',
  tri_dn: '<svg viewBox="0 0 14 14" fill="none" stroke="#1f9e78" stroke-width="1.4" aria-hidden="true"><path d="M7 12 12.5 2h-11z"/></svg>',
  eq: '<svg viewBox="0 0 14 14" fill="none" stroke="#2a9d8f" stroke-width="1.6" aria-hidden="true"><path d="M2.5 5h9M2.5 9h9"/></svg>',
  chev: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="m3.5 9 4.5-4 4.5 4M3.5 13l4.5-4 4.5 4"/></svg>',
  down: '<svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><path d="M6 1.5v7M3 5.5 6 8.5l3-3M2 10.5h8"/></svg>',
};
const statusChip = (r) => r.lambda === 0 && !r.closed ? '<span class="chip gray">Not certified</span>' : r.sigBreach ? `<span class="chip breach">${I.up}Breach</span>` : r.ok ? `<span class="chip ok">${I.check}Within bound</span>` : '<span class="chip sus" title="Realized rate above the bound, but not significantly (exact one-sided test, p ≥ 0.05)">Above, not significant</span>';
const riskFmt = (s, x) => s.risk === 'leak' ? (1000 * x).toFixed(2) + ' / 1k' : pct(x, 2);
const rateNum = (s, x) => s.risk === 'leak' ? (1000 * x).toFixed(2) : pct(x, 2);
const alphaFmt = (s) => s.risk === 'leak' ? (1000 * s.alpha).toFixed(s.alpha < 0.002 ? 0 : 0) + ' per 1,000 incidents' : pct(s.alpha, 1) + ' of threats';

function controlsHTML() {
  const s = state;
  return `<div class="controls" role="group" aria-label="Guarantee settings">
    <div class="ctl"><span class="l">Bound on threats closed</span><div class="seg">${['leak', 'miss'].map((r) => `<button data-risk="${r}" aria-pressed="${s.risk === r}" title="${RISK_LABEL[r]}">${r === 'leak' ? 'Per incident' : 'Share of threats'}</button>`).join('')}</div></div>
    <div class="divider-v"></div>
    <div class="ctl"><label for="alpha">At most</label><select class="in" id="alpha">${ALPHAS[s.risk].map((a) => `<option value="${a}" ${a === s.alpha ? 'selected' : ''}>${s.risk === 'leak' ? (1000 * a) + ' per 1,000 incidents' : pct(a, 1) + ' of threats'}</option>`).join('')}</select></div>
    <div class="ctl"><span class="l">Confidence</span><div class="seg">${[90, 95, 99].map((c) => `<button data-conf="${c}" aria-pressed="${s.conf === c}">${c}%</button>`).join('')}</div></div>
    <div class="divider-v"></div>
    <div class="ctl"><label for="win">Daily window</label><select class="in" id="win">${[3, 5, 7].map((w) => `<option value="${w}" ${w === s.window ? 'selected' : ''}>${w} days</option>`).join('')}</select></div>
  </div>`;
}
function bindControls() {
  for (const b of document.querySelectorAll('[data-risk]')) b.onclick = () => set({ risk: b.dataset.risk, alpha: ALPHAS[b.dataset.risk][2] });
  for (const b of document.querySelectorAll('[data-conf]')) b.onclick = () => set({ conf: +b.dataset.conf });
  $('alpha').onchange = (e) => set({ alpha: +e.target.value });
  $('win').onchange = (e) => set({ window: +e.target.value });
}

// ---------- render ----------
function render() {
  const s = state;
  const cur = { overview: 'navAssure', customer: 'navAssure', policies: 'navPolicies', method: 'navMethod' }[s.view];
  for (const id of ['navAssure', 'navPolicies', 'navMethod']) { if (id === cur) $(id).setAttribute('aria-current', 'page'); else $(id).removeAttribute('aria-current'); }
  $('polCount').style.display = policies.length ? '' : 'none';
  $('polCount').textContent = policies.length;
  const crumbs = { overview: '<b>Verdict assurance</b>', customer: `<a href="#overview" id="crumbBack">Verdict assurance</a> / <b>Org ${esc(s.org)}</b>`, policies: '<b>Routing policies</b>', method: '<b>Method</b>' };
  $('crumbs').innerHTML = crumbs[s.view];
  $('crumbBack')?.addEventListener('click', (e) => { e.preventDefault(); set({ view: 'overview', inc: '', filter: 'all' }, true); });
  const t0 = performance.now();
  try {
    if (s.view === 'overview') renderOverview();
    else if (s.view === 'customer') renderCustomer();
    else if (s.view === 'policies') renderPolicies();
    else renderMethod();
  } catch (e) { console.error(e); $('view').innerHTML = `<div class="card state"><h3>Something went wrong computing this view.</h3><p>${esc(e.message)}</p><button class="btn" onclick="location.reload()">Reload</button></div>`; }
  $('dataNote').textContent = `${fmt(DATA.inc.length)} incidents · computed in ${Math.max(1, Math.round(performance.now() - t0))} ms`;
}

function renderOverview() {
  const s = state;
  const rows = rollingOf(s, 'customer'), plug = rollingOf(s, 'plugin'), fleet = rollingOf(s, 'fleet');
  const S = C.summarize(rows, s.alpha), P = C.summarize(plug, s.alpha), F = C.summarize(fleet, s.alpha);
  const within = rows.filter((r) => r.ok).length, above = rows.filter((r) => !r.ok && !r.sigBreach).length;
  const fewer = P.missed - S.missed;
  const sel = state._row ?? -1;
  const body = rows.map((r, i) => {
    const pr = plug.find((x) => x.org === r.org);
    const ub = C.cpUpper(r.closedTP, s.risk === 'leak' ? r.n : r.tp, 0.95);
    return `<tr class="click${i === sel ? ' sel' : ''}" data-org="${r.org}" tabindex="0" aria-label="Open Org ${r.org}">
      <td style="font-weight:700">Org ${esc(r.org)}</td><td class="num">${fmt(r.n)}</td><td class="num">${fmt(r.tp)}</td>
      <td><div style="display:flex;align-items:center;gap:8px"><div class="bar" style="flex:1"><i style="width:${(100 * r.autoShare).toFixed(1)}%"></i></div><span style="font-weight:700;min-width:46px;text-align:right">${pct(r.autoShare)}</span></div></td>
      <td class="num">${r.closedTP}</td><td class="num" style="white-space:nowrap">${rateNum(s, r.risk)}<span style="font-size:11px;color:var(--text-tertiary);margin-left:6px">≤ ${rateNum(s, ub)}</span></td>
      <td class="num" style="color:${pr.sigBreach ? '#c21d47' : 'inherit'}">${pr.closedTP}${pr.sigBreach ? ' · breach' : ''}</td>
      <td>${statusChip(r)}</td><td>${policies.some((p) => p.org === r.org && p.active) ? '<span class="chip dark">Applied</span>' : '<span style="color:var(--text-tertiary)">Draft</span>'}</td></tr>`;
  }).join('');
  $('view').innerHTML = `
  <div class="page-head"><div><div class="eyebrow">Verdict</div><h1>Verdict assurance</h1><p class="sub">Each customer gets the threshold that takes the most work off experts while keeping real threats closed by the agent under the bound, certified on that customer's own recent cases.</p></div>
    <div style="display:flex;gap:8px"><button class="btn secondary" id="exp">${I.down}Export CSV</button><button class="btn" id="applyAll">Apply to all certified ${I.arrow}</button></div></div>
  ${controlsHTML()}
  <div class="grid4">
    <div class="card kpi"><div class="label">Off the expert queue</div><div class="value">${pct(S.autoShare)}</div><div class="note">${fmt(S.closed)} of ${fmt(S.n)} incidents closed by the agent, Jun 10 to 17</div></div>
    <div class="card kpi"><div class="label">Threats closed by agent</div><div class="value">${S.missed}<small>of ${fmt(S.tp)}</small></div><div class="note">${s.risk === 'leak' ? (1000 * S.leak).toFixed(2) + ' per 1,000 incidents' : pct(S.miss, 2) + ' of threats'} · bound ${alphaFmt(s)}</div></div>
    <div class="card kpi"><div class="label">Customers within bound</div><div class="value">${within}<small>/ ${S.customers}</small></div><div class="note">${S.sigBreaches ? `<span class="delta bad">${S.sigBreaches} significant breach${S.sigBreaches > 1 ? 'es' : ''}</span>` : '<span class="delta good">No significant breach</span>'}${above ? ` · ${above} above by chance` : ''} · uncorrected rule: <b>${P.sigBreaches} breaches</b></div></div>
    <div class="card kpi"><div class="label">vs. uncorrected threshold</div><div class="value">${fewer >= 0 ? fewer : -fewer}<small>${fewer >= 0 ? 'fewer missed' : 'more missed'}</small></div><div class="note">${P.missed} threats closed at ${pct(P.autoShare)} auto. One fleet-wide threshold: ${F.missed} at ${pct(F.autoShare)}, ${F.sigBreaches} breach${F.sigBreaches === 1 ? '' : 'es'}</div></div>
  </div>
  <div class="card" style="margin-bottom:16px"><div class="card-h"><h2>Customers</h2><span class="meta">Replay of Jun 10 to 17, 2024 · recalibrated daily on the previous ${s.window} days · click a customer or press <kbd>j</kbd> <kbd>k</kbd> <kbd>Enter</kbd></span></div>
      <table><thead><tr><th>Customer</th><th class="num">Incidents</th><th class="num">Threats</th><th style="width:220px">Closed by agent</th><th class="num">Threats closed</th><th class="num" title="Realized rate, and its 95% upper confidence bound">${s.risk === 'leak' ? 'Per 1,000 · 95% upper' : 'Miss rate · 95% upper'}</th><th class="num">Uncorrected rule</th><th>Status</th><th>Policy</th></tr></thead><tbody>${body}</tbody></table></div>
  <div class="card"><div class="card-h"><h2>Realized rate by customer</h2><span class="legend"><span><i style="background:#2a9d8f"></i>Certified threshold</span><span><i style="background:#ff3263"></i>Uncorrected threshold</span><span><i style="background:none;border-top:1.5px dashed #0d0c0c;border-radius:0;height:0;width:14px"></i>Bound</span></span></div>
      <div class="card-b" style="position:relative"><svg class="chart" id="dot" role="img" aria-label="Realized rate per customer, certified versus uncorrected thresholds"></svg>
      <p style="margin:8px 0 0;font-size:12px;color:var(--text-tertiary)">Uncorrected thresholds set the rate exactly to the bound on recent cases, so they overshoot on new ones. Certified thresholds leave a margin sized by how much evidence each customer has. ${s.risk === 'leak' ? 'Rates are real threats closed by the agent per 1,000 incidents.' : 'Rates are the share of real threats closed by the agent.'}</p></div></div>`;
  bindControls();
  drawDots(rows, plug);
  for (const tr of document.querySelectorAll('tr[data-org]')) {
    const go = () => set({ view: 'customer', org: tr.dataset.org, inc: '', filter: 'all' }, true);
    tr.onclick = go; tr.onkeydown = (e) => { if (e.key === 'Enter') go(); };
  }
  $('exp').onclick = () => exportOverview();
  $('applyAll').onclick = () => { let n = 0; for (const r of rows) if (r.lambda > 0) { applyPolicy(r.org, r.lambda, false); n++; } toast(`Applied ${n} certified policies`); render(); };
}

function drawDots(rows, plug) {
  const svg = $('dot'); const W = svg.clientWidth || 900, rowH = 22, H = rows.length * rowH + 34, ml = 64, mr = 16;
  const vals = rows.flatMap((r) => [r.risk, plug.find((p) => p.org === r.org).risk, state.alpha]);
  const xmax = Math.max(...vals) * 1.15 || 0.01;
  const x = (v) => ml + v / xmax * (W - ml - mr);
  let g = '';
  for (let t = 0; t <= 6; t++) { const v = xmax * t / 6; g += `<line x1="${x(v)}" x2="${x(v)}" y1="8" y2="${H - 22}" stroke="#efeee3"/><text x="${x(v)}" y="${H - 6}" text-anchor="middle">${rateNum(state, v)}</text>`; }
  g += `<line x1="${x(state.alpha)}" x2="${x(state.alpha)}" y1="4" y2="${H - 22}" stroke="#0d0c0c" stroke-dasharray="4 3"/>`;
  rows.forEach((r, i) => {
    const y = 16 + i * rowH, p = plug.find((q) => q.org === r.org);
    g += `<text x="${ml - 10}" y="${y + 4}" text-anchor="end" style="font-weight:600;fill:#333130">Org ${r.org}</text><line x1="${x(Math.min(r.risk, p.risk))}" x2="${x(Math.max(r.risk, p.risk))}" y1="${y}" y2="${y}" stroke="#e0e0d5" stroke-width="2"/>`;
    g += `<circle cx="${x(p.risk)}" cy="${y}" r="5" fill="#ff3263" data-tip="Org ${r.org} uncorrected: ${riskFmt(state, p.risk)} (${p.closedTP} missed)"/><circle cx="${x(r.risk)}" cy="${y}" r="5" fill="#2a9d8f" stroke="#fff" stroke-width="1.5" data-tip="Org ${r.org} certified: ${riskFmt(state, r.risk)} (${r.closedTP} missed)"/>`;
  });
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`); svg.style.height = H + 'px'; svg.innerHTML = g;
  bindTips(svg);
}
function bindTips(svg) {
  const tip = $('tip');
  for (const c of svg.querySelectorAll('[data-tip]')) {
    c.addEventListener('mouseenter', () => { const r = c.getBoundingClientRect(); tip.textContent = c.dataset.tip; tip.style.display = 'block'; tip.style.left = (r.left + r.width / 2 + scrollX) + 'px'; tip.style.top = (r.top + scrollY) + 'px'; });
    c.addEventListener('mouseleave', () => { tip.style.display = 'none'; });
  }
}

// ---------- customer drill-down ----------
function renderCustomer() {
  const s = state, org = s.org;
  const rows = rollingOf(s, 'customer'), r = rows.find((x) => x.org === org), pr = rollingOf(s, 'plugin').find((x) => x.org === org);
  const lam = dailyLambdas(s), lamP = dailyLambdas(s, 'plugin');
  const cal = calWindow(s, LAST + 1).filter((x) => x.org === org); // window feeding tomorrow's policy
  const cert = C.certify(cal, { risk: s.risk, alpha: s.alpha, delta: 1 - s.conf / 100 });
  const plg = C.plugIn(cal, { risk: s.risk, alpha: s.alpha });
  const incs = DATA.inc.filter((x) => x.org === org && x.minute >= FIRST * 1440 && x.minute < (LAST + 1) * 1440)
    .map((x) => { const d = Math.floor(x.minute / 1440); const l = lam.get(d).get(org); return { ...x, day: d, lam: l, auto: x.score < l, autoP: x.score < lamP.get(d).get(org) }; });
  const filt = { all: () => true, auto: (x) => x.auto, esc: (x) => !x.auto, missed: (x) => x.auto && x.tp, saved: (x) => !x.auto && x.autoP && x.tp }[s.filter] || (() => true);
  const list = incs.filter(filt).sort((a, b) => b.minute - a.minute);
  const shown = list.slice(0, 60);
  const selInc = incs.find((x) => String(x.i) === String(s.inc)) || shown[0];
  const applied = policies.find((p) => p.org === org && p.active);
  const daily = [];
  for (let d = FIRST; d <= LAST; d++) { const xs = incs.filter((x) => x.day === d); daily.push({ d, n: xs.length, lam: lam.get(d).get(org), auto: xs.filter((x) => x.auto).length, missed: xs.filter((x) => x.auto && x.tp).length }); }
  const counts = { all: incs.length, auto: incs.filter((x) => x.auto).length, esc: incs.filter((x) => !x.auto).length, missed: incs.filter((x) => x.auto && x.tp).length, saved: incs.filter((x) => !x.auto && x.autoP && x.tp).length };
  $('view').innerHTML = `
  <div class="page-head"><div><div class="eyebrow">Customer · GUIDE organisation ${esc(org)}</div><h1>Org ${esc(org)} ${statusChip(r)}</h1><p class="sub">${fmt(r.n)} incidents and ${fmt(r.tp)} confirmed threats from Jun 10 to 17. Tomorrow's certified threshold comes from the last ${s.window} days: ${cal.length} cases, ${cal.filter((x) => x.tp).length} threats.</p></div>
    <div style="display:flex;gap:8px"><button class="btn secondary" id="expInc">${I.down}Export incidents</button><button class="btn ${applied && Math.abs(applied.lambda - cert.lambda) < 1e-12 ? 'secondary' : ''}" id="apply" ${cert.lambda > 0 ? '' : 'disabled'}>${applied && Math.abs(applied.lambda - cert.lambda) < 1e-12 ? 'Policy applied' : 'Apply certified policy'} ${I.arrow}</button></div></div>
  ${controlsHTML()}
  <div class="grid4">
    <div class="card kpi"><div class="label">Off the expert queue</div><div class="value">${pct(r.autoShare)}</div><div class="note">${fmt(r.closed)} closed by the agent</div></div>
    <div class="card kpi"><div class="label">Threats closed by agent</div><div class="value">${r.closedTP}<small>of ${fmt(r.tp)}</small></div><div class="note">${riskFmt(s, r.risk)} realized · bound ${alphaFmt(s)}</div></div>
    <div class="card kpi"><div class="label">Certified threshold</div><div class="value">${cert.lambda ? cert.lambda.toFixed(4) : 'None'}</div><div class="note">${cert.lambda ? `Close when AI threat confidence &lt; ${cert.lambda.toFixed(4)}` : 'Not enough cases to certify any auto-close'}</div></div>
    <div class="card kpi"><div class="label">Uncorrected would miss</div><div class="value">${pr.closedTP}<small>threats</small></div><div class="note">${pr.sigBreach ? '<span class="delta bad">Breaches the bound</span>' : 'Within the bound here'} · ${pct(pr.autoShare)} auto</div></div>
  </div>
  <div class="two-eq">
    <div class="card"><div class="card-h"><h2>AI threat confidence, last ${s.window} days</h2><span class="legend"><span><i style="background:#ff3263"></i>Threat</span><span><i style="background:#c9c7bb"></i>Benign / false positive</span></span></div><div class="card-b"><svg class="chart" id="hist" role="img" aria-label="Score histogram with thresholds"></svg></div></div>
    <div class="card"><div class="card-h"><h2>Certification walk</h2><span class="meta">exact binomial test at each threshold, stop at first failure</span></div><div class="card-b"><svg class="chart" id="walk" role="img" aria-label="Risk and p-value as the threshold rises"></svg></div></div>
  </div>
  <div class="two">
    <div class="card"><div class="card-h"><h2>Incidents</h2><div class="seg" role="group" aria-label="Filter incidents">${[['all', 'All'], ['auto', 'Closed by agent'], ['esc', 'Escalated'], ['missed', 'Missed threats'], ['saved', 'Caught vs uncorrected']].map(([k, l]) => `<button data-f="${k}" aria-pressed="${s.filter === k}">${l} <span style="color:var(--text-tertiary)">${counts[k]}</span></button>`).join('')}</div></div>
      ${shown.length ? `<table><thead><tr><th>Incident</th><th>Created (UTC)</th><th>Category</th><th class="num">AI confidence</th><th>Routing</th><th>SOC grade</th></tr></thead><tbody>${shown.map((x) => `<tr class="click${selInc && x.i === selInc.i ? ' sel' : ''}" data-inc="${x.i}" tabindex="0"><td style="font-weight:700">#${x.iid}</td><td style="white-space:nowrap">${timeLabel(x.minute).replace(' UTC', '')}</td><td style="white-space:nowrap">${esc(x.category.replace(/([a-z])([A-Z])/g, '$1 $2'))}</td><td class="num">${x.score.toFixed(4)}</td><td>${x.auto ? `<span class="route auto"><span class="dot">${I.check}</span>Closed by agent</span>` : `<span class="route esc"><span class="dot">${I.up}</span>Escalated</span>`}</td><td>${x.grade === 'T' ? '<span class="chip breach">True positive</span>' : x.grade === 'B' ? '<span class="chip gray">Benign positive</span>' : '<span class="chip gray">False positive</span>'}</td></tr>`).join('')}</tbody></table>${list.length > 60 ? `<div style="padding:10px 18px;color:var(--text-tertiary);font-size:12px">Showing the 60 most recent of ${list.length}. Export for all.</div>` : ''}`
      : `<div class="state"><h3>No incidents match this filter.</h3><p>${s.filter === 'missed' ? 'The agent closed no real threats for this customer in the replay.' : 'Try another filter.'}</p></div>`}
    </div>
    <div>${selInc ? incidentCard(selInc) : ''}
      <div class="card" style="margin-top:16px"><div class="card-h"><h2>Daily thresholds</h2><span class="meta">recalibrated each morning</span></div>
      <table><thead><tr><th>Day</th><th class="num">Incidents</th><th class="num">Threshold</th><th class="num">Closed</th><th class="num">Missed</th></tr></thead><tbody>${daily.map((d) => `<tr><td>${dayLabel(d.d)}</td><td class="num">${d.n}</td><td class="num">${d.lam ? d.lam.toFixed(4) : '–'}</td><td class="num">${d.auto}</td><td class="num">${d.missed}</td></tr>`).join('')}</tbody></table></div>
    </div>
  </div>`;
  bindControls();
  drawHist(cal, cert.lambda, plg.lambda);
  drawWalk(cert, s);
  for (const b of document.querySelectorAll('[data-f]')) b.onclick = () => set({ filter: b.dataset.f, inc: '' });
  for (const tr of document.querySelectorAll('tr[data-inc]')) { const go = () => set({ inc: tr.dataset.inc }); tr.onclick = go; tr.onkeydown = (e) => { if (e.key === 'Enter') go(); }; }
  $('apply').onclick = () => { if (applyPolicy(org, cert.lambda)) render(); };
  $('expInc').onclick = () => download(`org-${org}-incidents.csv`, C.toCSV(incs.map((x) => ({ incident: x.iid, created_utc: new Date(DAY0 + x.minute * 60000).toISOString(), category: x.category, ai_confidence: x.score, threshold: x.lam, routing: x.auto ? 'closed_by_agent' : 'escalated', soc_grade: { T: 'TruePositive', B: 'BenignPositive', F: 'FalsePositive' }[x.grade] }))));
}

function incidentCard(x) {
  const findings = [];
  findings.push([x.verdict === 'Malicious' || x.verdict === 'Suspicious' ? 'up' : x.verdict === 'NoThreatsFound' ? 'dn' : 'eq', `Detection verdict on the evidence: <u>${esc(x.verdict === 'None' ? 'none recorded' : x.verdict)}</u>`]);
  findings.push(['eq', `${x.alerts} alert${x.alerts === 1 ? '' : 's'} and ${x.evidence} evidence row${x.evidence === 1 ? '' : 's'}, mostly <u>${esc(x.entities.split(',').join(', '))}</u>`]);
  if (x.mitre.length) findings.push(['up', `MITRE ATT&amp;CK: ${x.mitre.map((m) => `<u>${esc(m)}</u>`).join(', ')}`]);
  findings.push([x.score >= x.lam ? 'up' : 'dn', `AI threat confidence <u>${x.score.toFixed(4)}</u> ${x.score >= x.lam ? 'is at or above' : 'is below'} the certified threshold ${x.lam ? x.lam.toFixed(4) : '(none: everything escalates)'}`]);
  findings.push([x.tp ? 'up' : 'dn', `Customer SOC graded it <u>${{ T: 'TruePositive', B: 'BenignPositive', F: 'FalsePositive' }[x.grade]}</u>`]);
  const sev = x.score > 0.8 ? 'High' : x.score > 0.3 ? 'Medium' : 'Low';
  return `<div class="card"><div class="card-b">
    <div class="verdict-row">${x.score >= 0.5 ? `<span class="chip sus">${I.shield}Suspicious</span>` : '<span class="chip gray">Benign</span>'}${x.auto ? `<span class="route auto"><span class="dot">${I.check}</span>Closed by agent</span>` : `<span class="route esc"><span class="dot">${I.up}</span>Escalated</span>`}</div>
    <div style="display:flex;gap:16px;align-items:flex-start"><span class="sev" style="margin-top:8px">${I.chev}${sev}</span><div class="verdict-title">${esc(x.category.replace(/([a-z])([A-Z])/g, '$1 $2'))} incident #${x.iid}</div></div>
    <div style="color:var(--text-tertiary);font-size:12px;margin:2px 0 14px">Org ${esc(x.org)} · ${timeLabel(x.minute)} · alert title ${esc(x.title)} (anonymised in GUIDE)</div>
    <div class="findings"><h3>Findings</h3><ul>${findings.map(([k, t]) => `<li>${k === 'up' ? I.tri_up : k === 'dn' ? I.tri_dn : I.eq}<span>${t}</span></li>`).join('')}</ul></div>
    ${x.auto && x.tp ? '<p style="margin:12px 0 0;font-weight:600;color:#c21d47">A real threat closed without an expert. It counts against this customer\'s bound.</p>' : ''}
  </div></div>`;
}

function drawHist(cal, lam, lamP) {
  const svg = $('hist'); const W = svg.clientWidth || 520, H = 210, ml = 34, mr = 10, mt = 10, mb = 26;
  const B = 40, lo = -10, hi = 6; // logit bins
  const logit = (p) => Math.log(Math.max(1e-6, p) / Math.max(1e-6, 1 - p));
  const tp = new Array(B).fill(0), bn = new Array(B).fill(0);
  for (const x of cal) { const b = Math.max(0, Math.min(B - 1, Math.floor((logit(x.score) - lo) / (hi - lo) * B))); (x.tp ? tp : bn)[b]++; }
  const ymax = Math.log10(Math.max(2, ...tp, ...bn) + 1);
  const bw = (W - ml - mr) / B, y = (c) => mt + (1 - Math.log10(c + 1) / ymax) * (H - mt - mb);
  let g = '';
  for (let e = 0; e <= Math.ceil(ymax); e++) { const yy = y(10 ** e - 1); if (yy < mt - 1) continue; g += `<line x1="${ml}" x2="${W - mr}" y1="${yy}" y2="${yy}" stroke="#efeee3"/><text x="${ml - 6}" y="${yy + 4}" text-anchor="end">${10 ** e}</text>`; }
  for (let b = 0; b < B; b++) {
    const x0 = ml + b * bw;
    if (bn[b]) g += `<rect x="${x0 + 1}" y="${y(bn[b])}" width="${bw / 2 - 1}" height="${H - mb - y(bn[b])}" fill="#c9c7bb" rx="1.5"/>`;
    if (tp[b]) g += `<rect x="${x0 + bw / 2}" y="${y(tp[b])}" width="${bw / 2 - 1}" height="${H - mb - y(tp[b])}" fill="#ff3263" rx="1.5"/>`;
  }
  const xs = (p) => ml + (logit(p) - lo) / (hi - lo) * (W - ml - mr);
  for (const p of [0.001, 0.01, 0.1, 0.5, 0.9, 0.99]) g += `<text x="${xs(p)}" y="${H - 8}" text-anchor="middle">${p}</text>`;
  if (lamP > 0) g += `<line x1="${xs(lamP)}" x2="${xs(lamP)}" y1="${mt}" y2="${H - mb}" stroke="#ff3263" stroke-dasharray="4 3" stroke-width="1.5"/><text x="${xs(lamP) + 4}" y="${mt + 10}" style="fill:#c21d47;font-weight:700" text-anchor="start">uncorrected</text>`;
  if (lam > 0) g += `<line x1="${xs(lam)}" x2="${xs(lam)}" y1="${mt}" y2="${H - mb}" stroke="#2a9d8f" stroke-width="2"/><text x="${xs(lam) - 4}" y="${mt + 10}" style="fill:#1d7f74;font-weight:700" text-anchor="end">certified</text>`;
  g += `<line x1="${ml}" x2="${W - mr}" y1="${H - mb}" y2="${H - mb}" stroke="#e0e0d5"/>`;
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`); svg.style.height = H + 'px'; svg.innerHTML = g;
}

function drawWalk(cert, s) {
  const svg = $('walk'); const W = svg.clientWidth || 520, H = 210, ml = 40, mr = 40, mt = 10, mb = 26;
  const sw = cert.sweep; const last = Math.min(sw.length - 1, Math.max(cert.index + 60, 120));
  const xs = (g) => ml + g / last * (W - ml - mr);
  const risks = sw.slice(0, last + 1).map((c) => C.riskValue(c, s.risk));
  const rmax = Math.max(s.alpha * 2.2, ...risks.slice(0, cert.index + 40).filter(Number.isFinite)) || s.alpha * 2;
  const yr = (v) => mt + (1 - Math.min(v, rmax) / rmax) * (H - mt - mb);
  const yp = (p) => mt + (1 - p) * (H - mt - mb);
  let g = `<line x1="${ml}" x2="${W - mr}" y1="${yr(s.alpha)}" y2="${yr(s.alpha)}" stroke="#0d0c0c" stroke-dasharray="4 3"/><text x="${ml - 6}" y="${yr(s.alpha) + 4}" text-anchor="end">${rateNum(s, s.alpha)}</text>`;
  g += `<text x="${ml - 6}" y="${yr(0) + 4}" text-anchor="end">0</text><text x="${W - mr + 4}" y="${yp(1) + 8}">p=1</text><text x="${W - mr + 4}" y="${yp(0) + 4}">0</text>`;
  g += `<line x1="${ml}" x2="${W - mr}" y1="${yp(1 - s.conf / 100)}" y2="${yp(1 - s.conf / 100)}" stroke="#ff3263" stroke-opacity=".35"/><text x="${W - mr + 4}" y="${yp(1 - s.conf / 100) + 4}">δ</text>`;
  let pr = '', pp = '';
  for (let g2 = 0; g2 <= last; g2++) { pr += (g2 ? 'L' : 'M') + xs(g2).toFixed(1) + ' ' + yr(risks[g2]).toFixed(1); }
  for (let g2 = 0; g2 < cert.pvalues.length && g2 <= last; g2++) pp += (g2 ? 'L' : 'M') + xs(g2).toFixed(1) + ' ' + yp(cert.pvalues[g2]).toFixed(1);
  g += `<path d="${pr}" fill="none" stroke="#2a9d8f" stroke-width="2"/><path d="${pp}" fill="none" stroke="#ff3263" stroke-width="1.5"/>`;
  if (cert.index >= 0) g += `<line x1="${xs(cert.index)}" x2="${xs(cert.index)}" y1="${mt}" y2="${H - mb}" stroke="#0d0c0c" stroke-width="1"/><text x="${xs(cert.index) + 4}" y="${H - mb - 6}" style="fill:#0d0c0c;font-weight:700">stop · ${cert.lambda.toFixed(4)}</text>`;
  g += `<text x="${ml}" y="${H - 8}">stricter</text><text x="${W - mr}" y="${H - 8}" text-anchor="end">more auto-close</text>`;
  g += `<text x="${ml}" y="${mt + 2}" style="fill:#1d7f74;font-weight:700">empirical rate</text><text x="${ml + 100}" y="${mt + 2}" style="fill:#c21d47;font-weight:700">p-value</text>`;
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`); svg.style.height = H + 'px'; svg.innerHTML = g;
}

// ---------- policies (persistent action) ----------
function savePolicies() { try { localStorage.setItem(STORE, JSON.stringify(policies)); } catch { toast('Could not save in this browser'); } }
function loadPolicies() { try { const v = JSON.parse(localStorage.getItem(STORE) || '[]'); return Array.isArray(v) ? v : []; } catch { return []; } }
function applyPolicy(org, lambda, notify = true) {
  if (!(lambda > 0)) { toast('Nothing certified for this customer'); return false; }
  const s = state;
  const prev = policies.filter((p) => p.org === org);
  for (const p of prev) p.active = false;
  policies.push({ id: Math.random().toString(36).slice(2, 9), org, version: prev.length + 1, lambda, risk: s.risk, alpha: s.alpha, confidence: s.conf, window: s.window, applied: new Date().toISOString(), active: true });
  savePolicies();
  if (notify) toast(`Org ${org}: policy v${prev.length + 1} applied (close below ${lambda.toFixed(4)})`);
  return true;
}
function renderPolicies() {
  const act = policies.filter((p) => p.active).sort((a, b) => a.org.localeCompare(b.org, undefined, { numeric: true }));
  const log = [...policies].sort((a, b) => b.applied.localeCompare(a.applied));
  $('view').innerHTML = `
  <div class="page-head"><div><div class="eyebrow">Assurance</div><h1>Routing policies</h1><p class="sub">Thresholds you have applied. Each records the bound, confidence and calibration window it was certified under, so an auditor can re-run it.</p></div>
    <div style="display:flex;gap:8px"><button class="btn secondary" id="expJson" ${policies.length ? '' : 'disabled'}>${I.down}Export JSON</button><button class="btn secondary" id="clear" ${policies.length ? '' : 'disabled'}>Reset</button></div></div>
  <div class="two">
    <div class="card"><div class="card-h"><h2>Active</h2><span class="meta">${act.length} customer${act.length === 1 ? '' : 's'}</span></div>
      ${act.length ? `<table><thead><tr><th>Customer</th><th>Version</th><th class="num">Close below</th><th>Bound</th><th>Confidence</th><th>Window</th><th></th></tr></thead><tbody>${act.map((p) => `<tr><td style="font-weight:700">Org ${esc(p.org)}</td><td>v${p.version}</td><td class="num">${p.lambda.toFixed(4)}</td><td>${p.risk === 'leak' ? (1000 * p.alpha) + ' per 1,000 incidents' : pct(p.alpha, 1) + ' of threats'}</td><td>${p.confidence}%</td><td>${p.window} days</td><td style="text-align:right"><button class="linkbtn" data-open="${esc(p.org)}">Open</button> · <button class="linkbtn" data-revoke="${p.id}">Revoke</button></td></tr>`).join('')}</tbody></table>`
      : '<div class="state"><h3>No routing policies applied yet.</h3><p>Open a customer in Verdict assurance and apply its certified policy, or apply all certified policies from the overview.</p><a class="btn" href="#overview">Go to Verdict assurance ' + I.arrow + '</a></div>'}
    </div>
    <div class="card"><div class="card-h"><h2>Audit log</h2></div><div class="card-b">${log.length ? `<ul class="audit" style="list-style:none;margin:0;padding:0">${log.slice(0, 40).map((p) => `<li><b>Org ${esc(p.org)} v${p.version}</b> ${p.active ? 'applied' : 'superseded'} · close below ${p.lambda.toFixed(4)} · ${new Date(p.applied).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</li>`).join('')}</ul>` : '<p style="margin:0;color:var(--text-tertiary)">Nothing yet.</p>'}</div></div>
  </div>`;
  $('expJson').onclick = () => download('routing-policies.json', JSON.stringify({ exported: new Date().toISOString(), method: 'Learn-then-Test, fixed sequence, exact binomial', policies }, null, 2), 'application/json');
  $('clear').onclick = () => { policies = []; savePolicies(); toast('Policies reset'); render(); };
  for (const b of document.querySelectorAll('[data-revoke]')) b.onclick = () => { const p = policies.find((q) => q.id === b.dataset.revoke); p.active = false; savePolicies(); toast(`Org ${p.org}: policy revoked, all incidents escalate`); render(); };
  for (const b of document.querySelectorAll('[data-open]')) b.onclick = () => set({ view: 'customer', org: b.dataset.open, inc: '', filter: 'all' }, true);
}

function renderMethod() {
  const m = DATA.model;
  $('view').innerHTML = `
  <div class="page-head"><div><div class="eyebrow">Assurance</div><h1>Method</h1><p class="sub">How a threshold gets certified, what the data is, and what this does not claim.</p></div></div>
  <div class="two"><div class="card"><div class="card-b prose">
    <h3 style="margin-top:0">The question</h3><p>The agent investigates every incident and produces a threat confidence. Experts cost the most, so the agent should close what it can. The question for each customer is how much it can close while keeping real threats closed without an expert under a stated bound, and how sure we are of that.</p>
    <h3>Certifying a threshold</h3><p>On a fixed grid of thresholds λ, chosen before seeing any data, walk upward from the strictest. At each λ, test H<sub>0</sub>: risk(λ) &gt; bound with an exact binomial p-value, <code>P(Bin(n, bound) ≤ k)</code>, where <i>k</i> is the number of real threats below λ and <i>n</i> is the number of incidents (or of threats, for the share-of-threats bound). Stop at the first λ that is not rejected. This is Learn then Test (Angelopoulos, Bates, Candès, Jordan &amp; Lei, 2021) with fixed-sequence testing. If cases are exchangeable, then with probability at least the chosen confidence the certified λ keeps the true risk under the bound.</p>
    <h3>Per customer, recalibrated daily</h3><p>Customers differ enormously. In this replay their threat rates run from under 1% to 98%, so one fleet threshold over-closes for some and under-closes for others. Each customer is certified on its own last few days of cases and recalibrated every morning. A customer with too little history gets no auto-close until it has enough. That is a feature: the guarantee never borrows confidence it has not earned.</p>
    <h3>The data</h3><p>Microsoft GUIDE (Freitas et al., 2024) is the largest public set of real security incidents with customer SOC triage grades: true positive, benign positive, false positive. This demo uses 14 organisations from GUIDE's test file (${fmt(DATA.inc.length)} incidents). The AI confidence is a stand-in triage model I trained on GUIDE's separate train file: empirical-Bayes encodings of detector, organisation × detector, alert title and category, plus a logistic layer (test AUC ${m.test_auc_selected_orgs.toFixed(3)}). Daylight would plug in its own agent's verdict confidence.</p>
    <h3>What this does not claim</h3><p>GUIDE grades are customer labels and can be wrong. The guarantee needs the next day's cases to look like the last few days', and real attacks shift. That is why the replay checks breaches with an exact test and recalibrates daily. The stand-in model is not Daylight's agent, and its high AUC reflects GUIDE's repeated detectors per organisation.</p>
  </div></div>
  <div class="card"><div class="card-h"><h2>Replay result at the defaults</h2><span class="meta">Jun 10 to 17, 2024</span></div>
    <table><thead><tr><th>Threshold rule</th><th class="num">Off queue</th><th class="num">Threats missed</th><th class="num">Breaches</th></tr></thead><tbody>
    ${RESULTS ? ['customer', 'plugin', 'fleet'].map((k) => { const v = RESULTS.modes[k].summary; return `<tr${k === 'customer' ? ' class="sel"' : ''}><td style="font-weight:700">${{ customer: 'Certified per customer', plugin: 'Uncorrected per customer', fleet: 'Certified, one fleet threshold' }[k]}</td><td class="num">${pct(v.autoShare)}</td><td class="num">${v.missed}</td><td class="num">${v.sigBreaches} / ${v.customers}</td></tr>`; }).join('') : ''}</tbody></table>
    <div class="card-b" style="font-size:12px;color:var(--text-tertiary)">Bound: 5 real threats closed per 1,000 incidents, 95% confidence, 7-day window. A breach is a customer whose realized rate is significantly above the bound (exact one-sided test, p &lt; 0.05).</div></div></div>`;
}

function exportOverview() {
  const s = state;
  download('verdict-assurance.csv', C.toCSV(rollingOf(s, 'customer').map((r) => ({ customer: 'Org ' + r.org, incidents: r.n, threats: r.tp, closed_by_agent: r.closed, auto_share: r.autoShare.toFixed(4), threats_closed: r.closedTP, realized_risk: r.risk.toFixed(5), bound: s.alpha, confidence: s.conf / 100, latest_threshold: r.lambda, significant_breach: r.sigBreach }))));
}

// ---------- keyboard ----------
let gPending = false;
function bindKeys() {
  addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { if ($('help').classList.contains('on')) { $('help').classList.remove('on'); return; } if (state.view === 'customer') set({ view: 'overview', inc: '', filter: 'all' }, true); return; }
    if (['INPUT', 'SELECT', 'TEXTAREA'].includes(e.target.tagName) || e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === '?') { $('help').classList.toggle('on'); return; }
    if (gPending) { gPending = false; if (e.key === 'o') set({ view: 'overview' }, true); if (e.key === 'p') set({ view: 'policies' }, true); return; }
    if (e.key === 'g') { gPending = true; setTimeout(() => (gPending = false), 900); return; }
    if (e.key === 'j' || e.key === 'k') {
      const rows = [...document.querySelectorAll(state.view === 'customer' ? 'tr[data-inc]' : 'tr[data-org]')];
      if (!rows.length) return;
      let i = rows.findIndex((r) => r.classList.contains('sel') || r === document.activeElement);
      i = Math.max(0, Math.min(rows.length - 1, i + (e.key === 'j' ? 1 : -1)));
      if (state.view === 'customer') set({ inc: rows[i].dataset.inc }); else { for (const r of rows) r.classList.remove('sel'); rows[i].classList.add('sel'); rows[i].focus(); state._row = i; }
      return;
    }
    if (e.key === 'Enter' && state.view === 'overview') { const r = document.querySelector('tr[data-org].sel'); if (r) r.click(); }
    if (e.key === 'a' && state.view === 'customer') $('apply')?.click();
    if (e.key === 'e') { if (state.view === 'customer') $('expInc')?.click(); else if (state.view === 'overview') exportOverview(); else $('expJson')?.click(); }
  });
}

// ---------- boot ----------
async function boot() {
  $('view').innerHTML = `<div class="skeleton" style="height:64px;margin-bottom:16px"></div><div class="grid4">${'<div class="skeleton" style="height:104px"></div>'.repeat(4)}</div><div class="skeleton" style="height:420px"></div>`;
  try {
    const [inc, model, results] = await Promise.all([fetch('data/incidents.json').then((r) => { if (!r.ok) throw new Error('data/incidents.json ' + r.status); return r.json(); }), fetch('data/model.json').then((r) => r.json()), fetch('data/results.json').then((r) => r.json()).catch(() => null)]);
    const u = C.unpack(inc);
    DATA = { meta: u.meta, inc: u.incidents.filter((x) => x.minute >= 0), model };
    RESULTS = results;
  } catch (e) {
    $('view').innerHTML = `<div class="card state"><h3>Couldn't load the incident replay.</h3><p>${esc(e.message)}</p><button class="btn" onclick="location.reload()">Retry</button></div>`;
    return;
  }
  policies = loadPolicies();
  for (const a of document.querySelectorAll('[data-stub]')) a.onclick = (e) => { e.preventDefault(); toast(a.dataset.stub + ' is outside this concept demo'); };
  $('navAssure').onclick = (e) => { e.preventDefault(); set({ view: 'overview', inc: '', filter: 'all' }, true); };
  $('navPolicies').onclick = (e) => { e.preventDefault(); set({ view: 'policies' }, true); };
  $('navMethod').onclick = (e) => { e.preventDefault(); set({ view: 'method' }, true); };
  $('helpBtn').onclick = () => $('help').classList.add('on');
  $('help').onclick = (e) => { if (e.target.id === 'help') $('help').classList.remove('on'); };
  bindKeys();
  state = readHash();
  addEventListener('popstate', () => { state = readHash(); render(); });
  addEventListener('hashchange', () => { state = readHash(); render(); });
  let rt; addEventListener('resize', () => { clearTimeout(rt); rt = setTimeout(render, 150); });
  render();
  document.documentElement.dataset.ready = '1';
}
boot();
