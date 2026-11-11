#!/usr/bin/env python3
"""Prepare the public Microsoft GUIDE dataset for the escalation-guarantee demo (stdlib only).

GUIDE (Freitas et al., Microsoft Security Research, 2024): 13M evidence rows across ~1M incidents
from 6,100+ organisations, each incident labelled by the customer SOC as TruePositive,
BenignPositive or FalsePositive.

Steps (deterministic):
 1. Stream GUIDE_Train.csv and GUIDE_Test.csv out of GUIDE.zip and aggregate evidence rows to incidents.
 2. Fit a stand-in triage model on the TRAIN file only: empirical-Bayes target encodings
    (detector, org x detector, alert title, category, org) learned on train half A, logistic
    regression fitted on train half B (SGD, fixed seed). It outputs P(true positive).
    This stands in for the investigation agent's verdict confidence.
 3. Score every TEST-file incident for the selected organisations and write a compact columnar
    data/incidents.json plus data/model.json (weights, train/test AUC).

Usage: python3 scripts/prepare_guide.py /path/to/GUIDE.zip data
"""
import csv, io, json, math, random, subprocess, sys, zipfile, collections
from datetime import datetime

ORGS = ['11', '24', '38', '62', '8', '55', '59', '49', '28', '65', '54', '18', '48', '6']
GRADES = {'TruePositive': 1, 'BenignPositive': 0, 'FalsePositive': 0}


def incidents(zip_path, member, keep_orgs=None):
    p = subprocess.Popen(['unzip', '-p', zip_path, member], stdout=subprocess.PIPE)
    r = csv.reader(io.TextIOWrapper(p.stdout, encoding='utf-8', newline=''))
    hdr = next(r); ix = {h: i for i, h in enumerate(hdr)}
    inc = {}
    for row in r:
        org = row[ix['OrgId']]
        if keep_orgs is not None and org not in keep_orgs:
            continue
        g = row[ix['IncidentGrade']]
        if g not in GRADES:
            continue
        k = (org, row[ix['IncidentId']])
        d = inc.get(k)
        ts = row[ix['Timestamp']]
        if d is None:
            d = inc[k] = {'org': org, 'iid': row[ix['IncidentId']], 'grade': g, 't0': ts, 'alerts': set(), 'n': 0,
                          'det': collections.Counter(), 'title': collections.Counter(), 'cat': collections.Counter(),
                          'mitre': set(), 'ent': collections.Counter(), 'susp': 0, 'incrim': 0, 'lv': collections.Counter()}
        d['n'] += 1
        if ts < d['t0']:
            d['t0'] = ts
        d['alerts'].add(row[ix['AlertId']])
        d['det'][row[ix['DetectorId']]] += 1
        d['title'][row[ix['AlertTitle']]] += 1
        d['cat'][row[ix['Category']]] += 1
        for m in row[ix['MitreTechniques']].split(';'):
            if m:
                d['mitre'].add(m)
        d['ent'][row[ix['EntityType']]] += 1
        s = row[ix['SuspicionLevel']]
        d['susp'] += s == 'Suspicious'
        d['incrim'] += s == 'Incriminated'
        d['lv'][row[ix['LastVerdict']] or 'None'] += 1
    p.wait()
    out = []
    for d in inc.values():
        d['detector'] = d['det'].most_common(1)[0][0]
        d['title1'] = d['title'].most_common(1)[0][0]
        d['category'] = d['cat'].most_common(1)[0][0]
        d['verdict'] = d['lv'].most_common(1)[0][0]
        d['y'] = GRADES[d['grade']]
        out.append(d)
    out.sort(key=lambda d: (d['org'], d['t0'], d['iid']))
    return out


class Encoder:
    """Empirical-Bayes smoothed TP rate per key: (tp + m*prior) / (n + m)."""
    def __init__(self, m=20):
        self.m = m; self.tp = collections.Counter(); self.n = collections.Counter(); self.prior = 0.0

    def fit(self, rows, keyf):
        for d in rows:
            k = keyf(d); self.n[k] += 1; self.tp[k] += d['y']
        self.prior = sum(d['y'] for d in rows) / max(1, len(rows))
        self.keyf = keyf
        return self

    def logit(self, d):
        k = self.keyf(d)
        p = (self.tp[k] + self.m * self.prior) / (self.n[k] + self.m)
        p = min(1 - 1e-4, max(1e-4, p))
        return math.log(p / (1 - p))


def features(d, enc):
    return [1.0] + [e.logit(d) for e in enc] + [
        math.log1p(len(d['alerts'])), math.log1p(d['n']), 1.0 if d['incrim'] else 0.0, 1.0 if d['susp'] else 0.0,
        1.0 if d['verdict'] == 'Malicious' else 0.0, 1.0 if d['verdict'] == 'Suspicious' else 0.0,
        1.0 if d['verdict'] == 'NoThreatsFound' else 0.0]


def sigmoid(z):
    return 1 / (1 + math.exp(-max(-30, min(30, z))))


def auc(scores, ys):
    pairs = sorted(zip(scores, ys))
    pos = sum(ys); neg = len(ys) - pos
    rank_sum = 0.0; i = 0
    while i < len(pairs):
        j = i
        while j < len(pairs) and pairs[j][0] == pairs[i][0]:
            j += 1
        avg = (i + j + 1) / 2
        rank_sum += avg * sum(y for _, y in pairs[i:j])
        i = j
    return (rank_sum - pos * (pos + 1) / 2) / (pos * neg)


def main(zip_path, out_dir):
    rnd = random.Random(2024)
    train = incidents(zip_path, 'GUIDE_Train.csv')
    print('train incidents', len(train))
    rnd.shuffle(train)
    A, B = train[: len(train) // 2], train[len(train) // 2:]
    enc = [Encoder().fit(A, lambda d: d['detector']), Encoder().fit(A, lambda d: (d['org'], d['detector'])),
           Encoder().fit(A, lambda d: d['title1']), Encoder().fit(A, lambda d: d['category']), Encoder().fit(A, lambda d: d['org'])]
    XB = [features(d, enc) for d in B]; yB = [d['y'] for d in B]
    w = [0.0] * len(XB[0]); lr = 0.05
    for epoch in range(4):
        order = list(range(len(XB))); rnd.shuffle(order)
        for i in order:
            x = XB[i]; p = sigmoid(sum(a * b for a, b in zip(w, x)))
            g = p - yB[i]
            for j in range(len(w)):
                w[j] -= lr * (g * x[j] + 1e-5 * w[j])
        lr *= 0.5
    train_auc = auc([sigmoid(sum(a * b for a, b in zip(w, x))) for x in XB[:200000]], yB[:200000])
    # refit encoders on the full train file for scoring test incidents (no test labels used)
    enc_full = [Encoder().fit(train, e.keyf) for e in enc]
    test = incidents(zip_path, 'GUIDE_Test.csv', set(ORGS))
    scores = [sigmoid(sum(a * b for a, b in zip(w, features(d, enc_full)))) for d in test]
    test_auc = auc(scores, [d['y'] for d in test])
    print('weights', [round(x, 3) for x in w], 'train AUC', round(train_auc, 4), 'test AUC', round(test_auc, 4))
    # compact columnar output
    t_base = datetime.fromisoformat('2024-06-01T00:00:00+00:00')
    titles, cats, techs = {}, {}, {}
    def code(tbl, v):
        if v not in tbl: tbl[v] = len(tbl)
        return tbl[v]
    cols = {k: [] for k in ['org', 'iid', 'grade', 'minute', 'score', 'alerts', 'evidence', 'title', 'category', 'mitre', 'verdict', 'ent']}
    for d, s in zip(test, scores):
        t = datetime.fromisoformat(d['t0'].replace('Z', '+00:00'))
        cols['org'].append(ORGS.index(d['org']))
        cols['iid'].append(int(d['iid']))
        cols['grade'].append({'TruePositive': 'T', 'BenignPositive': 'B', 'FalsePositive': 'F'}[d['grade']])
        cols['minute'].append(int((t - t_base).total_seconds() // 60))
        cols['score'].append(round(s, 5))
        cols['alerts'].append(len(d['alerts']))
        cols['evidence'].append(d['n'])
        cols['title'].append(code(titles, d['title1']))
        cols['category'].append(code(cats, d['category']))
        cols['mitre'].append([code(techs, m) for m in sorted(d['mitre'])[:4]])
        cols['verdict'].append(d['verdict'])
        cols['ent'].append(','.join(e for e, _ in d['ent'].most_common(3)))
    cols['grade'] = ''.join(cols['grade'])
    vmap = {}
    cols['verdict'] = [code(vmap, v) for v in cols['verdict']]
    emap = {}
    cols['ent'] = [code(emap, v) for v in cols['ent']]
    meta = {'source': 'Microsoft GUIDE (Freitas et al. 2024), GUIDE_Test.csv, incidents of 14 organisations',
            'orgs': ORGS, 'time_base': '2024-06-01T00:00:00Z', 'n': len(test),
            'titles': list(titles), 'categories': list(cats), 'mitre': list(techs), 'verdicts': list(vmap), 'entities': list(emap)}
    json.dump({'meta': meta, 'cols': cols}, open(f'{out_dir}/incidents.json', 'w'), separators=(',', ':'))
    json.dump({'weights': w, 'features': ['bias', 'detector', 'org_x_detector', 'alert_title', 'category', 'org', 'log_alerts', 'log_evidence', 'incriminated', 'suspicious', 'verdict_malicious', 'verdict_suspicious', 'verdict_nothreats'],
               'train_incidents': len(train), 'train_auc_halfB': train_auc, 'test_auc_selected_orgs': test_auc}, open(f'{out_dir}/model.json', 'w'), indent=1)


if __name__ == '__main__':
    main(*sys.argv[1:3])
