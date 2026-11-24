"""Independent evaluation protocol for AgentWatch on real agent traces.

Separate from evaluate.py (the frozen synthetic regression gate). This tool
enforces the order of operations; it does not create data or labels.

  1. split   Group sessions by task family (or collection time), then assign
             whole groups to baseline / tune / final. Writes partition files and
             a blind review packet for the final set (metadata only, no model output).
  2. tune    Run all three review modes on the tune partition with tune labels.
             Explore domain policies here, never on final.
  3. freeze  Pin the domain policy, analyzer settings and SHA-256 of the code and
             partition files. Must happen before final labels are scored.
  4. score   Verify the freeze, read independent reviewer labels for final,
             compare rules-only / ML-only / combined, report counts with
             Wilson intervals and, when there are enough families, a
             family-level cluster bootstrap. Each scoring is logged.

Labels: one CSV row per (session_id, reviewer) with label normal|actionable,
optional blind=yes|no and review_seconds. Disagreements need an adjudication
CSV (session_id,label). The tool cannot verify that reviewers were blind; it
records what they declared.
"""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import random
import time

import agentwatch
from agentwatch import analyze, analyze_rules, load, normalize_domain

ROOT = Path(__file__).resolve().parent
PARTITIONS = ('baseline', 'tune', 'final')
LABELS = {'normal', 'actionable'}
MODES = ('rules_only', 'ml_only', 'combined')


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _private_write(path, text, exclusive=True):
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        stream.write(text)


def _bucket(key, seed):
    """Stable value in [0, 1) for a group key; independent of input order."""
    digest = hashlib.sha256(f'{seed}:{key}'.encode()).digest()
    return int.from_bytes(digest[:8], 'big') / 2**64


# ---------------------------------------------------------------- split

def assign(runs, strategy, seed=0, tune=0.2, final=0.3, tune_after=None, final_after=None,
           keep_out=()):
    """Return {session_id: partition}. Groups never straddle partitions.

    keep_out: families that must never train the baseline (e.g. controlled
    policy-violation scenarios). They go to tune or final by the same hash.
    """
    keep_out = set(keep_out)
    if strategy == 'family':
        if not 0 < tune < 1 or not 0 < final < 1 or tune + final >= 1:
            raise ValueError('tune and final fractions must be positive and sum below 1')
        out = {}
        for run in runs:
            b = _bucket(run['task_family'], seed)
            if run['task_family'] in keep_out:
                out[run['session_id']] = 'final' if b < final / (final + tune) else 'tune'
            else:
                out[run['session_id']] = 'final' if b < final else 'tune' if b < final + tune else 'baseline'
        return out
    if strategy == 'time':
        if not tune_after or not final_after or not tune_after < final_after:
            raise ValueError('time strategy needs --tune-after < --final-after (ISO timestamps)')
        out = {}
        for run in runs:
            t = run['finished_at']
            p = 'final' if t >= final_after else 'tune' if t >= tune_after else 'baseline'
            if p == 'baseline' and run['task_family'] in keep_out:
                raise ValueError(f"keep-out family {run['task_family']} falls before --tune-after")
            out[run['session_id']] = p
        # Keep related runs together: a family seen earlier may not appear later.
        first = {}
        for run in sorted(runs, key=lambda r: r['finished_at']):
            first.setdefault(run['task_family'], out[run['session_id']])
        leaked = sorted({r['task_family'] for r in runs if out[r['session_id']] != first[r['task_family']]})
        return out, leaked
    raise ValueError('strategy must be family or time')


def split(trace, runs_path, study, strategy, **options):
    study = Path(study)
    study.mkdir(mode=0o700, parents=True, exist_ok=False)
    runs = [json.loads(l) for l in Path(runs_path).read_text(encoding='utf-8').splitlines() if l.strip()]
    by_id = {r['session_id']: r for r in runs}
    if len(by_id) != len(runs):
        raise ValueError('duplicate session_id in runs file')
    sessions = load(trace)
    missing_meta = sorted(set(sessions) - set(by_id))
    if missing_meta:
        raise ValueError(f'trace sessions without run metadata: {missing_meta[:5]}')
    leaked = []
    allow_overlap = options.pop('allow_family_overlap', False)
    result = assign(runs, strategy, **options)
    options['allow_family_overlap'] = allow_overlap
    if strategy == 'time':
        result, leaked = result
        if leaked and not allow_overlap:
            raise ValueError(f'task families span time partitions: {leaked[:5]}. '
                             'Move cutoffs or pass --allow-family-overlap and report it.')
    lines = {p: [] for p in PARTITIONS}
    for line in Path(trace).read_text(encoding='utf-8').splitlines():
        if line.strip():
            sid = json.loads(line)['session_id']
            lines[result[sid]].append(line)
    hashes = {}
    for p in PARTITIONS:
        path = study / f'{p}.jsonl'
        _private_write(path, '\n'.join(lines[p]) + ('\n' if lines[p] else ''))
        hashes[path.name] = sha256(path)
    families = {p: sorted({by_id[s]['task_family'] for s in sessions if result[s] == p}) for p in PARTITIONS}
    counts = {p: sum(result[s] == p for s in sessions) for p in PARTITIONS}
    # Blind packet: events only, ordered by sequence; no rules, margins or intent.
    packet = []
    for sid in sorted(s for s in sessions if result[s] == 'final'):
        evs = sorted(sessions[sid], key=lambda e: (e.get('seq', 0), e['_line']))
        packet.append(json.dumps({'session_id': sid, 'events': [
            {k: e[k] for k in ('tool', 'destination', 'bytes_sent', 'sensitive', 'approved', 'status', 'seq')
             if k in e} for e in evs]}))
    _private_write(study / 'review_packet_final.jsonl', '\n'.join(packet) + '\n')
    for p in ('tune', 'final'):
        rows = ['session_id,reviewer,label,blind,review_seconds,notes'] + \
               [f'{s},,,,,' for s in sorted(s for s in sessions if result[s] == p)]
        _private_write(study / f'labels_{p}_TEMPLATE.csv', '\n'.join(rows) + '\n')
    manifest = {'created': _now(), 'strategy': strategy, 'options': {k: v for k, v in options.items()},
                'counts': counts, 'families': families, 'family_overlap': leaked,
                'partition_sha256': hashes, 'trace_sha256': sha256(trace),
                'runs_sha256': sha256(runs_path), 'session_family': {s: by_id[s]['task_family'] for s in sessions},
                'partition_of': result}
    _private_write(study / 'split.json', json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    return manifest


# ---------------------------------------------------------------- labels

def read_labels(path, adjudication=None, expect=None):
    per = {}
    meta = {'reviewers': set(), 'blind_declared': {}, 'review_seconds': []}
    with open(path, newline='', encoding='utf-8') as stream:
        for row in csv.DictReader(stream):
            sid, label, who = row.get('session_id', '').strip(), row.get('label', '').strip().lower(), row.get('reviewer', '').strip()
            if not sid:
                continue
            if label not in LABELS or not who:
                raise ValueError(f'{sid}: label must be normal|actionable and reviewer is required')
            if who in per.setdefault(sid, {}):
                raise ValueError(f'{sid}: duplicate label from {who}')
            per[sid][who] = label
            meta['reviewers'].add(who)
            meta['blind_declared'][who] = meta['blind_declared'].get(who, True) and \
                row.get('blind', '').strip().lower() in {'yes', 'y', 'true'}
            if (row.get('review_seconds') or '').strip():
                meta['review_seconds'].append(float(row['review_seconds']))
    adjudicated = {}
    if adjudication:
        with open(adjudication, newline='', encoding='utf-8') as stream:
            for row in csv.DictReader(stream):
                label = row['label'].strip().lower()
                if label not in LABELS:
                    raise ValueError('adjudicated label must be normal|actionable')
                adjudicated[row['session_id'].strip()] = label
    final, unresolved = {}, []
    for sid, votes in per.items():
        if sid in adjudicated:
            final[sid] = adjudicated[sid]
        elif len(set(votes.values())) == 1:
            final[sid] = next(iter(votes.values()))
        else:
            unresolved.append(sid)
    if unresolved:
        raise ValueError(f'reviewer disagreement needs adjudication: {sorted(unresolved)[:10]}')
    if expect is not None and set(final) != set(expect):
        raise ValueError(f'labels must cover exactly the partition: missing {sorted(set(expect)-set(final))[:5]}, '
                         f'extra {sorted(set(final)-set(expect))[:5]}')
    meta['agreement'] = agreement(per)
    meta['reviewers'] = sorted(meta['reviewers'])
    return final, meta


def agreement(per):
    """Raw agreement and Cohen's kappa for sessions labelled by the first two reviewers."""
    reviewers = sorted({r for v in per.values() for r in v})
    if len(reviewers) < 2:
        return None
    a, b = reviewers[:2]
    pairs = [(v[a], v[b]) for v in per.values() if a in v and b in v]
    if not pairs:
        return None
    n = len(pairs)
    po = sum(x == y for x, y in pairs) / n
    pa = sum(x == 'actionable' for x, _ in pairs) / n
    pb = sum(y == 'actionable' for _, y in pairs) / n
    pe = pa * pb + (1 - pa) * (1 - pb)
    kappa = None if pe == 1 else (po - pe) / (1 - pe)
    return {'reviewers': [a, b], 'sessions': n, 'raw_agreement': round(po, 4),
            'cohen_kappa': None if kappa is None else round(kappa, 4)}


# ---------------------------------------------------------------- metrics

def wilson(k, n, z=1.959964):
    if n == 0:
        return None
    p = k / n
    denom = 1 + z*z/n
    centre = (p + z*z/(2*n)) / denom
    half = z * math.sqrt(p*(1-p)/n + z*z/(4*n*n)) / denom
    return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


def confusion(flags, labels):
    c = {'tp': 0, 'fp': 0, 'fn': 0, 'tn': 0}
    for sid, label in labels.items():
        f = flags[sid]
        c[('tp' if f else 'fn') if label == 'actionable' else ('fp' if f else 'tn')] += 1
    return c


def summarize(c):
    pos, neg, alerts = c['tp'] + c['fn'], c['fp'] + c['tn'], c['tp'] + c['fp']
    return {**c, 'actionable_sessions': pos, 'normal_sessions': neg, 'alerts': alerts,
            'recall': None if not pos else round(c['tp']/pos, 4), 'recall_95ci_wilson': wilson(c['tp'], pos),
            'false_alert_rate': None if not neg else round(c['fp']/neg, 4),
            'false_alert_rate_95ci_wilson': wilson(c['fp'], neg),
            'precision': None if not alerts else round(c['tp']/alerts, 4)}


def cluster_bootstrap(flags, labels, family, reps=2000, seed=0):
    """Resample whole task families (correlated runs) with replacement."""
    fams = sorted({family[s] for s in labels})
    if len(fams) < 5:
        return {'note': f'only {len(fams)} families in final; cluster bootstrap not reported'}
    members = {f: [s for s in labels if family[s] == f] for f in fams}
    rng = random.Random(seed)
    recalls, fars = [], []
    for _ in range(reps):
        c = {'tp': 0, 'fp': 0, 'fn': 0, 'tn': 0}
        for f in (rng.choice(fams) for _ in fams):
            for k, v in confusion({s: flags[s] for s in members[f]}, {s: labels[s] for s in members[f]}).items():
                c[k] += v
        if c['tp'] + c['fn']:
            recalls.append(c['tp']/(c['tp']+c['fn']))
        if c['fp'] + c['tn']:
            fars.append(c['fp']/(c['fp']+c['tn']))
    pct = lambda xs: None if len(xs) < reps * 0.5 else [round(sorted(xs)[int(0.025*len(xs))], 4),
                                                          round(sorted(xs)[min(len(xs)-1, int(0.975*len(xs)))], 4)]
    return {'families': len(fams), 'reps': reps, 'seed': seed,
            'recall_95ci': pct(recalls), 'false_alert_rate_95ci': pct(fars)}


def compare(baseline, target, domains, labels, family):
    start = time.perf_counter()
    combined = analyze(baseline, target, domains)
    ml_seconds = time.perf_counter() - start
    rules = analyze_rules(target, domains)
    rows = {r['session_id']: r for r in combined['sessions']}
    flags = {'rules_only': {r['session_id']: r['review'] for r in rules['sessions']},
             'ml_only': {s: r['anomaly'] for s, r in rows.items()},
             'combined': {s: r['review'] for s, r in rows.items()}}
    out = {m: {**summarize(confusion(flags[m], labels)),
               'family_bootstrap': cluster_bootstrap(flags[m], labels, family)} for m in MODES}
    out['incremental_combined_vs_rules'] = {
        'additional_actionable_found': out['combined']['tp'] - out['rules_only']['tp'],
        'additional_false_alerts': out['combined']['fp'] - out['rules_only']['fp']}
    out['analyzer_seconds_total'] = round(ml_seconds, 4)
    out['analyzer_ms_per_session'] = round(1000 * ml_seconds / max(1, len(target)), 3)
    return out


# ---------------------------------------------------------------- freeze / score

def pinned_files(study):
    study = Path(study)
    files = {'agentwatch.py': Path(agentwatch.__file__), 'independent_eval.py': Path(__file__),
             'split.json': study/'split.json'}
    files.update({f'{p}.jsonl': study/f'{p}.jsonl' for p in PARTITIONS})
    return files


def freeze(study, domains, note=''):
    study = Path(study)
    target = study/'freeze.json'
    record = {'frozen_at': _now(), 'allow_domains': sorted(normalize_domain(d) for d in domains),
              'agentwatch_version': agentwatch.__version__,
              'analyzer': {'model': 'IsolationForest', 'n_estimators': 200, 'contamination': 0.05,
                           'random_state': 42, 'features': agentwatch.FEATURES, 'review_rule': 'rule OR margin<0'},
              'sha256': {k: sha256(v) for k, v in pinned_files(study).items()}, 'note': note}
    _private_write(target, json.dumps(record, indent=2, sort_keys=True) + '\n')
    return record


def _verify_freeze(study):
    study = Path(study)
    if not (study/'freeze.json').is_file():
        raise ValueError('run freeze before scoring the final partition')
    record = json.loads((study/'freeze.json').read_text(encoding='utf-8'))
    changed = [k for k, v in pinned_files(study).items() if sha256(v) != record['sha256'].get(k)]
    if changed:
        raise ValueError(f'files changed since freeze: {changed}. Scoring would not be pre-registered.')
    return record


def evaluate_partition(study, partition, labels_path, adjudication=None, domains=None):
    study = Path(study)
    manifest = json.loads((study/'split.json').read_text(encoding='utf-8'))
    if partition == 'final':
        record = _verify_freeze(study)
        domains = set(record['allow_domains'])
    elif partition != 'tune':
        raise ValueError('evaluate tune or final only')
    domains = {normalize_domain(d) for d in (domains or [])}
    baseline, target = load(study/'baseline.jsonl'), load(study/f'{partition}.jsonl')
    labels, meta = read_labels(labels_path, adjudication, expect=set(target))
    result = {'partition': partition, 'evaluated_at': _now(), 'allow_domains': sorted(domains),
              'baseline_sessions': len(baseline), 'sessions': len(target),
              'families': len({manifest['session_family'][s] for s in target}),
              'reviewers': meta['reviewers'], 'blind_declared': meta['blind_declared'],
              'reviewer_agreement': meta['agreement'],
              'median_review_seconds': _median(meta['review_seconds']),
              'labels_sha256': sha256(labels_path),
              'results': compare(baseline, target, domains, labels, manifest['session_family']),
              'caveats': ['Counts come only from the supplied traces and labels.',
                          'Intervals assume the stated sampling; runs within a family are correlated.',
                          'Blindness is self-declared by reviewers.']}
    if partition == 'final':
        log = study/'final_scoring_log.jsonl'
        fd = os.open(log, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, 'a', encoding='utf-8') as stream:
            stream.write(json.dumps({'at': result['evaluated_at'], 'labels_sha256': result['labels_sha256']}) + '\n')
        result['final_scoring_count'] = sum(1 for _ in log.read_text().splitlines() if _.strip())
    return result


def completeness_summary(path):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    n, bad = data['session_count'], data['incomplete_sessions']
    return {'sessions': n, 'incomplete': bad, 'incomplete_rate': None if not n else round(bad/n, 4),
            'incomplete_95ci_wilson': wilson(bad, n)}


def _median(xs):
    if not xs:
        return None
    xs = sorted(xs)
    mid = len(xs)//2
    return xs[mid] if len(xs) % 2 else (xs[mid-1] + xs[mid]) / 2


def _now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('split')
    s.add_argument('--trace', required=True); s.add_argument('--runs', required=True)
    s.add_argument('--study', required=True); s.add_argument('--strategy', choices=['family', 'time'], default='family')
    s.add_argument('--seed', type=int, default=0); s.add_argument('--tune', type=float, default=0.2)
    s.add_argument('--final', type=float, default=0.3)
    s.add_argument('--tune-after'); s.add_argument('--final-after')
    s.add_argument('--allow-family-overlap', action='store_true')
    s.add_argument('--keep-out-of-baseline', action='append', default=[], metavar='FAMILY',
                   help='Task family that must not train the baseline (repeatable)')
    for name in ('tune', 'score'):
        p = sub.add_parser(name)
        p.add_argument('--study', required=True); p.add_argument('--labels', required=True)
        p.add_argument('--adjudication'); p.add_argument('--completeness')
        p.add_argument('--output', required=True, help='New JSON results file')
        if name == 'tune':
            p.add_argument('--allow-domain', action='append', default=[])
    f = sub.add_parser('freeze')
    f.add_argument('--study', required=True); f.add_argument('--allow-domain', action='append', default=[])
    f.add_argument('--note', default='')
    args = parser.parse_args(argv)
    try:
        if args.cmd == 'split':
            opts = ({'seed': args.seed, 'tune': args.tune, 'final': args.final} if args.strategy == 'family'
                    else {'tune_after': args.tune_after, 'final_after': args.final_after,
                          'allow_family_overlap': args.allow_family_overlap})
            opts['keep_out'] = sorted(args.keep_out_of_baseline)
            m = split(args.trace, args.runs, args.study, args.strategy, **opts)
            print(json.dumps({'counts': m['counts'], 'families': {k: len(v) for k, v in m['families'].items()}}))
        elif args.cmd == 'freeze':
            print(json.dumps(freeze(args.study, args.allow_domain, args.note), indent=2))
        else:
            result = evaluate_partition(args.study, 'tune' if args.cmd == 'tune' else 'final', args.labels,
                                        args.adjudication, getattr(args, 'allow_domain', None))
            if args.completeness:
                result['logging_completeness'] = completeness_summary(args.completeness)
            _private_write(args.output, json.dumps(result, indent=2) + '\n')
            print(json.dumps(result['results']['incremental_combined_vs_rules']))
    except (ValueError, OSError, KeyError) as error:
        print(f'independent_eval: {error}')
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
