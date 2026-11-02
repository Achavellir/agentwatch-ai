"""Offline, read-only AI-agent trace triage. Never executes trace content."""
import argparse
from collections import defaultdict
import html
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np
from sklearn.ensemble import IsolationForest

__version__ = '0.2.0'

FEATURES = ['calls', 'bytes_sent', 'external_calls', 'sensitive_calls', 'write_calls', 'unique_tools']
ALLOWED_TOOLS = {'search', 'read', 'http', 'write', 'shell'}


def hostname(url):
    if not url:
        return ''
    parsed = urlsplit(url)
    if parsed.scheme not in {'https', 'http'} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('destination must be an HTTP(S) URL without embedded credentials')
    return parsed.hostname.lower().rstrip('.')


def validate_event(event):
    """Shared schema for imported events and the integration writer."""
    if not isinstance(event, dict):
        raise ValueError('event must be an object')
    for key in ('event_id', 'session_id', 'tool'):
        if not isinstance(event.get(key), str) or not 0 < len(event[key]) <= 200:
            raise ValueError(f'invalid {key}')
    if event['tool'] not in ALLOWED_TOOLS:
        raise ValueError('unsupported tool')
    if type(event.get('bytes_sent')) is not int or not 0 <= event['bytes_sent'] <= 10**12:
        raise ValueError('invalid bytes_sent')
    for key in ('sensitive', 'approved'):
        if type(event.get(key)) is not bool:
            raise ValueError(f'{key} must be boolean')
    if not isinstance(event.get('destination', ''), str):
        raise ValueError('invalid destination')
    hostname(event.get('destination', ''))


def load(path):
    """Read at most the input limit plus one byte, including growing files."""
    with Path(path).open('rb') as stream:
        raw = stream.read(10_000_001)
    if len(raw) > 10_000_000:
        raise ValueError('Input exceeds 10 MB')
    sessions = defaultdict(list)
    ids = set()
    for number, line in enumerate(raw.decode('utf-8').splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
            validate_event(event)
        except ValueError as error:
            raise ValueError(f'Line {number}: {error}') from error
        if event['event_id'] in ids:
            raise ValueError(f'Line {number}: duplicate event ID')
        ids.add(event['event_id'])
        event['_line'] = number
        sessions[event['session_id']].append(event)
    if not sessions:
        raise ValueError('No events')
    return dict(sessions)


def vector(events, domains):
    return [len(events), sum(e['bytes_sent'] for e in events),
            sum(bool(hostname(e.get('destination', ''))) and hostname(e['destination']) not in domains for e in events),
            sum(e['sensitive'] for e in events), sum(e['tool'] in {'write', 'shell'} for e in events),
            len({e['tool'] for e in events})]


def findings(events, domains):
    output = []
    for e in events:
        host = hostname(e.get('destination', ''))
        rules = []
        if not host and (e['bytes_sent'] > 0 or e['tool'] == 'http'):
            rules.append('MISSING_DESTINATION')
        if host and host not in domains:
            rules.append('UNAPPROVED_DESTINATION')
        if e['sensitive'] and e['bytes_sent'] > 0 and host and host not in domains:
            rules.append('SENSITIVE_EXTERNAL_TRANSFER')
        if e['tool'] in {'write', 'shell'} and not e['approved']:
            rules.append('ACTION_WITHOUT_APPROVAL')
        if rules:
            output.append({'event_id': e['event_id'], 'line': e['_line'], 'rules': rules})
    return output


def analyze(baseline, candidate, domains):
    if len(baseline) < 30:
        raise ValueError('Provide at least 30 reviewed baseline sessions')
    if set(baseline) & set(candidate):
        raise ValueError('Baseline and candidate session IDs overlap')
    if {e['event_id'] for es in baseline.values() for e in es} & {e['event_id'] for es in candidate.values() for e in es}:
        raise ValueError('Baseline and candidate event IDs overlap')
    train = np.array([vector(es, domains) for es in baseline.values()])
    model = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=1)
    model.fit(np.log1p(train))
    rows = []
    for sid, events in candidate.items():
        values = vector(events, domains)
        margin = float(model.decision_function(np.log1p([values]))[0])
        rules = findings(events, domains)
        rows.append({'session_id': sid, 'anomaly': margin < 0, 'anomaly_margin': round(margin, 6),
                     'review': bool(rules) or margin < 0, 'features': dict(zip(FEATURES, values)),
                     'baseline_medians': dict(zip(FEATURES, np.median(train, axis=0).tolist())),
                     'findings': rules, 'evidence_ids': [e['event_id'] for e in events]})
    return {'schema_version': 1, 'agentwatch_version': __version__, 'model': 'IsolationForest', 'seed': 42, 'contamination': 0.05,
            'baseline_sessions': len(baseline), 'candidate_sessions': len(candidate),
            'note': 'Negative margins indicate unusual behavior, not attack probability. Human review required. Rules and ML are independent.',
            'sessions': sorted(rows, key=lambda r: (not r['review'], r['anomaly_margin']))}


def normalize_domain(value):
    """Accept explicit DNS hostnames; URLs, ports and wildcards are mistakes."""
    value = value.lower().rstrip('.')
    if len(value) > 253 or not value or any(
        not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
        for label in value.split('.')
    ):
        raise ValueError('allow-domain must be an exact ASCII hostname, without scheme, path, port or wildcard')
    return value


def analyze_rules(candidate, domains):
    rows = []
    for sid, events in candidate.items():
        rules = findings(events, domains)
        rows.append({'session_id': sid, 'anomaly': False, 'anomaly_margin': None,
                     'review': bool(rules), 'features': dict(zip(FEATURES, vector(events, domains))),
                     'baseline_medians': dict.fromkeys(FEATURES, None),
                     'findings': rules, 'evidence_ids': [e['event_id'] for e in events]})
    return {'schema_version': 1, 'agentwatch_version': __version__, 'model': None,
            'baseline_sessions': 0, 'candidate_sessions': len(candidate),
            'note': 'Rules-only review. ML is disabled; no behavioral baseline is used. Human review required.',
            'sessions': sorted(rows, key=lambda r: (not r['review'], r['session_id']))}


def write_reports(report, output):
    """A fresh private directory owns this run; never replace existing evidence.

    Files are exclusively created. The destination parent must be controlled by
    the caller; this is not a defense against a hostile process with the same UID.
    On failure a partial directory may remain and must not be treated as a run.
    """
    payloads = {'report.json': json.dumps(report, indent=2, allow_nan=False) + '\n',
                'report.html': render(report)}
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir(mode=0o700, exist_ok=False)
    for name, content in payloads.items():
        fd = os.open(output/name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(content)
    # Written last: consumers can distinguish complete runs from partial writes.
    fd = os.open(output/'COMPLETE', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        stream.write('AgentWatch report generation completed.\n')


def render(report):
    esc = lambda x: html.escape(str(x), quote=True)
    cards = []
    for row in report['sessions']:
        details = ''.join(f'<tr><td>{esc(k)}</td><td>{esc(v)}</td><td>{esc(row["baseline_medians"][k] if report["model"] else "Not used")}</td></tr>' for k, v in row['features'].items())
        cards.append(f'<article><h2>{esc(row["session_id"])} <small>{"REVIEW" if row["review"] else "No signal"}</small></h2>'
                     f'<p>ML margin: {row["anomaly_margin"] if report["model"] else "Disabled"} · Policy findings: {len(row["findings"])}</p>'
                     f'<details><summary>Features, baseline and evidence</summary><table><tr><th>Feature</th><th>Observed</th><th>Baseline median</th></tr>{details}</table>'
                     f'<pre>{esc(json.dumps(row["findings"], indent=2))}</pre><p>Evidence IDs: {esc(", ".join(row["evidence_ids"]))}</p></details></article>')
    return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' + \
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">' + \
        '<title>AgentWatch AI | Review report</title><style>body{font:16px system-ui;background:#101925;color:#e5edf5;max-width:1050px;margin:40px auto;padding:24px}h1{font-size:44px}small{font-size:12px;color:#79dfc2}article{background:#1a293b;border:1px solid #365069;padding:24px;margin:16px 0;border-radius:12px}table{width:100%;text-align:left}td,th{padding:8px}pre,p{overflow-wrap:anywhere;white-space:pre-wrap}summary{cursor:pointer;color:#79dfc2}</style>' + \
        f'<h1>AgentWatch AI</h1><p>Read-only agent security triage · {report["candidate_sessions"]} sessions · {report["baseline_sessions"]} baseline sessions</p><p>{esc(report["note"])}</p><p>Input provenance is not verified by this tool. Bundled examples are synthetic; results do not establish production accuracy.</p>' + ''.join(cards) + '</html>'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version=f'AgentWatch {__version__}')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--baseline', help='Reviewed JSONL baseline with at least 30 sessions')
    mode.add_argument('--rules-only', action='store_true', help='Run policy rules without a baseline or ML')
    parser.add_argument('--input', required=True, help='Candidate JSONL tool events (maximum 10 MB)')
    parser.add_argument('--allow-domain', action='append', default=[], help='Exact ASCII hostname; repeat for multiple hosts')
    parser.add_argument('--output', required=True, help='New report directory; existing paths are never overwritten')
    args = parser.parse_args(argv)
    try:
        domains = {normalize_domain(d) for d in args.allow_domain}
        candidate = load(args.input)
        report = (analyze_rules(candidate, domains) if args.rules_only
                  else analyze(load(args.baseline), candidate, domains))
        write_reports(report, args.output)
    except (ValueError, OSError, RecursionError) as error:
        if isinstance(error, FileExistsError):
            message = 'Output path already exists. Choose a new directory to preserve previous evidence.'
        elif isinstance(error, UnicodeError):
            message = 'Input must be UTF-8 JSONL.'
        elif isinstance(error, OSError):
            message = f'File operation failed: {error.strerror}. Check input paths, output permissions and disk space.'
        elif isinstance(error, RecursionError):
            message = 'Input nesting is too deep.'
        else:
            message = str(error)
        print(f'AgentWatch: {message}', file=sys.stderr)
        return 2
    print(f'{len(report["sessions"])} sessions; {sum(r["review"] for r in report["sessions"])} require review. Report: {Path(args.output) / "report.html"}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
