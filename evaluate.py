"""Gate frozen synthetic regressions; never claim independent security accuracy."""
import argparse
import hashlib
import json
from pathlib import Path

from agentwatch import analyze, load

ROOT = Path(__file__).resolve().parent
EVENT_FIELDS = ('tool', 'destination', 'bytes_sent', 'sensitive', 'approved')


def session_digest(events):
    # Ignore identifiers, line numbers, unknown metadata and event ordering.
    records = sorted(json.dumps({key: e.get(key, '') for key in EVENT_FIELDS},
                                sort_keys=True) for e in events)
    return hashlib.sha256(json.dumps(records).encode('utf-8')).hexdigest()


def check_split(baseline, candidate):
    if set(baseline) & set(candidate):
        raise ValueError('Baseline and candidate session IDs overlap')
    base_ids = {e['event_id'] for events in baseline.values() for e in events}
    test_ids = {e['event_id'] for events in candidate.values() for e in events}
    if base_ids & test_ids:
        raise ValueError('Baseline and candidate event IDs overlap')
    if {session_digest(es) for es in baseline.values()} & {session_digest(es) for es in candidate.values()}:
        raise ValueError('Baseline and candidate session content overlap; review provenance')


def grade(report, manifest):
    labels = manifest.get('labels', {})
    rows = {row['session_id']: row for row in report['sessions']}
    if not labels or set(rows) != set(labels):
        raise ValueError('Manifest labels must cover exactly every candidate session')
    if any(not isinstance(label, dict) or label.get('kind') not in {'normal', 'scenario'}
           for label in labels.values()):
        raise ValueError('Unknown evaluation label')
    ceiling = manifest.get('max_normal_flags')
    if type(ceiling) is not int or ceiling < 0:
        raise ValueError('max_normal_flags must be a nonnegative integer')
    normals = [rows[sid] for sid, label in labels.items() if label['kind'] == 'normal']
    scenarios = [(rows[sid], label) for sid, label in labels.items() if label['kind'] == 'scenario']
    if not normals or not scenarios:
        raise ValueError('Evaluation requires both normal and scenario sessions')
    failures = []
    flagged = sum(row['review'] for row in normals)
    if flagged > ceiling:
        failures.append(f'Normal flags {flagged} exceed regression ceiling {ceiling}')
    outcomes = []
    for row, label in scenarios:
        required = label.get('required_rules')
        if not isinstance(required, list) or any(not isinstance(rule, str) for rule in required):
            raise ValueError('Scenario required_rules must be a list of rule names')
        if type(label.get('expect_rules')) is not bool:
            raise ValueError('Scenario expect_rules must be boolean')
        rules = {rule for finding in row['findings'] for rule in finding['rules']}
        passed = row['review'] and set(required) <= rules and bool(rules) == label['expect_rules']
        if not passed:
            failures.append(f"Scenario expectations failed: {row['session_id']}")
        outcomes.append({'session': row['session_id'], 'ml': row['anomaly'],
                         'rules': bool(rules), 'review': row['review'], 'passed': bool(passed)})
    return {'held_out_normal_sessions': len(normals), 'normal_sessions_flagged': flagged,
            'normal_flag_rate': flagged/len(normals), 'max_normal_flags': ceiling,
            'scenario_results': outcomes, 'passed': not failures, 'failures': failures}


def evaluate(examples):
    examples = Path(examples)
    manifest = json.loads((examples/'manifest.json').read_text(encoding='utf-8'))
    for name in ('baseline.jsonl', 'candidate.jsonl'):
        actual = hashlib.sha256((examples/name).read_bytes()).hexdigest()
        if manifest.get('sha256', {}).get(name) != actual:
            raise ValueError(f'Fixture hash mismatch: {name}')
    baseline, candidate = load(examples/'baseline.jsonl'), load(examples/'candidate.jsonl')
    check_split(baseline, candidate)
    report = analyze(baseline, candidate, {'docs.example.com'})
    return {'dataset': 'Frozen synthetic regression fixtures; not an independent benchmark',
            'baseline_sessions': len(baseline), 'split_checks': 'IDs and session content disjoint',
            'fixture_sha256': manifest['sha256'],
            'threshold_note': 'Maximum 5 normal flags preserves the previously observed baseline; not a production false-alert target',
            **grade(report, manifest)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--examples', type=Path, default=ROOT/'examples')
    parser.add_argument('--output', type=Path, default=ROOT/'reports/evaluation.json')
    args = parser.parse_args()
    try:
        result = evaluate(args.examples)
    except (ValueError, OSError) as error:
        result = {'passed': False, 'failures': [str(error)]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
