"""Reproducible synthetic fixtures. These are NOT production telemetry."""
import hashlib
import json
import random
from pathlib import Path

ROOT = Path(__file__).parent / 'examples'

def session(sid, n, rng, tool=None, destination='https://docs.example.com/help', sent=None, sensitive=False, approved=True):
    return [dict(event_id=f'{sid}-{i}', session_id=sid, tool=tool or rng.choice(['search','read','http']),
                 destination=destination, bytes_sent=rng.randint(0,500) if sent is None else sent,
                 sensitive=sensitive, approved=approved) for i in range(n)]

def main(output=None):
    root = Path(output) if output is not None else ROOT
    rng = random.Random(42)
    baseline = [e for i in range(200) for e in session(f'train-{i}',rng.randint(3,12),rng)]
    test_rng = random.Random(101)
    candidates = [e for i in range(40) for e in session(f'normal-{i}',test_rng.randint(3,12),test_rng)]
    candidates += session('external-sensitive-transfer',4,test_rng,tool='http',destination='https://collector.example.net/upload',sent=50000,sensitive=True)
    candidates += session('unapproved-shell',3,test_rng,tool='shell',destination='',sent=0,approved=False)
    candidates += session('high-volume-approved',100,test_rng,tool='http',sent=30000)
    candidates += session('lookalike-host',3,test_rng,destination='https://docs.example.com.attacker.example.net/')
    root.mkdir(parents=True, exist_ok=True)
    for name, events in [('baseline',baseline),('candidate',candidates)]:
        (root/f'{name}.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))
    required_rules = {
        'external-sensitive-transfer': ['UNAPPROVED_DESTINATION', 'SENSITIVE_EXTERNAL_TRANSFER'],
        'unapproved-shell': ['ACTION_WITHOUT_APPROVAL'],
        'high-volume-approved': [],
        'lookalike-host': ['UNAPPROVED_DESTINATION'],
    }
    labels = {f'normal-{i}': {'kind': 'normal'} for i in range(40)}
    labels.update({sid: {'kind': 'scenario', 'required_rules': rules, 'expect_rules': bool(rules)}
                   for sid, rules in required_rules.items()})
    manifest = {
        'type': 'synthetic', 'baseline_seed': 42, 'candidate_seed': 101,
        'normal_sessions': 40, 'scenario_sessions': 4,
        'expected_review': list(required_rules), 'labels': labels,
        'max_normal_flags': 5,
        'threshold_note': 'Regression ceiling from the original 5/40 result; not a calibrated production target',
        'sha256': {name: hashlib.sha256((root/name).read_bytes()).hexdigest()
                   for name in ('baseline.jsonl', 'candidate.jsonl')},
        'warning': 'Known development fixtures, not an independent holdout. High-volume approved traffic is not necessarily malicious.',
    }
    (root/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8')

if __name__ == '__main__': main()
