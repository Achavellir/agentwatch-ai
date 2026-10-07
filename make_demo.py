"""Reproducible synthetic fixtures. These are NOT production telemetry."""
import json
import random
from pathlib import Path

ROOT = Path(__file__).parent / 'examples'

def session(sid, n, rng, tool=None, destination='https://docs.example.com/help', sent=None, sensitive=False, approved=True):
    return [dict(event_id=f'{sid}-{i}', session_id=sid, tool=tool or rng.choice(['search','read','http']),
                 destination=destination, bytes_sent=rng.randint(0,500) if sent is None else sent,
                 sensitive=sensitive, approved=approved) for i in range(n)]

def main():
    rng = random.Random(42)
    baseline = [e for i in range(200) for e in session(f'train-{i}',rng.randint(3,12),rng)]
    test_rng = random.Random(101)
    candidates = [e for i in range(40) for e in session(f'normal-{i}',test_rng.randint(3,12),test_rng)]
    candidates += session('external-sensitive-transfer',4,test_rng,tool='http',destination='https://collector.example.net/upload',sent=50000,sensitive=True)
    candidates += session('unapproved-shell',3,test_rng,tool='shell',destination='',sent=0,approved=False)
    candidates += session('high-volume-approved',100,test_rng,tool='http',sent=30000)
    candidates += session('lookalike-host',3,test_rng,destination='https://docs.example.com.attacker.example.net/')
    ROOT.mkdir(exist_ok=True)
    for name, events in [('baseline',baseline),('candidate',candidates)]:
        (ROOT/f'{name}.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))
    (ROOT/'manifest.json').write_text(json.dumps({'type':'synthetic','baseline_seed':42,'candidate_seed':101,
        'normal_sessions':40,'scenario_sessions':4,'expected_review':['external-sensitive-transfer','unapproved-shell','high-volume-approved','lookalike-host'],
        'warning':'High-volume approved traffic is intentionally unusual, not necessarily malicious. No production accuracy claim.'},indent=2))

if __name__ == '__main__': main()
