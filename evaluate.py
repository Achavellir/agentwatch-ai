"""Describe fixed synthetic-scenario outcomes, not real-world accuracy."""
import json
from pathlib import Path
from agentwatch import analyze, load

report=analyze(load('examples/baseline.jsonl'),load('examples/candidate.jsonl'),{'docs.example.com'})
normal=[r for r in report['sessions'] if r['session_id'].startswith('normal-')]
scenarios=[r for r in report['sessions'] if not r['session_id'].startswith('normal-')]
result={'dataset':'Synthetic fixed fixtures; separate PRNG seeds; no production validation',
        'baseline_sessions':report['baseline_sessions'],'held_out_normal_sessions':len(normal),
        'normal_sessions_flagged':sum(r['review'] for r in normal),
        'normal_flag_rate':sum(r['review'] for r in normal)/len(normal),
        'scenario_results':[{'session':r['session_id'],'ml':r['anomaly'],'rules':bool(r['findings']),'review':r['review']} for r in scenarios]}
Path('reports/evaluation.json').write_text(json.dumps(result,indent=2))
print(json.dumps(result,indent=2))
