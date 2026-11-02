"""Exercise the installed wheel from outside the source tree."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
command = shutil.which('agentwatch')
if not command:
    raise SystemExit('Install the wheel before running this check')
with tempfile.TemporaryDirectory() as directory:
    work = Path(directory)
    for name in ('baseline.jsonl', 'candidate.jsonl'):
        shutil.copy2(ROOT/'examples'/name, work/name)
    for mode, args in [('rules', ['--rules-only']), ('ml', ['--baseline', str(work/'baseline.jsonl')])]:
        output = work/mode
        result = subprocess.run([command, *args, '--input', str(work/'candidate.jsonl'),
                                 '--allow-domain', 'docs.example.com', '--output', str(output)],
                                cwd=work, capture_output=True, text=True)
        if result.returncode:
            raise SystemExit(result.stderr)
        report = json.loads((output/'report.json').read_text())
        assert report['schema_version'] == 1
        assert report['candidate_sessions'] == 44
        assert (output/'COMPLETE').is_file()
        assert 'Content-Security-Policy' in (output/'report.html').read_text()
        count = sum(row['review'] for row in report['sessions'])
        assert count == (3 if mode == 'rules' else 9), (mode, count)
        assert (report['model'] is None) == (mode == 'rules')
        print(f'Installed {mode} workflow passed: {count}/44 sessions need review')
