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

# The browser package must include its assets in the installed wheel.
ui = shutil.which('agentwatch-ui')
assert ui, 'Missing installed browser entry point'
with tempfile.TemporaryDirectory() as directory:
    work = Path(directory)
    code = """
import http.client, json, threading
from agentwatch_ui import create_server
with create_server(0) as server:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for route in ('/', '/app.js', '/style.css'):
            conn = http.client.HTTPConnection('127.0.0.1', server.server_port)
            conn.request('GET', route)
            response = conn.getresponse()
            assert response.status == 200, route
            assert response.read(), route
            conn.close()
        event = dict(event_id='installed', session_id='installed', tool='shell', bytes_sent=0, sensitive=False, approved=False)
        conn = http.client.HTTPConnection('127.0.0.1', server.server_port)
        body = json.dumps(dict(events=json.dumps(event), domains=[]))
        conn.request('POST', '/api/review', body, {'Origin':server.origin,'X-AgentWatch-Token':server.token,'Content-Type':'application/json'})
        response = conn.getresponse()
        assert response.status == 200
        result = json.loads(response.read())
        assert result['report']['sessions'][0]['review']
        conn.close()
    finally:
        server.shutdown()
        thread.join()
"""
    import sys
    result = subprocess.run([sys.executable, '-c', code], cwd=work, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    result = subprocess.run([ui, '--version'], cwd=work, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert '0.3.0' in result.stdout
    print('Installed browser assets and policy review passed')
