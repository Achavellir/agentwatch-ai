import copy
import json
from pathlib import Path
import tempfile
import unittest

from agentwatch import analyze, findings, load
from trace_writer import TraceWriter

ROOT = Path(__file__).resolve().parents[1]

class HardeningTests(unittest.TestCase):
    def event(self):
        return dict(event_id='one', session_id='one', tool='http', destination='',
                    bytes_sent=10, sensitive=True, approved=True, _line=1)

    def test_missing_destination_requires_review(self):
        for destination in ('', None):
            event = self.event()
            if destination is None:
                del event['destination']
            with self.subTest(destination=destination):
                self.assertIn('MISSING_DESTINATION', findings([event], set())[0]['rules'])

    def test_http_without_destination_even_with_zero_bytes(self):
        event = self.event()
        event['bytes_sent'] = 0
        self.assertIn('MISSING_DESTINATION', findings([event], set())[0]['rules'])

    def test_local_read_without_network_is_not_flagged(self):
        event = self.event()
        event.update(tool='read', bytes_sent=0)
        self.assertEqual(findings([event], set()), [])

    def test_writer_rejects_invalid_record_before_writing(self):
        for sid, sent in [('', 0), ('x'*201, 0), (None, 0), ('ok', 10**12+1), ('ok', True)]:
            with self.subTest(sid=sid, sent=sent), tempfile.TemporaryDirectory() as d:
                p = Path(d)/'trace'
                with self.assertRaises(ValueError):
                    TraceWriter(p, sid).record('http', bytes_sent=sent)
                self.assertFalse(p.exists())

    def test_maximum_bytes_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'trace'
            TraceWriter(p, 'ok').record('http', bytes_sent=10**12, destination='https://example.com')
            self.assertEqual(load(p)['ok'][0]['bytes_sent'], 10**12)

    def test_unapproved_shell_rule_without_ml(self):
        event = self.event()
        event.update(tool='shell', bytes_sent=0, approved=False)
        self.assertEqual(findings([event], set())[0]['rules'], ['ACTION_WITHOUT_APPROVAL'])

    def test_event_id_overlap_with_disjoint_session_ids(self):
        base = load(ROOT/'examples/baseline.jsonl')
        events = copy.deepcopy(next(iter(base.values())))
        for e in events:
            e['session_id'] = 'renamed'
        with self.assertRaisesRegex(ValueError, 'event IDs overlap'):
            analyze(base, {'renamed': events}, set())

    def test_empty_malformed_and_non_object_inputs(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'trace'
            for payload in ('', '{broken', '[]', 'null'):
                with self.subTest(payload=payload):
                    p.write_text(payload)
                    with self.assertRaises(ValueError):
                        load(p)

    def test_file_size_boundary(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'trace'
            event = json.dumps(self.event())
            p.write_text(event + ' '*(10_000_000-len(event)))
            self.assertEqual(len(load(p)), 1)
            with p.open('a') as stream:
                stream.write(' ')
            with self.assertRaisesRegex(ValueError, '10 MB'):
                load(p)

    def test_missing_destination_overrides_normal_ml_score(self):
        from unittest.mock import patch
        base = load(ROOT/'examples/baseline.jsonl')
        event = self.event()
        with patch('agentwatch.IsolationForest') as model:
            model.return_value.decision_function.return_value = [0.5]
            row = analyze(base, {'one': [event]}, set())['sessions'][0]
        self.assertFalse(row['anomaly'])
        self.assertTrue(row['review'])

    def test_cli_writes_both_reports(self):
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as d:
            result = subprocess.run([sys.executable, str(ROOT/'agentwatch.py'),
                '--baseline', str(ROOT/'examples/baseline.jsonl'),
                '--input', str(ROOT/'examples/candidate.jsonl'),
                '--allow-domain', 'docs.example.com', '--output', d], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((Path(d)/'report.json').read_text())
            self.assertEqual(report['candidate_sessions'], 44)
            self.assertIn('Content-Security-Policy', (Path(d)/'report.html').read_text())
