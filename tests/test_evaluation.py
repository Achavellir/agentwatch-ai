import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from evaluate import evaluate, check_split, grade
from agentwatch import load

ROOT = Path(__file__).resolve().parents[1]

class EvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = evaluate(ROOT/'examples')
        cls.base = load(ROOT/'examples/baseline.jsonl')
        cls.candidate = load(ROOT/'examples/candidate.jsonl')
        cls.manifest = json.loads((ROOT/'examples/manifest.json').read_text())

    def test_frozen_regression_passes(self):
        self.assertTrue(self.result['passed'])
        self.assertEqual(self.result['normal_sessions_flagged'], 5)
        self.assertEqual(len(self.result['scenario_results']), 4)

    def test_renamed_reordered_copy_rejected(self):
        events = copy.deepcopy(next(iter(self.base.values())))
        for i, event in enumerate(events):
            event.update(event_id=f'new-{i}', session_id='new')
        with self.assertRaisesRegex(ValueError, 'content overlap'):
            check_split(self.base, {'new': list(reversed(events))})

    def test_bundled_split_is_disjoint(self):
        check_split(self.base, self.candidate)

    def test_missing_and_unknown_labels_rejected(self):
        for change in ('missing', 'unknown'):
            manifest = copy.deepcopy(self.manifest)
            if change == 'missing':
                manifest['labels'].pop(next(iter(manifest['labels'])))
            else:
                manifest['labels'][next(iter(manifest['labels']))]['kind'] = 'typo'
            with self.subTest(change=change), self.assertRaises(ValueError):
                grade({'sessions': [{'session_id': sid} for sid in self.candidate]}, manifest)

    def test_detection_regression_fails(self):
        rows = []
        for sid in self.candidate:
            rows.append(dict(session_id=sid, review=False, anomaly=False, findings=[]))
        result = grade({'sessions': rows}, self.manifest)
        self.assertFalse(result['passed'])
        self.assertEqual(len(result['failures']), 4)

    def test_normal_alert_regression_fails(self):
        rows = []
        for sid, label in self.manifest['labels'].items():
            findings = [{'rules': label.get('required_rules', [])}] if label.get('required_rules') else []
            rows.append(dict(session_id=sid, review=True, anomaly=True, findings=findings))
        self.assertFalse(grade({'sessions': rows}, self.manifest)['passed'])

    def test_fixture_hash_mismatch_rejected(self):
        import shutil
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)/'examples'
            shutil.copytree(ROOT/'examples', root)
            with (root/'candidate.jsonl').open('a') as stream:
                stream.write('\n')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                evaluate(root)

    def test_cli_nonzero_for_failed_gate(self):
        import shutil
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)/'examples'
            shutil.copytree(ROOT/'examples', root)
            manifest = json.loads((root/'manifest.json').read_text())
            manifest['max_normal_flags'] = 0
            (root/'manifest.json').write_text(json.dumps(manifest))
            output = Path(d)/'result.json'
            result = subprocess.run([sys.executable, str(ROOT/'evaluate.py'), '--examples', str(root), '--output', str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertFalse(json.loads(output.read_text())['passed'])

    def test_generator_reproduces_frozen_fixtures(self):
        from make_demo import main
        with tempfile.TemporaryDirectory() as d:
            main(d)
            for name in ('baseline.jsonl', 'candidate.jsonl', 'manifest.json'):
                self.assertEqual((Path(d)/name).read_bytes(), (ROOT/'examples'/name).read_bytes())
