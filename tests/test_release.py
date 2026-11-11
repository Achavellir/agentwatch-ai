import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class ReleaseTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(ROOT/'agentwatch.py'), *map(str, args)],
                              capture_output=True, text=True)

    def test_version(self):
        result = self.run_cli('--version')
        self.assertEqual(result.returncode, 0)
        self.assertIn('0.3.0', result.stdout)

    def test_rules_only_and_private_reports(self):
        with tempfile.TemporaryDirectory() as d:
            output = Path(d)/'new'
            result = self.run_cli('--rules-only', '--input', ROOT/'examples/candidate.jsonl',
                                  '--allow-domain', 'DOCS.EXAMPLE.COM.', '--output', output)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((output/'report.json').read_text())
            self.assertEqual(report['schema_version'], 1)
            self.assertEqual(report['model'], None)
            self.assertEqual(report['baseline_sessions'], 0)
            self.assertTrue(any(r['review'] for r in report['sessions']))
            self.assertTrue(all(r['anomaly_margin'] is None for r in report['sessions']))
            self.assertNotIn('ML margin: None', (output/'report.html').read_text())
            if os.name == 'posix':
                self.assertEqual(output.stat().st_mode & 0o777, 0o700)
                self.assertEqual((output/'report.json').stat().st_mode & 0o777, 0o600)

    def test_existing_directory_is_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)/'report.json'
            target.write_text('keep me')
            result = self.run_cli('--rules-only', '--input', ROOT/'examples/candidate.jsonl', '--output', d)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(target.read_text(), 'keep me')
            self.assertNotIn('Traceback', result.stderr)

    def test_invalid_domain_is_actionable(self):
        for domain in ('https://example.com', '*.example.com', 'example.com/path', 'example.com:443'):
            result = self.run_cli('--rules-only', '--input', 'missing', '--output', 'unused', '--allow-domain', domain)
            self.assertEqual(result.returncode, 2)
            self.assertIn('hostname', result.stderr)
            self.assertNotIn('Traceback', result.stderr)

    def test_bad_input_has_no_traceback_or_output(self):
        with tempfile.TemporaryDirectory() as d:
            source, output = Path(d)/'bad', Path(d)/'out'
            for raw in (b'\xff', b'{broken', b'[]'):
                source.write_bytes(raw)
                result = self.run_cli('--rules-only', '--input', source, '--output', output)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn('Traceback', result.stderr)
                self.assertFalse(output.exists())

    def test_missing_input_and_mode_conflict(self):
        for args in [('--rules-only', '--baseline', 'x'), ('--baseline', 'missing')]:
            result = self.run_cli(*args, '--input', 'missing', '--output', 'unused')
            self.assertEqual(result.returncode, 2)
            self.assertNotIn('Traceback', result.stderr)

    def test_output_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            link = Path(d)/'link'
            target = Path(d)/'target'
            target.mkdir()
            link.symlink_to(target, target_is_directory=True)
            result = self.run_cli('--rules-only', '--input', ROOT/'examples/candidate.jsonl', '--output', link)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(list(target.iterdir()), [])

    def test_partial_output_has_no_completion_marker(self):
        from unittest.mock import patch
        from agentwatch import write_reports
        report = {'sessions': [], 'candidate_sessions': 0, 'baseline_sessions': 0, 'note': ''}
        with tempfile.TemporaryDirectory() as d:
            output = Path(d)/'run'
            original = os.open
            def fail_second(path, *args, **kwargs):
                if Path(path).name == 'report.html':
                    raise OSError('simulated disk failure')
                return original(path, *args, **kwargs)
            with patch('agentwatch.os.open', side_effect=fail_second):
                with self.assertRaises(OSError):
                    write_reports(report, output)
            self.assertTrue((output/'report.json').exists())
            self.assertFalse((output/'COMPLETE').exists())
