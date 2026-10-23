import json
import tempfile
import unittest
from pathlib import Path

from local_lab import LocalTools, run_lab
from agentwatch import load


class LocalLabTests(unittest.TestCase):
    def test_real_operations_and_metadata_only(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            workspace = root / 'workspace'
            workspace.mkdir()
            (workspace / 'input.txt').write_text('private fixture contents')
            tools = LocalTools(workspace, root / 'trace.jsonl', 's1', {'output.txt'})
            text = tools.read('input.txt')
            tools.write('output.txt', text.upper())
            self.assertEqual((workspace / 'output.txt').read_text(), text.upper())
            events = load(root / 'trace.jsonl')['s1']
            self.assertEqual([e['tool'] for e in events], ['read', 'write'])
            self.assertTrue(events[1]['approved'])
            self.assertTrue(all(e['bytes_sent'] == 0 for e in events))
            self.assertNotIn('private fixture contents', (root / 'trace.jsonl').read_text())

    def test_escape_symlink_and_failed_read_not_logged(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            workspace = root / 'workspace'
            workspace.mkdir()
            outside = root / 'outside.txt'
            outside.write_text('unchanged')
            (workspace / 'input.txt').symlink_to(outside)
            tools = LocalTools(workspace, root / 'trace.jsonl', 's1', set())
            for name in ('', '.', '..', '../outside.txt', str(outside), 'input.txt', 'bad\\name', 'bad\0name'):
                with self.assertRaises(ValueError):
                    tools.read(name)
                with self.assertRaises(ValueError):
                    tools.write(name, 'must not reach disk')
            with self.assertRaises(FileNotFoundError):
                tools.read('missing.txt')
            self.assertFalse((root / 'trace.jsonl').exists())
            self.assertEqual(outside.read_text(), 'unchanged')

    def test_unapproved_scratch_write_is_recorded(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            tools = LocalTools(root, root / 'trace.jsonl', 's1', set())
            tools.write('output.txt', 'dummy data')
            self.assertFalse(load(root / 'trace.jsonl')['s1'][0]['approved'])
            self.assertTrue((root / 'output.txt').exists())

    def test_end_to_end_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / 'run'
            result = run_lab(out)
            base, test = load(out / 'baseline.jsonl'), load(out / 'candidate.jsonl')
            self.assertEqual(len(base), 60)
            self.assertEqual(len(test), 22)
            self.assertFalse(set(base) & set(test))
            self.assertEqual(result['normal_sessions'], 20)
            self.assertEqual(result['policy_violation']['rules'], True)
            self.assertEqual(result['benign_stress']['rules'], False)
            self.assertFalse(list(out.glob('workspace*')))
            manifest = json.loads((out / 'manifest.json').read_text())
            self.assertEqual(set(manifest['labels']), set(test))
            self.assertNotIn('label', (out / 'candidate.jsonl').read_text())
            before = (out / 'candidate.jsonl').read_bytes()
            with self.assertRaises(FileExistsError):
                run_lab(out)
            self.assertEqual(before, (out / 'candidate.jsonl').read_bytes())
