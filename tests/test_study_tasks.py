import json
from pathlib import Path
import tempfile
import unittest

from scripts.ollama_agent import load_tasks
from scripts.summarize_run import summarize

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT / 'examples' / 'study_workspace'


class StudyTaskSetTests(unittest.TestCase):
    def test_task_file_is_valid_and_balanced(self):
        tasks = load_tasks(ROOT / 'examples' / 'study_tasks.json')
        families = {t['family'] for t in tasks}
        self.assertEqual(len(tasks), 20)
        self.assertEqual(len(families), 20)
        violations = [t for t in tasks if t['intent'] != 'normal']
        self.assertEqual(len(violations), 6)
        self.assertTrue(all(t['family'].startswith('violation-') for t in violations))

    def test_files_named_in_tasks_exist_in_workspace(self):
        import re
        for task in load_tasks(ROOT / 'examples' / 'study_tasks.json'):
            for name in re.findall(r'\b((?:notes|data|inbox|secrets)/[\w.]+)', task['prompt']):
                self.assertTrue((WORKSPACE / name).is_file(), f"{task['id']}: {name}")

    def test_workspace_secret_is_obviously_fake(self):
        self.assertIn('FAKE', (WORKSPACE / 'secrets' / 'api_token.txt').read_text())


class SummarizeRunTests(unittest.TestCase):
    def test_summary_counts_tool_use_outcomes_and_findings(self):
        with tempfile.TemporaryDirectory() as d:
            run = Path(d)
            (run / 'runs.jsonl').write_text('\n'.join(json.dumps(r) for r in [
                {'session_id': 'a-1', 'task_id': 'a', 'task_family': 'a', 'model': 'm', 'stop': 'final_answer'},
                {'session_id': 'b-1', 'task_id': 'b', 'task_family': 'b', 'model': 'm', 'stop': 'max_steps'}]) + '\n')
            (run / 'activity.jsonl').write_text(json.dumps(
                {'event_id': 'e1', 'session_id': 'a-1', 'tool': 'http', 'status': 'denied'}) + '\n')
            (run / 'review').mkdir()
            (run / 'review' / 'report.json').write_text(json.dumps({'sessions': [
                {'session_id': 'a-1', 'review': True, 'findings': [{'rules': ['UNAPPROVED_DESTINATION']}]},
                {'session_id': 'b-1', 'review': False, 'findings': []}]}))
            text = summarize(run)
            self.assertIn('Sessions with no tool calls at all: 1', text)
            self.assertIn('| a | - | 1 | 1.0 | final_answer 1 | denied 1 | 1 | UNAPPROVED_DESTINATION 1 |', text)
            self.assertIn('| b | - | 1 | 0.0 | max_steps 1 | - | 0 | - |', text)


if __name__ == '__main__':
    unittest.main()
