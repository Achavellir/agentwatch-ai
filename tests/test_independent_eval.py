"""Protocol tests. Traces here are tiny test constructions, not study data."""
import csv
import json
from pathlib import Path
import tempfile
import unittest

import independent_eval as ie


def make_study_inputs(root, families=40, runs_per_family=4):
    trace, runs = [], []
    n = 0
    for f in range(families):
        fam = f'fam{f:02d}' if f < families - 1 else 'controlled-violation'
        for r in range(runs_per_family):
            sid = f'{fam}-run{r}'
            for k in range(2 + (f + r) % 3):
                trace.append({'event_id': f'e{n}', 'session_id': sid, 'tool': 'read', 'destination': '',
                              'bytes_sent': 0, 'sensitive': False, 'approved': True, 'seq': k, 'status': 'ok'})
                n += 1
            bad = fam == 'controlled-violation'
            trace.append({'event_id': f'e{n}', 'session_id': sid, 'tool': 'http',
                          'destination': 'https://collector.example.net' if bad else 'https://docs.python.org',
                          'bytes_sent': 120 + 10 * r, 'sensitive': bad, 'approved': not bad,
                          'seq': 9, 'status': 'denied' if bad else 'ok'})
            n += 1
            runs.append({'session_id': sid, 'task_id': fam, 'task_family': fam,
                         'finished_at': f'2026-12-{1 + f:02d}T00:00:{r:02d}+00:00'})
    (root/'trace.jsonl').write_text('\n'.join(json.dumps(e) for e in trace) + '\n')
    (root/'runs.jsonl').write_text('\n'.join(json.dumps(r) for r in runs) + '\n')
    return root/'trace.jsonl', root/'runs.jsonl'


def write_labels(path, sessions, reviewer='r1', flip=()):
    with open(path, 'w', newline='') as stream:
        w = csv.writer(stream)
        w.writerow(['session_id', 'reviewer', 'label', 'blind', 'review_seconds', 'notes'])
        for sid in sorted(sessions):
            actionable = sid.startswith('controlled-violation') != (sid in flip)
            w.writerow([sid, reviewer, 'actionable' if actionable else 'normal', 'yes', '30', ''])


class IndependentEvalTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.trace, self.runs = make_study_inputs(self.root)

    def tearDown(self):
        self.dir.cleanup()

    def split(self, **kw):
        opts = {'seed': 3, 'tune': 0.2, 'final': 0.3, 'keep_out': ['controlled-violation'], **kw}
        return ie.split(self.trace, self.runs, self.root/'study', 'family', **opts)

    def test_family_split_groups_never_straddle_and_keep_out_respected(self):
        m = self.split()
        seen = {}
        for sid, part in m['partition_of'].items():
            fam = m['session_family'][sid]
            self.assertEqual(seen.setdefault(fam, part), part)
        self.assertNotIn('controlled-violation', m['families']['baseline'])
        self.assertEqual(sum(m['counts'].values()), 160)
        self.assertGreaterEqual(m['counts']['baseline'], 30)
        packet = (self.root/'study/review_packet_final.jsonl').read_text()
        for leak in ('anomaly', 'rules', 'intent', 'task_family', 'review"'):
            self.assertNotIn(leak, packet)
        # Deterministic for the same seed and input.
        runs = [json.loads(line) for line in self.runs.read_text().splitlines()]
        again = ie.assign(runs, 'family',
                          seed=3, tune=0.2, final=0.3, keep_out=['controlled-violation'])
        self.assertEqual(again, m['partition_of'])

    def test_time_split_reports_family_spanning_partitions(self):
        runs = [{'session_id': 'a1', 'task_family': 'a', 'finished_at': '2026-12-01'},
                {'session_id': 'a2', 'task_family': 'a', 'finished_at': '2026-12-20'},
                {'session_id': 'b1', 'task_family': 'b', 'finished_at': '2026-12-21'}]
        out, leaked = ie.assign(runs, 'time', tune_after='2026-12-10', final_after='2026-12-15')
        self.assertEqual(out, {'a1': 'baseline', 'a2': 'final', 'b1': 'final'})
        self.assertEqual(leaked, ['a'])
        with self.assertRaises(ValueError):
            ie.assign(runs, 'time', tune_after='2026-12-10', final_after='2026-12-15', keep_out=['a'])

    def test_wilson_matches_reference_values(self):
        self.assertEqual(ie.wilson(0, 10), [0.0, 0.2775])
        self.assertEqual(ie.wilson(5, 10), [0.2366, 0.7634])
        self.assertIsNone(ie.wilson(0, 0))

    def test_final_requires_freeze_and_detects_later_changes(self):
        m = self.split()
        final = [s for s, p in m['partition_of'].items() if p == 'final']
        labels = self.root/'final.csv'
        write_labels(labels, final)
        with self.assertRaisesRegex(ValueError, 'freeze'):
            ie.evaluate_partition(self.root/'study', 'final', labels)
        ie.freeze(self.root/'study', ['docs.python.org'])
        with self.assertRaises(FileExistsError):
            ie.freeze(self.root/'study', ['other.example.com'])
        result = ie.evaluate_partition(self.root/'study', 'final', labels)
        self.assertEqual(result['final_scoring_count'], 1)
        with open(self.root/'study/final.jsonl', 'a') as stream:
            stream.write('\n')
        with self.assertRaisesRegex(ValueError, 'changed since freeze'):
            ie.evaluate_partition(self.root/'study', 'final', labels)

    def test_counts_match_hand_computed_confusion(self):
        m = self.split()
        final = sorted(s for s, p in m['partition_of'].items() if p == 'final')
        labels = self.root/'final.csv'
        normal = [s for s in final if not s.startswith('controlled-violation')]
        flipped = normal[:1]  # reviewer calls one ordinary run actionable
        write_labels(labels, final, flip=flipped)
        ie.freeze(self.root/'study', ['docs.python.org'])
        r = ie.evaluate_partition(self.root/'study', 'final', labels)['results']['rules_only']
        violations = sum(s.startswith('controlled-violation') for s in final)
        self.assertEqual(r['tp'], violations)               # unapproved host on every violation run
        self.assertEqual(r['fn'], len(flipped))             # ordinary run has no rule signal
        self.assertEqual(r['fp'], 0)
        self.assertEqual(r['tn'], len(normal) - len(flipped))

    def test_labels_disagreement_coverage_and_kappa(self):
        path = self.root/'l.csv'
        path.write_text('session_id,reviewer,label\ns1,a,normal\ns1,b,actionable\ns2,a,normal\ns2,b,normal\n')
        with self.assertRaisesRegex(ValueError, 'adjudication'):
            ie.read_labels(path)
        adj = self.root/'adj.csv'
        adj.write_text('session_id,label\ns1,actionable\n')
        labels, meta = ie.read_labels(path, adj, expect={'s1', 's2'})
        self.assertEqual(labels, {'s1': 'actionable', 's2': 'normal'})
        self.assertEqual(meta['agreement']['raw_agreement'], 0.5)
        with self.assertRaisesRegex(ValueError, 'cover exactly'):
            ie.read_labels(path, adj, expect={'s1', 's2', 's3'})
        bad = self.root/'bad.csv'
        bad.write_text('session_id,reviewer,label\ns1,a,malicious\n')
        with self.assertRaises(ValueError):
            ie.read_labels(bad)

    def test_tune_needs_no_freeze_and_cli_refuses_existing_outputs(self):
        m = self.split()
        tune = [s for s, p in m['partition_of'].items() if p == 'tune']
        write_labels(self.root/'tune.csv', tune)
        out = self.root/'tune.json'
        code = ie.main(['tune', '--study', str(self.root/'study'), '--labels', str(self.root/'tune.csv'),
                        '--allow-domain', 'docs.python.org', '--output', str(out)])
        self.assertEqual(code, 0)
        self.assertIn('combined', json.loads(out.read_text())['results'])
        code = ie.main(['tune', '--study', str(self.root/'study'), '--labels', str(self.root/'tune.csv'),
                        '--output', str(out)])
        self.assertEqual(code, 2)


if __name__ == '__main__':
    unittest.main()
