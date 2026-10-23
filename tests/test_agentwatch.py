import json
import tempfile
import unittest
from pathlib import Path
from agentwatch import analyze, findings, hostname, load, render
from make_demo import main

class AgentWatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        root = Path(cls.temporary.name)
        main(root)
        cls.base = load(root/'baseline.jsonl')
        cls.candidate = load(root/'candidate.jsonl')
        cls.report = analyze(cls.base, cls.candidate, {'docs.example.com'})

    def parse(self, events):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'events.jsonl'
            path.write_text('\n'.join(json.dumps(e) for e in events))
            return load(path)

    def event(self): return dict(next(iter(self.base.values()))[0])

    def test_duplicate_rejected(self):
        with self.assertRaisesRegex(ValueError,'duplicate'): self.parse([self.event(),self.event()])

    def test_string_boolean_rejected(self):
        e=self.event(); e['approved']='false'
        with self.assertRaisesRegex(ValueError,'boolean'): self.parse([e])

    def test_negative_bytes_rejected(self):
        e=self.event(); e['bytes_sent']=-1
        with self.assertRaises(ValueError): self.parse([e])

    def test_missing_approval_rejected(self):
        e=self.event(); del e['approved']
        with self.assertRaises(ValueError): self.parse([e])

    def test_credential_url_rejected(self):
        with self.assertRaises(ValueError): hostname('https://user:secret@docs.example.com')

    def test_exact_domain_boundary(self):
        e=self.event(); e['destination']='https://docs.example.com.attacker.example.net'; e['_line']=1
        self.assertEqual(findings([e],{'docs.example.com'})[0]['rules'], ['UNAPPROVED_DESTINATION'])

    def test_baseline_leakage_rejected(self):
        with self.assertRaisesRegex(ValueError,'overlap'): analyze(self.base,self.base,{'docs.example.com'})

    def test_small_baseline_rejected(self):
        with self.assertRaisesRegex(ValueError,'30'): analyze(dict(list(self.base.items())[:5]),self.candidate,set())

    def test_sensitive_transfer_evidence(self):
        row=next(r for r in self.report['sessions'] if r['session_id']=='external-sensitive-transfer')
        self.assertIn('SENSITIVE_EXTERNAL_TRANSFER',row['findings'][0]['rules'])
        self.assertEqual(row['findings'][0]['event_id'],'external-sensitive-transfer-0')

    def test_volume_ml_independent_from_rules(self):
        row=next(r for r in self.report['sessions'] if r['session_id']=='high-volume-approved')
        self.assertTrue(row['anomaly']); self.assertFalse(row['findings'])

    def test_html_escape(self):
        import copy
        report=copy.deepcopy(self.report)
        report['sessions'][0]['session_id']='<script>alert(1)</script>'
        result=render(report)
        self.assertNotIn('<script>',result); self.assertIn('&lt;script&gt;',result)

    def test_deterministic(self):
        self.assertEqual(self.report,analyze(self.base,self.candidate,{'docs.example.com'}))

    def test_writer_removes_query_and_path(self):
        from trace_writer import TraceWriter
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'trace.jsonl'
            TraceWriter(p,'integration').record('http',destination='https://docs.example.com/private?token=secret#fragment',approved=True)
            self.assertNotIn('secret',p.read_text())
            self.assertNotIn('private',p.read_text())
            self.assertEqual(load(p)['integration'][0]['destination'],'https://docs.example.com')

    def test_writer_rejects_credentials(self):
        from trace_writer import TraceWriter
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                TraceWriter(Path(d)/'trace','x').record('http',destination='https://u:p@docs.example.com')

if __name__=='__main__': unittest.main()
