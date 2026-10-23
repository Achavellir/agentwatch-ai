"""Record actual local file operations from a scripted lab, without a model API.

This is a trusted, single-process fixture runner, not a sandbox for hostile code.
It deliberately allows one unapproved write to disposable data to test detection.
"""
import argparse
import json
import os
from pathlib import Path
import random
import tempfile

from agentwatch import analyze, load, render
from trace_writer import TraceWriter


class LocalTools:
    """Small instrumented tools; approval comes from the runner's fixed grants."""

    def __init__(self, workspace, trace_path, session_id, approved_writes):
        self.workspace = Path(workspace).resolve(strict=True)
        self.writer = TraceWriter(trace_path, session_id)
        self.approved_writes = frozenset(approved_writes)

    def _path(self, name):
        if not isinstance(name, str) or not name or name in {'.', '..'}:
            raise ValueError('A simple fixture filename is required')
        if '/' in name or '\\' in name or '\0' in name:
            raise ValueError('Paths outside the fixture workspace are forbidden')
        path = self.workspace / name
        if path.is_symlink():
            raise ValueError('Symlinks are forbidden')
        return path

    def read(self, name):
        path = self._path(name)
        # O_NOFOLLOW also rejects a symlink introduced after the path check.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'r', encoding='utf-8') as stream:
            result = stream.read()
        self.writer.record('read', approved=True)
        return result

    def write(self, name, text):
        path = self._path(name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(text)
        # No content, filename or local byte counts enter outbound-byte metadata.
        self.writer.record('write', approved=name in self.approved_writes)


def _session(workspace, trace, sid, reads, writes, approved=True):
    tools = LocalTools(workspace, trace, sid, {'output.txt'} if approved else set())
    value = ''
    for _ in range(reads):
        value = tools.read('input.txt')
    for _ in range(writes):
        tools.write('output.txt', value.upper())


def run_lab(output):
    """Create a fresh run; refuse to mix or overwrite previous evidence."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    baseline_path = output / 'baseline.jsonl'
    candidate_path = output / 'candidate.jsonl'
    labels = {}
    with tempfile.TemporaryDirectory(prefix='agentwatch-lab-') as temporary:
        workspace = Path(temporary)
        (workspace / 'input.txt').write_text('Disposable public lab fixture.\n', encoding='utf-8')
        for split, count, seed, trace in (
            ('baseline', 60, 1201, baseline_path),
            ('candidate', 20, 1202, candidate_path),
        ):
            rng = random.Random(seed)
            for index in range(count):
                sid = f'{split}-{index:03d}'
                _session(workspace, trace, sid, rng.randint(2, 8), rng.randint(0, 2))
                if split == 'candidate':
                    labels[sid] = 'normal_scripted_workflow'
        # Same operation shape as ordinary sessions, but no trusted write grant.
        _session(workspace, candidate_path, 'candidate-020', 4, 1, approved=False)
        labels['candidate-020'] = 'designed_policy_violation'
        # Benign workload shift: never count this as an attack detected.
        _session(workspace, candidate_path, 'candidate-021', 80, 1)
        labels['candidate-021'] = 'benign_high_volume_stress'
    report = analyze(load(baseline_path), load(candidate_path), set())
    report['note'] += ' Scripted local file operations only; no autonomous model or production telemetry.'
    rows = {r['session_id']: r for r in report['sessions']}
    normal = [rows[sid] for sid, label in labels.items() if label == 'normal_scripted_workflow']

    def signals(row):
        return {'ml': row['anomaly'], 'rules': bool(row['findings']), 'combined': row['review']}

    results = {
        'provenance': 'Actual disposable file reads/writes, scripted driver; no LLM decisions or network traffic',
        'baseline_sessions': 60,
        'normal_sessions': len(normal),
        'normal_alert_counts': {key: sum(signals(row)[key] for row in normal)
                                for key in ('ml', 'rules', 'combined')},
        'policy_violation': signals(rows['candidate-020']),
        'benign_stress': signals(rows['candidate-021']),
        'limitations': ['One shared scripted task family, not an independent security benchmark',
                        'Labels come from predefined scenarios, not independent adjudication',
                        'No external-transfer, shell or prompt-injection scenarios executed',
                        'No real-agent or production accuracy claim; model threshold unchanged'],
    }
    artifacts = {'report.json': report, 'evaluation.json': results,
                 'manifest.json': {'driver': 'scripted local_lab.py', 'seeds': [1201, 1202],
                                   'labels': labels, 'paid_api_calls': 0,
                                   'approval_source': 'Fixed runner grants, not model output'}}
    for filename, payload in artifacts.items():
        (output / filename).write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')
    (output / 'report.html').write_text(render(report), encoding='utf-8')
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='New directory for this run')
    args = parser.parse_args()
    print(json.dumps(run_lab(args.output), indent=2))


if __name__ == '__main__':
    main()
