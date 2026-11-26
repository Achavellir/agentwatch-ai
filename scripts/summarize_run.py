"""Summarize one agent run for its author: tool use, outcomes, completeness, findings.

    python -m scripts.summarize_run private-data/agent-run-1

Reads runs.jsonl, activity.jsonl, completeness.json and review/report.json in the
run folder and writes summary.md there. This is a pilot check of the setup. It shows
each task's design intent, so it is NOT a blind review: collect fresh runs for the
independent study (docs/INDEPENDENT_EVALUATION.md).
"""
from collections import Counter, defaultdict
import json
import os
from pathlib import Path
import sys


def _jsonl(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def summarize(run_dir, tasks_path=None):
    run_dir = Path(run_dir)
    runs = _jsonl(run_dir / 'runs.jsonl')
    if not runs:
        raise ValueError(f'no runs.jsonl in {run_dir}')
    events = _jsonl(run_dir / 'activity.jsonl')
    completeness = json.loads((run_dir / 'completeness.json').read_text()) if (run_dir / 'completeness.json').exists() else None
    report_path = run_dir / 'review' / 'report.json'
    report = json.loads(report_path.read_text()) if report_path.exists() else {'sessions': []}
    intents = {}
    if tasks_path and Path(tasks_path).exists():
        intents = {t['id']: t.get('intent', '') for t in json.loads(Path(tasks_path).read_text())}

    by_session = defaultdict(list)
    for e in events:
        by_session[e['session_id']].append(e)
    reviewed = {s['session_id']: s for s in report.get('sessions', [])}

    per_task = defaultdict(lambda: {'runs': 0, 'calls': [], 'stops': Counter(), 'status': Counter(),
                                    'flagged': 0, 'rules': Counter(), 'family': '', 'model': ''})
    for run in runs:
        t = per_task[run['task_id']]
        t['runs'] += 1
        t['family'], t['model'] = run.get('task_family', ''), run.get('model', '')
        t['stops'][run.get('stop', '?')] += 1
        evs = by_session.get(run['session_id'], [])
        t['calls'].append(len(evs))
        t['status'].update(e.get('status', 'ok') for e in evs)
        s = reviewed.get(run['session_id'])
        if s and s.get('review'):
            t['flagged'] += 1
        for f in (s or {}).get('findings', []):
            t['rules'].update(f.get('rules', []))

    total_runs = len(runs)
    no_tools = sum(1 for r in runs if not by_session.get(r['session_id']))
    lines = ['# Agent run summary (pilot, not blind)', '',
             f'- Run folder: `{run_dir}`',
             f"- Model: {runs[0].get('model', 'unknown')}",
             f'- Sessions: {total_runs}; tool calls recorded: {len(events)}',
             f'- Sessions with no tool calls at all: {no_tools}']
    if completeness:
        lines.append(f"- Incomplete traces: {completeness['incomplete_sessions']} of {completeness['session_count']}")
    lines.append(f"- Sessions flagged for review (rules only): {sum(1 for s in report.get('sessions', []) if s.get('review'))}")
    lines += ['', '| Task | Intent | Runs | Avg tool calls | Stops | Outcomes | Flagged | Rules fired |',
              '|---|---|---:|---:|---|---|---:|---|']
    for task_id in sorted(per_task, key=lambda k: (intents.get(k, '') != 'normal', k)):
        t = per_task[task_id]
        avg = sum(t['calls']) / len(t['calls']) if t['calls'] else 0
        fmt = lambda c: ', '.join(f'{k} {v}' for k, v in sorted(c.items())) or '-'
        lines.append(f"| {task_id} | {intents.get(task_id, '') or '-'} | {t['runs']} | {avg:.1f} | {fmt(t['stops'])} | "
                     f"{fmt(t['status'])} | {t['flagged']} | {fmt(t['rules'])} |")
    lines += ['', 'Notes: "denied" calls were refused by policy and never executed. A task that the model',
              'answered without calling tools is a model-behaviour result, not an AgentWatch result.']
    return '\n'.join(lines) + '\n'


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print(__doc__)
        return 2
    run_dir = Path(argv[0])
    tasks = argv[1] if len(argv) > 1 else 'examples/study_tasks.json'
    try:
        text = summarize(run_dir, tasks)
    except (ValueError, OSError, KeyError) as error:
        print(f'summarize_run: {error}')
        return 2
    out = run_dir / 'summary.md'
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        stream.write(text)
    print(text)
    print(f'Saved {out}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
