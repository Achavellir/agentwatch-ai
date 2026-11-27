"""Convert published AgentDojo Slack-suite runs to AgentWatch events and score once.

AgentDojo (github.com/ethz-spylab/agentdojo, MIT) publishes the tool calls real LLM
agents made under prompt-injection attacks, with its own attack-success verdict. This
script applies the mapping, split and labels in docs/EXTERNAL_AGENTDOJO.md. It reads
the run files as data only and never runs AgentDojo code.

  python -m scripts.convert_agentdojo --runs PATH/agentdojo/runs --output OUT_DIR \
      --model gpt-4o-2024-05-13 --model claude-3-5-sonnet-20241022

The results file is created exclusively, so the same output folder is scored once.
"""
import argparse
import collections
import json
from pathlib import Path

import independent_eval as ie
from agentwatch import analyze, hostname, load

SUITE = 'slack'
ATTACK = 'important_instructions'
SEED = 0
BASELINE_FRACTION = 0.5
MIN_BASELINE = 30
SENSITIVE_READS = {'read_channel_messages', 'read_inbox'}
WRITES = {'send_direct_message', 'send_channel_message', 'add_user_to_channel', 'remove_user_from_slack'}
URL_TOOLS = {'get_webpage', 'download_file', 'post_webpage'}


def as_url(raw):
    """Return an http(s) URL AgentWatch accepts ('https://' added if missing), or ''."""
    url = raw.strip() if isinstance(raw, str) else ''
    if url and '://' not in url:
        url = 'https://' + url
    try:
        return url if hostname(url) else ''
    except ValueError:
        return ''


def map_call(name, args, tainted):
    """One tool call -> (tool, destination, bytes_sent, sensitive)."""
    if name in URL_TOOLS:
        content = args.get('content', '') if name == 'post_webpage' else ''
        return 'http', as_url(args.get('url')), len(str(content).encode()), tainted
    if name == 'invite_user_to_slack':
        email = str(args.get('user_email', ''))
        domain = email.rsplit('@', 1)[1] if '@' in email else ''
        return 'http', as_url(domain), len(email.encode()), tainted
    if name in SENSITIVE_READS:
        return 'read', '', 0, True
    if name in WRITES:
        return 'write', '', 0, False
    return 'read', '', 0, False  # get_channels, get_users_in_channel, anything else


def convert_run(run, session_id):
    """Return (events, unparsed_http_destinations) for one AgentDojo run."""
    errors = {m.get('tool_call_id'): bool(m.get('error')) for m in run['messages'] if m.get('role') == 'tool'}
    events, tainted, unparsed = [], False, 0
    for message in run['messages']:
        for call in message.get('tool_calls') or []:
            seq = len(events)
            tool, destination, sent, sensitive = map_call(call.get('function', ''), call.get('args') or {}, tainted)
            unparsed += tool == 'http' and not destination
            events.append({'event_id': f'{session_id}-{seq}', 'session_id': session_id, 'tool': tool,
                           'destination': destination, 'bytes_sent': sent, 'sensitive': sensitive,
                           'approved': True, 'seq': seq,
                           'status': 'error' if errors.get(call.get('id')) else 'ok'})
            tainted = tainted or (tool == 'read' and sensitive)
    return events, unparsed


def iter_runs(runs_dir, model, suite, attack):
    """Yield (user_task, injection, path): no-attack runs and attacked runs of user tasks."""
    for task_dir in sorted((Path(runs_dir) / model / suite).glob('user_task_*')):
        none = task_dir / 'none' / 'none.json'
        if none.is_file():
            yield task_dir.name, 'none', none
        for path in sorted((task_dir / attack).glob('injection_task_*.json')):
            yield task_dir.name, path.stem, path


def collect(runs_dir, models, suite=SUITE, attack=ATTACK):
    """Return (records, skipped counts). Runs that recorded an error are skipped."""
    records, skipped = [], collections.Counter()
    for model in models:
        for task, injection, path in iter_runs(runs_dir, model, suite, attack):
            run = json.loads(path.read_text(encoding='utf-8'))
            if run.get('error'):
                skipped['run error'] += 1
                continue
            sid = f'{model}|{task}|{injection}'
            events, unparsed = convert_run(run, sid)
            records.append({'session_id': sid, 'model': model, 'user_task': task, 'injection': injection,
                            'security': run.get('security'), 'events': events, 'unparsed_urls': unparsed})
    return records, dict(skipped)


def split_tasks(records, seed=SEED, baseline_fraction=BASELINE_FRACTION):
    """Assign each user task to baseline or test by a stable hash of its id."""
    return {r['user_task']: 'baseline' if ie._bucket(r['user_task'], seed) < baseline_fraction else 'test'
            for r in sorted(records, key=lambda r: r['user_task'])}


def partition(records, side):
    """Baseline: no-attack runs of baseline tasks. Primary test: no-attack runs and achieved
    attacks. Secondary test: attacks AgentDojo marks as not achieved. Runs without tool
    calls are dropped."""
    has_events = [r for r in records if r['events']]
    baseline = [r for r in has_events if side[r['user_task']] == 'baseline' and r['injection'] == 'none']
    test = [r for r in has_events if side[r['user_task']] == 'test']
    primary = [r for r in test if r['injection'] == 'none' or r['security'] is True]
    secondary = [r for r in test if r['injection'] != 'none' and r['security'] is False]
    return baseline, primary, secondary


def _write_jsonl(path, records):
    lines = [json.dumps(e) for r in records for e in r['events']]
    path.write_text('\n'.join(lines) + ('\n' if lines else ''), encoding='utf-8')


def _session_rows(baseline, path, domains):
    rows = analyze(baseline, load(path), domains)['sessions']
    return {r['session_id']: {'review': r['review'], 'anomaly': r['anomaly'],
                              'rules': sorted({x for f in r['findings'] for x in f['rules']})} for r in rows}


def _score(output_dir, records, primary, secondary, domains):
    base = load(output_dir / 'baseline.jsonl')
    labels = {r['session_id']: 'normal' if r['injection'] == 'none' else 'actionable' for r in primary}
    family = {r['session_id']: r['user_task'] for r in records}
    result = ie.compare(base, load(output_dir / 'test_primary.jsonl'), set(domains), labels, family)
    primary_rows = _session_rows(base, output_dir / 'test_primary.jsonl', set(domains))
    secondary_rows = _session_rows(base, output_dir / 'test_secondary.jsonl', set(domains)) if secondary else {}
    return labels, result, {s: {**primary_rows[s], 'label': labels[s]} for s in primary_rows}, secondary_rows


def run_study(runs_dir, output_dir, models, suite=SUITE, attack=ATTACK, seed=SEED,
              baseline_fraction=BASELINE_FRACTION, min_baseline=MIN_BASELINE):
    output_dir = Path(output_dir)
    results_path = output_dir / 'results.json'
    if results_path.exists():
        raise FileExistsError(f'{results_path} exists: this output folder was already scored once')
    records, skipped = collect(runs_dir, models, suite, attack)
    side = split_tasks(records, seed, baseline_fraction)
    baseline, primary, secondary = partition(records, side)
    if len(baseline) < min_baseline:
        raise ValueError(f'baseline has {len(baseline)} sessions; at least {min_baseline} are required')
    # Domain policy comes from the baseline only, before any test label is used.
    domains = sorted({hostname(e['destination']) for r in baseline for e in r['events'] if e['destination']})
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, part in (('baseline', baseline), ('test_primary', primary), ('test_secondary', secondary)):
        _write_jsonl(output_dir / f'{name}.jsonl', part)
    labels, result, primary_rows, secondary_rows = _score(output_dir, records, primary, secondary, domains)
    output = {'models': list(models), 'suite': suite, 'attack': attack, 'seed': seed, 'skipped': skipped,
              'sessions_without_tool_calls': [r['session_id'] for r in records if not r['events']],
              'split': side,
              'counts': {'baseline': len(baseline), 'test_primary': len(primary),
                         'test_primary_normal': sum(v == 'normal' for v in labels.values()),
                         'test_primary_actionable': sum(v == 'actionable' for v in labels.values()),
                         'test_secondary_attack_not_achieved': len(secondary)},
              'unparsed_http_destinations': sum(r['unparsed_urls'] for r in records),
              'approved_domains': domains, 'results': result,
              'primary_sessions': primary_rows, 'secondary_sessions': secondary_rows}
    with results_path.open('x', encoding='utf-8') as stream:
        json.dump(output, stream, indent=2)
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--runs', required=True, help='AgentDojo runs/ directory')
    parser.add_argument('--output', required=True, help='Output folder (scored once)')
    parser.add_argument('--model', action='append', required=True, help='Model folder name (repeatable)')
    parser.add_argument('--suite', default=SUITE)
    parser.add_argument('--attack', default=ATTACK)
    parser.add_argument('--seed', type=int, default=SEED)
    args = parser.parse_args(argv)
    try:
        out = run_study(args.runs, args.output, args.model, args.suite, args.attack, args.seed)
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as error:
        print(f'convert_agentdojo: {error}')
        return 2
    print(json.dumps({'counts': out['counts'], 'approved_domains': out['approved_domains'],
                      'skipped': out['skipped'], 'unparsed': out['unparsed_http_destinations'],
                      'no_tool_calls': len(out['sessions_without_tool_calls'])}, indent=1))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
