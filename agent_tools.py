"""Record an agent's tool calls at the point where they really execute.

Wrap each tool function the agent can call. The wrapper asks a trusted
application policy (never the model) whether the call is approved and whether
it touches sensitive data, runs the tool, then appends one metadata event with
the outcome: ok, error or denied. Denied calls are recorded but not executed.

Only metadata is stored: tool category, scheme+host, outgoing byte count,
booleans, outcome, sequence number, UTC start time and duration. Never pass
prompts, credentials, file contents or response bodies into the trace.

Limits (unchanged from TraceWriter): the producer can still omit or forge
events; a hostile process with the same OS user can edit the files; this is a
single-process recorder. The session sidecar lets a reviewer detect gaps,
truncation and sessions that never closed, not deliberate forgery.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading
import time
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from agentwatch import ALLOWED_TOOLS, hostname, validate_event


@dataclass(frozen=True)
class Decision:
    """Trusted answer from the application, computed before the tool runs."""
    approved: bool
    sensitive: bool = False
    allow: bool = True          # False => do not execute; record status 'denied'
    reason: str = ''            # kept in memory for the caller; never written


class Policy:
    """Override decide(). The default approves nothing and marks nothing sensitive."""

    def decide(self, tool, call, state):
        return Decision(approved=False, sensitive=False, allow=tool not in {'write', 'shell'})


@dataclass
class PathPolicy(Policy):
    """A small, explicit policy for file and HTTP tools in a sandbox directory.

    - Reads under `sensitive_dirs` are sensitive.
    - With `taint=True`, once a sensitive read has happened, later outbound HTTP
      in the same session is marked sensitive (conservative data-flow proxy).
    - Writes are approved only inside `writable_dirs`; others are denied.
    - Shell is never approved or executed.
    - HTTP to hosts outside `network_hosts` is denied unless `network='any'`.
      Denied attempts are still recorded so policy rules can see them.
    """
    root: Path
    writable_dirs: tuple = ()
    sensitive_dirs: tuple = ()
    network_hosts: frozenset = frozenset()
    network: str = 'allowlist'   # 'off' | 'allowlist' | 'any'
    taint: bool = True

    def _inside(self, path, dirs):
        target = (self.root/path).resolve()
        return any(target.is_relative_to((self.root/d).resolve()) for d in dirs)

    def decide(self, tool, call, state):
        if tool == 'shell':
            return Decision(approved=False, allow=False, reason='shell disabled')
        if tool in {'read', 'search'}:
            sensitive = self._inside(call.get('path', '.'), self.sensitive_dirs)
            return Decision(approved=True, sensitive=sensitive)
        if tool == 'write':
            ok = self._inside(call.get('path', ''), self.writable_dirs)
            return Decision(approved=ok, allow=ok, reason='' if ok else 'outside writable dirs')
        if tool == 'http':
            host = hostname(call.get('url', ''))
            if self.network == 'off':
                allowed = False
            else:
                allowed = self.network == 'any' or host in self.network_hosts
            sensitive = self.taint and state.get('sensitive_read', False)
            return Decision(approved=host in self.network_hosts, sensitive=sensitive, allow=allowed)
        return Decision(approved=False, allow=False, reason='unknown tool')


def scheme_and_host(url):
    """Keep only scheme://host[:port]; paths and queries can hold secrets."""
    if not url:
        return ''
    hostname(url)  # rejects non-HTTP(S) and embedded credentials
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, '', '', ''))


class ToolRecorder:
    """Append-only, private (0600) trace plus a per-session completeness sidecar."""

    def __init__(self, trace_path, session_id, policy=None):
        if not isinstance(session_id, str) or not 0 < len(session_id) <= 200:
            raise ValueError('invalid session_id')
        self.trace_path = Path(trace_path)
        self.sidecar_path = self.trace_path.with_name(self.trace_path.name + '.sessions.jsonl')
        self.session_id = session_id
        self.policy = policy or Policy()
        self.state = {'sensitive_read': False}
        self._seq = 0
        self._lock = threading.Lock()
        self._closed = False
        self.trace_path.parent.mkdir(parents=True, exist_ok=True)
        self._sidecar({'session_id': session_id, 'event': 'open', 'ts': _now()})

    def _append(self, path, record):
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, 'a', encoding='utf-8') as stream:
            stream.write(json.dumps(record, sort_keys=True) + '\n')
            stream.flush()
            os.fsync(stream.fileno())

    def _sidecar(self, record):
        self._append(self.sidecar_path, record)

    def wrap(self, tool, fn, *, describe, bytes_after=None):
        """Return a callable that records `fn`.

        describe(**kwargs) -> dict with optional 'path', 'url' and 'bytes_sent'
        computed by the application from the real arguments (not model claims).
        bytes_after() -> int, if given, replaces bytes_sent with the count the
        tool actually measured, read after the call (also on error).
        """
        if tool not in ALLOWED_TOOLS:
            raise ValueError('unsupported tool')

        def recorded(**kwargs):
            try:
                call = describe(**kwargs)
                destination = scheme_and_host(call.get('url', ''))
                decision = self.policy.decide(tool, call, dict(self.state))
                sent = int(call.get('bytes_sent', 0))
            except (ValueError, TypeError, OSError) as exc:
                # Unusable arguments (e.g. a non-HTTP URL or embedded credentials):
                # do not execute, record the attempt without a destination.
                self._record(tool, destination='', bytes_sent=0, sensitive=False, approved=False,
                             status='denied', ts=_now(), duration_ms=0)
                raise PermissionError(f'{tool} call rejected: {exc}') from exc
            start, clock = _now(), time.monotonic()
            status, result, error = 'denied', None, None
            if decision.allow:
                try:
                    result = fn(**kwargs)
                    status = 'ok'
                except Exception as exc:  # recorded, then re-raised to the agent loop
                    status, error = 'error', exc
                if bytes_after is not None:
                    sent = int(bytes_after())
            if status == 'ok' and tool in {'read', 'search'} and decision.sensitive:
                self.state['sensitive_read'] = True
            self._record(tool, destination=destination,
                         bytes_sent=sent if status != 'denied' else 0,
                         sensitive=decision.sensitive, approved=decision.approved,
                         status=status, ts=start,
                         duration_ms=int((time.monotonic() - clock) * 1000))
            if error is not None:
                raise error
            if status == 'denied':
                raise PermissionError(decision.reason or f'{tool} call denied by policy')
            return result

        recorded.__name__ = getattr(fn, '__name__', tool)
        return recorded

    def _record(self, tool, **fields):
        with self._lock:
            if self._closed:
                raise RuntimeError('session already closed')
            event = dict(event_id=str(uuid4()), session_id=self.session_id, tool=tool,
                         seq=self._seq, **fields)
            validate_event(event)
            self._append(self.trace_path, event)
            self._seq += 1

    def close(self, outcome='finished'):
        """Write the closing record with the number of events written."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._sidecar({'session_id': self.session_id, 'event': 'close', 'ts': _now(),
                           'events': self._seq, 'outcome': str(outcome)[:40]})

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close('finished' if exc_type is None else f'aborted:{exc_type.__name__}')
        return False


def check_completeness(trace_path, sidecar_path=None):
    """Compare recorded events with each session's open/close sidecar.

    Detects: sessions never closed, event-count mismatch, sequence gaps or
    duplicates, and events for sessions that were never opened. It cannot
    detect a producer that skipped calling the wrapper or forged both files.
    """
    trace_path = Path(trace_path)
    sidecar_path = Path(sidecar_path or trace_path.with_name(trace_path.name + '.sessions.jsonl'))
    seqs, opened, closed = {}, set(), {}
    trace_text = trace_path.read_text(encoding='utf-8') if trace_path.exists() else ''
    for line in trace_text.splitlines():
        if line.strip():
            event = json.loads(line)
            seqs.setdefault(event['session_id'], []).append(event.get('seq'))
    for line in sidecar_path.read_text(encoding='utf-8').splitlines():
        if line.strip():
            record = json.loads(line)
            if record['event'] == 'open':
                opened.add(record['session_id'])
            elif record['event'] == 'close':
                closed[record['session_id']] = record
    sessions = {}
    for sid in sorted(opened | set(seqs)):
        found = seqs.get(sid, [])
        problems = []
        if sid not in opened:
            problems.append('events without open record')
        if sid not in closed:
            problems.append('session not closed')
        elif closed[sid]['events'] != len(found):
            problems.append(f"closed with {closed[sid]['events']} events, {len(found)} found")
        if None in found:
            problems.append('events without seq')
        else:
            expected = closed[sid]['events'] if sid in closed else (max(found) + 1 if found else 0)
            missing = sorted(set(range(expected)) - set(found))
            if missing:
                problems.append(f'missing seq {missing[:10]}')
            if len(found) != len(set(found)):
                problems.append('duplicate seq')
        sessions[sid] = {'events': len(found), 'complete': not problems, 'problems': problems,
                         'outcome': closed.get(sid, {}).get('outcome')}
    total = len(sessions)
    return {'sessions': sessions, 'session_count': total,
            'incomplete_sessions': sum(not s['complete'] for s in sessions.values())}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')
