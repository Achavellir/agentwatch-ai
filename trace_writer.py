"""Single-process integration helper. Call AFTER an observed tool operation.
Approval and sensitivity must come from trusted application controls, not the LLM.
Only metadata is stored; do not pass prompts, credentials or response bodies.
"""
import json
from pathlib import Path
from uuid import uuid4
from urllib.parse import urlsplit, urlunsplit
from agentwatch import validate_event

class TraceWriter:
    def __init__(self, path, session_id):
        self.path = Path(path)
        self.session_id = session_id

    def record(self, tool, *, destination='', bytes_sent=0, sensitive=False, approved=False):
        event = dict(event_id=str(uuid4()), session_id=self.session_id, tool=tool,
                     destination=destination, bytes_sent=bytes_sent,
                     sensitive=sensitive, approved=approved)
        validate_event(event)
        # Strip paths, query parameters and fragments, which can contain secrets.
        parsed = urlsplit(destination)
        safe_url = urlunsplit((parsed.scheme, parsed.netloc, '', '', '')) if destination else ''
        event['destination'] = safe_url
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open('a') as stream: stream.write(json.dumps(event)+'\n')
        return event['event_id']
