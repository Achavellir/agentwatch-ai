"""Single-process integration helper. Call AFTER an observed tool operation.
Approval and sensitivity must come from trusted application controls, not the LLM.
Only metadata is stored; do not pass prompts, credentials or response bodies.
"""
import json
from pathlib import Path
from uuid import uuid4
from urllib.parse import urlsplit, urlunsplit
from agentwatch import hostname, ALLOWED_TOOLS

class TraceWriter:
    def __init__(self, path, session_id):
        self.path = Path(path)
        self.session_id = session_id

    def record(self, tool, *, destination='', bytes_sent=0, sensitive=False, approved=False):
        if tool not in ALLOWED_TOOLS: raise ValueError('Unsupported tool')
        hostname(destination)
        if type(bytes_sent) is not int or bytes_sent < 0: raise ValueError('Invalid bytes_sent')
        if type(sensitive) is not bool or type(approved) is not bool: raise ValueError('Boolean required')
        # Strip paths, query parameters and fragments, which can contain secrets.
        parsed = urlsplit(destination)
        safe_url = urlunsplit((parsed.scheme, parsed.netloc, '', '', '')) if destination else ''
        event = dict(event_id=str(uuid4()),session_id=self.session_id,tool=tool,
                     destination=safe_url,bytes_sent=bytes_sent,sensitive=sensitive,approved=approved)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open('a') as stream: stream.write(json.dumps(event)+'\n')
        return event['event_id']
