"""One real HTTPS request, automatic metadata recording, two policy reviews.

Run from the repository: python -m scripts.web_demo --output private-data/web-demo
This is a scripted integration demonstration, not an autonomous AI agent.
"""
import argparse
import http.client
import json
import os
from pathlib import Path
from uuid import uuid4

from agentwatch import analyze_rules, load, write_reports
from trace_writer import TraceWriter

HOST = 'www.python.org'
MAX_RESPONSE = 1024 * 1024


class CountedHTTPS(http.client.HTTPSConnection):
    """Count HTTP bytes handed successfully to TLS, excluding TLS overhead."""
    request_bytes = 0

    def send(self, data):
        super().send(data)
        self.request_bytes += len(data)


def fetch_public_page():
    # Fixed public destination, no credentials, cookies, user data or redirects.
    conn = CountedHTTPS(HOST, timeout=15)
    try:
        conn.request('GET', '/', headers={'User-Agent': 'AgentWatch-local-demo/0.3', 'Connection': 'close'})
        response = conn.getresponse()
        if response.status != 200:
            raise ValueError(f'Demo expected HTTP 200; received {response.status}. No redirect followed.')
        content = response.read(MAX_RESPONSE + 1)
        if len(content) > MAX_RESPONSE:
            raise ValueError('Response exceeds the demo size limit.')
        return dict(status=response.status, request_bytes=conn.request_bytes, response_bytes=len(content))
    finally:
        conn.close()


def private_write(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        stream.write(content)


def run_demo(output):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir(mode=0o700, exist_ok=False)
    receipt = fetch_public_page()
    trace = output / 'activity.jsonl'
    private_write(trace, '')
    TraceWriter(trace, 'web-demo-' + uuid4().hex).record(
        'http', destination='https://' + HOST, bytes_sent=receipt['request_bytes'],
        sensitive=False, approved=True)
    events = load(trace)
    write_reports(analyze_rules(events, {HOST}), output / 'approved')
    write_reports(analyze_rules(events, {'docs.python.org'}), output / 'unapproved')
    receipt.update(destination='https://' + HOST, driver='scripted HTTPS GET, not an autonomous AI agent',
                   note='Same recorded request reviewed twice. The second policy intentionally omits its host. No website vulnerability scan.')
    private_write(output / 'receipt.json', json.dumps(receipt, indent=2) + '\n')
    private_write(output / 'COMPLETE', 'Both policy reviews completed.\n')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='New output directory; existing paths are rejected')
    args = parser.parse_args()
    try:
        receipt = run_demo(args.output)
    except (OSError, ValueError, http.client.HTTPException) as error:
        parser.exit(1, f'Demo incomplete: {error}. Use a new output directory when retrying.\n')
    print(f"HTTP {receipt['status']}; recorded {receipt['request_bytes']} outbound HTTP bytes.")
    print(f'Open {Path(args.output) / "approved/report.html"}: approved destination, no policy finding.')
    print(f'Open {Path(args.output) / "unapproved/report.html"}: same visit, destination outside the second policy.')
    print('This demonstrates activity review, not website security or real-agent detection accuracy.')


if __name__ == '__main__':
    main()
