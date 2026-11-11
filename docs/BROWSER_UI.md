# Local browser review

Version 0.3.0 adds an optional local interface. It reviews saved logs using **policy rules only**. The existing command-line rules and optional ML workflows remain available. This is a single-user local pilot, not a public service or live monitoring system.

## Start

From your checkout, using Python 3.11 or newer:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
agentwatch-ui --open
```

Open the exact `http://127.0.0.1:PORT` address printed in Terminal if the browser does not open. The default selects an available port. `agentwatch-ui --port 8765` chooses a fixed port. Do not use `localhost`, expose the process through a proxy/tunnel, or bind it to a public network. The listener is fixed to 127.0.0.1. Stop it with Ctrl+C.

## Review your own activity

1. Choose a UTF-8 JSONL file with compatible events. Selecting a file alone does not send it to the local server.
2. Enter one approved ASCII hostname per line. Schemes, paths, ports and wildcards are rejected. Exact subdomains must be listed separately. An empty list flags all recorded network destinations.
3. Click **Check activity**. This sends the selected content to the loopback server on your computer.
4. Read the session counts, reasons for review and event IDs with source-line references. The default filter shows only sessions needing review; uncheck it to see other sessions.
5. Download the HTML or JSON report if needed. Click **Clear results** when finished.

Browser limits: 2 MB per file, 2,000 sessions, 20,000 events and 100 approved hostnames. The CLI continues to support 10 MB inputs. Large event lists are shown incrementally; all evidence is included in downloads.

The **Try a sample review** button uses three visibly labeled synthetic sessions: an approved request, a sensitive transfer to an unapproved destination and a write without recorded approval. Two sessions require review. This is a teaching example, not real-agent validation. You can download the sample file and select it to exercise the upload path.

## Input and interpretation

Each line is one event. For example:

```json
{"event_id":"event-1","session_id":"session-1","tool":"http","destination":"https://docs.example.com","bytes_sent":50,"sensitive":false,"approved":true}
```

The existing [input contract](LOCAL_RELEASE.md) applies. AgentWatch does not automatically capture activity; integrate the trace writer or map your own application logs. Approval and sensitivity flags must come from trusted application controls. A policy finding needs human investigation. No policy findings does not prove safety. The browser does not assess behavioral anomalies; use the CLI and a reviewed representative baseline for optional ML.

## Privacy and security boundary

- Uploaded content and generated results are processed in memory. The server has no upload directory, report store, directory listing or arbitrary file-read endpoint. Access logging is disabled.
- Downloads are ordinary browser-managed files, not the CLI's permission-controlled output directories. Protect those files and review them before sharing.
- The application uses no browser storage or external assets. Memory, browser extensions, OS swap and other processes on the same computer are outside this guarantee. Clearing results is not secure memory erasure.
- Exact Host validation, exact Origin validation, a per-process request token and Fetch Metadata checks reject cross-site review requests. Tokens are not placed in URLs. Responses are not CORS-enabled, use no-store caching and disallow embedding.
- The UI uses a strict content security policy with external same-origin script and stylesheet files. Untrusted identifiers are inserted as text, not markup. Exported HTML retains the existing escaped renderer.
- Request sizes, file sizes, event/session counts, concurrent connections and simultaneous analyses are bounded. This is not designed to withstand a hostile local process or provide multi-user authentication.
- URLs in activity records are inspected as text; the analyzer does not fetch them or execute recorded actions.

## Verification

```sh
python -m unittest discover -s tests -v
python evaluate.py
python -m pip wheel --no-deps --wheel-dir dist .
python -m pip install --force-reinstall --no-deps dist/agentwatch_local-0.3.0-py3-none-any.whl
python scripts/check_installed.py
```

`scripts/check_browser.cjs` provides developer-only browser tests using Playwright and axe-core. Install those in a separate temporary development environment and expose its modules through `NODE_PATH`. Run against the local server using `AGENTWATCH_URL`; `CHROME_PATH` optionally selects a Chrome executable and `QA_OUTPUT` chooses the artifact directory. These are test dependencies, not application requirements. The test generates its own synthetic uploads, exercises downloads and errors, checks three viewport widths and runs automated accessibility checks. See [the review record](BROWSER_REVIEW.md) for results and remaining limitations.
