# AgentWatch AI

**Local machine-learning triage for AI-agent tool activity.** Built with AI assistance for Rishi Achavelli's security engineering portfolio.

AgentWatch reads JSONL tool-event metadata, learns a baseline with Isolation Forest, and combines unusual-behavior signals with independent policy rules. It produces an offline HTML report and machine-readable JSON with event IDs and source-line evidence. It never runs tools, blocks traffic, sends messages, or contacts a model API.

## Why this project

Tool-using AI systems introduce security risks at the boundary between model suggestions and real actions. Current guidance stresses constrained tools, trusted authorization and layered defenses. This project explores a **detective** control for that boundary. It cannot identify the prompt that caused a behavior or prevent prompt injection.

Research reviewed October 6, 2026:
- [Anthropic: Trustworthy agents in practice](https://www.anthropic.com/research/trustworthy-agents)
- [OWASP MCP Top 10](https://owasp.org/projects/mcp-top-10?tab=top10)
- [OpenAI: Designing agents to resist prompt injection](https://openai.com/index/designing-agents-to-resist-prompt-injection/)
- [scikit-learn Isolation Forest](https://scikit-learn.org/1.7/modules/generated/sklearn.ensemble.IsolationForest.html)

## Run locally

Python 3.11+ is required. Install the local command in a virtual environment:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
agentwatch --version
agentwatch --rules-only --input examples/candidate.jsonl --allow-domain docs.example.com --output reports/first-local-run
```

Open `reports/first-local-run/report.html`. Choose a new directory for each run: existing paths are rejected to preserve evidence. Reports remain on your computer. No server, API key or paid service is needed. Installation downloads Python dependencies; analysis runs offline.

For optional ML, replace `--rules-only` with `--baseline examples/baseline.jsonl`. Use a representative reviewed baseline for real logs; bundled fixtures are only a demonstration. See [installation, input format, exit codes, privacy and recovery](docs/LOCAL_RELEASE.md).

Developer checks:

```sh
python -m unittest discover -s tests -v
python evaluate.py
```

## Controlled local tool lab (October 12 extension)

`python local_lab.py --output reports/my-lab-run` runs actual reads and writes on disposable files and records metadata for the existing analyzer. The driver is scripted, not an autonomous LLM agent; there are no paid API calls. See [the lab guide and measured results](docs/LOCAL_LAB.md). The separate lab evaluation flagged 1/20 normal sessions and the designed missing-approval write; its benign high-volume case was not flagged. These results do not establish real-agent or production performance.

## What the AI does

Six session-level features describe call count, bytes sent, external destinations, sensitive operations, write/shell operations and distinct tools. `log1p` compresses large counts. A 200-tree Isolation Forest learns from a separate baseline. A negative decision margin means unusual relative to that baseline, **not an attack probability**. Contamination is fixed at 5% for this prototype; it is an assumed baseline outlier fraction, not a measured attack rate. Baseline medians are context, not causal feature attribution.

Four rule signals are evaluated independently:
- Missing destination for HTTP activity or positive outbound bytes.
- Destination outside the explicit allowlist.
- Sensitive data sent to an unapproved destination.
- Write or shell event without recorded approval.

Either signal causes analyst review. A normal-looking ML score never suppresses a policy finding.

## Real integration

Map your application's events into one JSON object per line:

```json
{"event_id":"unique-123","session_id":"run-1","tool":"http","destination":"https://docs.example.com","bytes_sent":120,"sensitive":false,"approved":true}
```

Supported tool categories: `read`, `search`, `http`, `write`, `shell`. An empty destination is valid for local operations without outbound bytes. HTTP events or positive outbound bytes with no destination trigger `MISSING_DESTINATION` review. `bytes_sent` is observed outbound bytes, not response size. Sessions must be complete bounded runs; there is no time-windowing or streaming support yet.

`trace_writer.TraceWriter` is a small integration helper; call `record` after observing each operation. Approval and sensitivity flags must originate in trusted application controls, never from LLM self-report. It strips URL paths, queries and fragments. Do not include prompts, secrets or response bodies. The helper does not automatically instrument a framework; add it to the actual tool wrapper. It is single-process only.

Keep organizational traces in `private-data/` (gitignored), use restricted filesystem permissions, and review any report before sharing: event IDs and session identifiers may themselves be sensitive. Reports are local files, not an access-controlled application.

## Evaluation and limits

Included data is **synthetic**, with 200 baseline sessions, 40 held-out normal sessions, and four designed scenarios. Different random seeds and disjoint session/event IDs separate baseline and test. This is a reproducible functional demonstration, not an independent security benchmark. See `reports/evaluation.json` for measured results, including normal sessions flagged.

The committed manifest records explicit session labels and SHA-256 fixture hashes. `python evaluate.py` exits nonzero if the fixtures change, split checks fail, a designed scenario stops matching its expected signals, or more than five normal sessions are flagged. Five is the previous measured count used as a regression ceiling, not a calibrated production target. Tests generate their fixtures in temporary directories. See [the evaluation contract](docs/EVALUATION.md).

The scenarios cover sensitive external transfer, an unapproved shell action, a lookalike hostname, and high-volume approved traffic. The last is unusual but not necessarily malicious. Do not report scenario coverage as real-world attack detection accuracy.

Before operational use: collect representative reviewed traces, validate sensitivity/approval labels, tune thresholds with an independent time-separated dataset, measure workload-specific false alerts, protect telemetry integrity and add drift monitoring. Low-volume abuse can blend into normal activity. Poisoned baselines, incomplete logs, forged metadata and unseen tools undermine results. This is an offline prototype, not an EDR, inline guardrail or production-certified product.

## Security properties

No network calls in the analyzer; no shell execution, unsafe deserialization or dynamic evaluation. JSON inputs are bounded to 10 MB and validated. The writer and reader share validation. Duplicate IDs and baseline/test ID overlap are rejected. The evaluation additionally rejects identical session contents across splits, ignoring identifiers and event order. Reports escape untrusted text and use a restrictive content security policy. Model files are not loaded from disk. These controls reduce specific risks; they do not establish universal security.

## Repository layout

- `agentwatch.py`: parser, rules, ML and report renderer
- `trace_writer.py`: metadata-only integration helper
- `local_lab.py`: instrumented disposable-file lab with a scripted driver
- `make_demo.py`: reproducible synthetic fixtures
- `evaluate.py`: scenario/normal-alert evaluation
- `tests/`: regression tests
- `reports/`: generated demonstration and evaluation
- `docs/`: explanation, proposed LinkedIn announcement, and evaluation contract
- `.github/workflows/tests.yml`: automated tests and regression gate

GitHub Actions runs tests, the frozen evaluation, and a check that example fixtures remain unchanged on pushes and pull requests. It also supports manual runs. The [first hosted run passed on October 24, 2026](https://github.com/Achavellir/agentwatch-ai/actions/runs/40109804580), using Python 3.12 on Ubuntu. Local test results are included in `reports/tests.txt`.

For a five-minute walkthrough, see [the demo guide](docs/DEMO.md).

Code: MIT license. No employer code, customer data or employer performance claims are included.
