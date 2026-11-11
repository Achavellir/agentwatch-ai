# Local developer release (0.3.x)

This guide covers the command-line tool introduced in 0.2.0. It still applies to 0.3.x; version 0.3.0 adds an optional local browser interface described in [BROWSER_UI.md](BROWSER_UI.md).

## Supported use

One developer reviewing complete, bounded JSONL sessions from their own application, on a trusted local machine. No account, web service, API key, or subscription is required. This release provides offline policy review and optional exploratory anomaly scoring. It is not an enforcement control or an independently validated attack detector.

## Install

Use Python 3.11 or newer in a dedicated virtual environment. From the repository root:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
agentwatch --version
agentwatch --rules-only --input examples/candidate.jsonl --allow-domain docs.example.com --output reports/first-local-run
```

Installation downloads dependencies; analysis itself does not use the network. Choose a new output directory on every run. Open `report.html` inside that directory. `report.json` supports other local tooling; `COMPLETE` is written last to indicate that both report files were written successfully. An interrupted run can leave an incomplete directory; do not treat it as evidence of completed analysis.

For optional anomaly scoring, replace `--rules-only` with `--baseline examples/baseline.jsonl`. Real baselines need at least 30 reviewed sessions from the intended workload. Do not use the synthetic baseline to judge unrelated real activity.

## Input contract

Each UTF-8 JSONL line is one event with event_id, session_id, tool, bytes_sent, sensitive and approved. destination is optional for local operations. Supported tools are read, search, http, write and shell. IDs must be unique across baseline and candidate files. Each input is limited to 10 MB. Use ASCII hostnames in --allow-domain; URLs, wildcards and ports are rejected. Exact subdomains must be allowed separately. An empty allowlist treats all recorded network destinations as unapproved.

The trace writer is a single-process integration helper, not automatic instrumentation. Approval and sensitivity labels must originate in trusted application code. Failed tool operations and tamper-resistant collection are not supplied by this release. Never put prompts, response bodies, credentials or customer data in example traces. Identifiers and reports may themselves contain sensitive information.

## Output and exit status

JSON schema_version is 1; agentwatch_version records the generator. Existing fields have remained compatible from 0.2.0 through 0.3.x. In rules-only mode model and anomaly_margin are null, anomaly is false, and baseline medians are null. This means no ML assessment occurred, not that behavior was normal.

Exit 0 means analysis and report creation completed, including when review findings exist. Exit 2 means invalid arguments, rejected input or a filesystem failure. A review flag is a triage signal, not a confirmed incident. No-signal does not prove safety.

New report directories are owner-only (0700) and files are owner read/write (0600) on POSIX. Windows access depends on filesystem ACLs; equivalent privacy is not claimed. Use a private, caller-controlled output parent. Existing paths and output symlinks are rejected. These checks do not protect against hostile processes running as the same user, privileged users, or a writable hostile parent directory. No overwrite option is provided.

## Maintenance and recovery

Keep the previous virtual environment and reports when upgrading. Install a reviewed Git commit or wheel into a new virtual environment, run a representative local trace, then switch environments. Roll back by returning to the previous environment. There are no database migrations or remotely stored customer records. Report files are retained until their owner removes them; apply your own retention policy.

Report reproducible bugs through the GitHub repository with a minimal synthetic example. Do not attach real confidential traces. Before deploying this into an organizational workflow, validate telemetry quality, expected policy rules and normal-alert workload using authorized representative logs. Independent real-agent security effectiveness remains unverified.
