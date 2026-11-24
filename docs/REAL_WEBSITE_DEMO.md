# Real website activity demo

From an installed repository environment, run:

```sh
python -m scripts.web_demo --output private-data/web-demo-1
```

This makes one HTTPS GET to the public Python homepage. It automatically records
the destination and outgoing HTTP byte count, then creates two offline reports:

1. `private-data/web-demo-1/approved/report.html`: www.python.org is approved;
   the recorded visit has no policy finding.
2. `private-data/web-demo-1/unapproved/report.html`: only docs.python.org is
   approved; the identical visit is flagged as an unapproved destination.

Open both reports side by side. Explain: **the action stayed the same; the
developer's policy changed. A finding means review the action, not that the
website is dangerous.** You can also select the generated `activity.jsonl` in
`agentwatch-ui --open` and enter either hostname yourself.

The response body is read only up to 1 MiB and discarded. No prompts, credentials,
cookies, personal files or page content are saved. HTTPS certificate verification
is enabled; redirects are rejected. There are no paid API calls. The remote site
sees an ordinary request, including your IP address. Output files are private to
your user, with a fresh directory required for each run. Use a trusted parent
directory. A failed run may leave partial files; only a top-level `COMPLETE` file
indicates that both reports finished.

This is a scripted tool integration example, **not an autonomous LLM agent**, a
website vulnerability scanner, continuous browser monitoring or evidence of
real-world detection accuracy. Outbound byte counts exclude TLS/network overhead.
Approval and non-sensitive labels are set by this fixed public-request demo,
not inferred by a model. It intentionally supports one public site to keep the
demonstration reproducible and prevent arbitrary internal-network requests.

Next: instrument an actual agent's tool wrapper and validate independent,
human-reviewed traces. The demo does not complete that milestone.
