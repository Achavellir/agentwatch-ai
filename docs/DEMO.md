# Five-minute AgentWatch demo

## Prepare

From the repository, activate the Python environment and run:

```sh
python -m unittest discover -s tests -v
python evaluate.py
python agentwatch.py --baseline examples/baseline.jsonl --input examples/candidate.jsonl --allow-domain docs.example.com --output reports/meeting-demo
```

Open `reports/meeting-demo/report.html`. Choose a fresh directory on subsequent runs. No server, model API key, or paid service is required. Keep the GitHub Actions page available to show automated checks.

## Minute 1: Explain the problem

AgentWatch is an offline prototype for reviewing AI-agent tool activity. It reads recorded metadata and highlights sessions that deserve human review. It does not execute agents or stop an action before it happens.

## Minute 2: Explain the flow

JSONL events are validated and grouped into sessions. Six numeric features summarize tool activity. Isolation Forest compares each candidate session with a baseline. Independent policy rules check destinations, sensitive transfers, and approvals. Either signal can request review. The HTML report links findings to event IDs and input lines.

## Minute 3: Show two different signals

Show the lookalike-hostname scenario: the exact-hostname rule flags it even though the model does not. Then show high-volume approved traffic: the model flags unusual activity without a policy violation. This is benign unusual behavior, not proof of an attack. Expand the evidence for a policy finding and explain the triggering event.

## Minute 4: Explain the evidence

The frozen synthetic set has 200 baseline sessions, 40 normal candidate sessions, and four designed scenarios. All four scenarios request review, and 5/40 normal sessions also request review. These figures demonstrate the known examples, not production accuracy. The evaluation checks fixture hashes, labels, identifier overlap, and copied session contents. Tests do not regenerate the committed fixtures.

The separate scripted local lab performs real reads and writes on disposable files. Its missing-approval write is caught by a rule, not by ML. It does not establish additional security value from ML or autonomous-agent performance.

## Minute 5: Explain ownership and limitations

This portfolio project was built with substantial AI coding assistance. Describe only the decisions and code you can personally explain; do not claim independent authorship of every line.

Approval and sensitivity metadata must come from trusted application controls. The system does not provide telemetry integrity, streaming analysis, preventive enforcement, or independent real-agent validation. A negative ML score means unusual relative to the baseline, not an attack probability.

## Next research milestone

Before tuning further, define separate task families and reserve an unseen evaluation set. Collect authorized representative traces, compare rules alone with ML alone and the combined system, and measure useful detections alongside normal-alert workload. If ML adds no value, simplify the design. This work remains future research, not a completed capability.
