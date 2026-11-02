# Evaluation contract — October 23, 2026

The current release is an offline portfolio prototype with synthetic regression checks and a scripted local-file lab. It is not a completed real-agent security benchmark.

## Frozen regression set

The existing baseline (200 sessions) and candidate set (40 normal sessions and four designed scenarios) retain their original bytes. The manifest now provides explicit labels, SHA-256 hashes and scenario rule expectations. Labels are used only by the evaluator, never as model features. Session-name prefixes no longer determine the evaluation label.

The evaluation fails on changed fixture bytes, overlapping session/event IDs, or identical session contents after removing identifiers, unknown metadata and event ordering. It also fails when a scenario is no longer flagged, required rules disappear, unwanted rules appear in the approved-volume scenario, or normal alerts exceed the previous 5/40 result. This is a regression ceiling fixed from the known development result; it is not a newly calibrated security threshold.

Hashes detect accidental fixture changes against the checked-in manifest. They do not authenticate an attacker-controlled manifest, establish data provenance, or detect all near-duplicates. Changes to fixtures and manifest require code review. `make_demo.py` can explicitly regenerate the known development fixtures; normal tests generate separate temporary copies, and CI checks the committed fixtures without regenerating them first.

## Why overlap checks live in evaluation

Short local read/write sequences can legitimately repeat. The analyzer continues to accept these workflows when their identifiers are distinct. The synthetic evaluation rejects content overlap for review of the split; this is a conservative corpus rule, not evidence that every identical sequence is leaked data. The separate local lab intentionally shares a scripted task family and does not claim content independence.

## Independent validation remains future work

Different seeds are not independent validation. The bundled datasets have already been examined during development. No new independent holdout or real autonomous model experiment was created for this release. Before making a generalization claim, obtain authorized traces from different task families and a later time period, group related runs before splitting, reserve an unseen test set, and freeze tuning decisions before opening that set. Do not tune against the final test results.

## Reproduce

```sh
python -m unittest discover -s tests -v
python evaluate.py
python agentwatch.py --baseline examples/baseline.jsonl --input examples/candidate.jsonl --allow-domain docs.example.com --output reports/demo
python local_lab.py --output reports/new-local-run
```

Choose a fresh lab output directory. No API key, model subscription, hosting or purchase is needed. GitHub CI passed on October 24, 2026: [hosted run](https://github.com/Achavellir/agentwatch-ai/actions/runs/40109804580). That run installed dependencies and ran the tests and evaluation on Ubuntu with Python 3.12. Dependency vulnerability database scanning was not performed; passing installation and tests is not a vulnerability audit.
