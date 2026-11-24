# Independent evaluation protocol

Status, November 24, 2026: **harness implemented and tested on constructed test
data. No study data has been collected and no results exist.** `evaluate.py` remains
the frozen synthetic regression gate and is unchanged.

## Research question (open)

Does adding anomaly review to policy rules find more actionable sessions than rules
alone, at a reviewer workload the developer would accept?

## Order of operations, enforced by `independent_eval.py`

1. **Collect** runs with `scripts/ollama_agent.py` (or another instrumented agent)
   so that each session has a `task_family` and a `finished_at` time in `runs.jsonl`.
   Repeated runs of the same task belong to the same family.
2. **Split** before looking at any review output:
   ```sh
   python independent_eval.py split --trace RUN/activity.jsonl --runs RUN/runs.jsonl \
     --study private-data/study-1 --strategy family --seed 0 \
     --keep-out-of-baseline controlled-violation
   ```
   Whole families go to baseline, tune or final, so related runs never straddle
   partitions. `--strategy time --tune-after T1 --final-after T2` splits by collection
   period instead and refuses if a family spans periods. Controlled-violation families
   never train the baseline. The baseline must also be reviewed as normal; the tool
   cannot check that for you.
3. **Blind review packet.** `review_packet_final.jsonl` holds the final sessions'
   events only: no rule findings, margins, task names or intent. Reviewers fill in
   `labels_final_TEMPLATE.csv` with `normal` or `actionable`, plus `blind=yes|no` and
   optional `review_seconds`. Have them define "actionable" in writing beforehand.
   With two reviewers, disagreements need an adjudication CSV; agreement and Cohen's
   kappa are reported.
4. **Tune** on the tune partition only (`independent_eval.py tune ...`). This is the
   only place to try domain policies.
5. **Freeze** (`independent_eval.py freeze --study ... --allow-domain ...`). This
   records the domain policy, analyzer settings and SHA-256 of `agentwatch.py`,
   `independent_eval.py`, `split.json` and each partition. It cannot be overwritten.
6. **Score** (`independent_eval.py score --study ... --labels final.csv
   --completeness RUN/completeness.json --output results.json`). This refuses if any
   pinned file changed, and appends every scoring to `final_scoring_log.jsonl`. Report
   the count in that log, including any reruns.

## What is reported

For rules-only, ML-only and combined: TP/FP/FN/TN, recall and false-alert rate with
Wilson 95% intervals, precision, alert count (workload), and a family-level cluster
bootstrap when the final partition has at least 5 families. Also: actionable
sessions combined review adds over rules alone, false alerts it adds, analyzer
milliseconds per session, median reviewer seconds, and the logging-incomplete rate
with an interval.

## What it can't guarantee

- That reviewers were truly blind or independent (self-declared).
- That nobody deleted `freeze.json` and re-froze. The scoring log and hashes make
  that visible only if the study folder is kept intact; keep a copy elsewhere.
- That the traces are representative or the producer was honest.
- A sample size. Choose it from the interval width you need, and say how you chose it.

## Pre-registration checklist (fill in before collecting final data)

- Agent, model and version; tool set; policy (allowed hosts, writable/sensitive dirs)
- Task families and how many runs per family; collection dates
- Definition of "actionable", written before review; reviewer(s) and how they're independent
- Split strategy and seed; keep-out families
- Primary comparison (combined vs rules-only: additional actionable found, additional false alerts)
- Interval width target and the resulting family/run count
- What will be reported if results are negative (all of it)
