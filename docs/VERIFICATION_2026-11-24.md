# Verification of the November 23 handoff — November 24, 2026

Checked by Claude in a cloud Linux workspace from the handoff folder
`AgentWatch-Claude-Handoff`. Nothing was published, pushed or submitted.

## Confirmed by rerunning

| Claim in handoff | Result |
|---|---|
| Files match FILE_SHA256.json | All 59 entries match, both the folder and the zip |
| 66 tests pass | 66/66 on Python 3.12 (locked deps) and 3.11 (unlocked) |
| Frozen evaluation: 200 baseline, 40 normal, 4 scenarios; combined 5/40 normal, 4/4 scenarios | Output byte-identical to `reports/evaluation.json` on 3.11 and 3.12 |
| Rules 0/40 normal, ML 5/40, combined 9/44; scenario table | Installed CLI: rules-only 3/44, with ML 9/44. Rules flag no normals, so ML's 5/40 normal follows from combined |
| Wheel builds; installed CLI and browser checks pass | `scripts/check_installed.py` passes on 3.11 and 3.12 |

## Found

- **The documented install command failed on Python 3.11.** `pip install -c
  requirements-lock.txt .` had no solution because numpy 2.5.3 and scipy 1.18.1 publish
  no 3.11 builds. CI never caught it because it installs the wheel without the lock.
  Fixed with environment markers (3.11 gets numpy 2.4.6 and scipy 1.17.1); CI now
  installs with the lock. Python 3.14 with the lock was not tested here.
- `TraceWriter` creates traces with default permissions, not 0600. It is unchanged
  for compatibility; the new `ToolRecorder` writes 0600.

## Not verified by me

- The live python.org run (HTTP 200, 125 bytes). The cloud workspace couldn't resolve
  the host. Rerun on your Mac: `python -m scripts.web_demo --output private-data/web-run-2`.
- GitHub CI run 45334274096, PR 4 and commit 96b485e. Repository access wasn't
  granted to this session.
- Browser/accessibility review from November 11 (not rerun).

## Added (proposals implemented in code; no study results)

- `agent_tools.py`, `scripts/ollama_agent.py`, `examples/agent_tasks.json`,
  `tests/test_agent_integration.py`: see AGENT_INTEGRATION.md.
- `independent_eval.py`, `tests/test_independent_eval.py`: see INDEPENDENT_EVALUATION.md.
- Optional event fields `status`, `seq`, `ts`, `duration_ms` validated in `agentwatch.py`.
- Lockfile markers, CI lock install, refreshed dependency advisory check.

After the changes: 84 tests pass on 3.11 and 3.12. Frozen evaluation unchanged.
`examples/` fixtures unchanged; one file added.

## Notes for the research draft (author to decide)

1. §8 says Python 3.11+ with the declared dependencies. That was false for the locked
   install at 96b485e. Either cite the fixed revision or note the 3.11 lock issue.
2. §5.2 cites 66 tests for 96b485e. That's correct for that revision; a revision with
   this work has 84.
3. Related work has three references. Before choosing a venue, add verified citations
   for runtime monitoring and guardrails for LLM agents, provenance and audit logging
   for agent actions, prompt-injection defenses beyond AgentDojo, and behavioral
   anomaly detection (UEBA) baselines. None were added here, to avoid unverified
   references.
4. A clearer contribution, if the study is run: tool-boundary telemetry with
   completeness checks, plus a pre-registered rules-vs-ML-vs-combined comparison with
   reviewer workload. This is a proposal; it becomes a claim only after the study.
5. Venue fit is still undecided. With no study, a workshop or tool/artifact track
   fits the current evidence better than a main research track. This is a judgment
   call for you.
