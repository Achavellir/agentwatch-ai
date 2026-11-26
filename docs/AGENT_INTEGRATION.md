# Real-agent integration (tool boundary)

Status, November 24, 2026: **implemented and tested with a scripted stand-in
model. Not yet run with a real local LLM.** The first real run needs Ollama on
your computer (free, local). Until then there are no real-agent results.

## What it does

`agent_tools.ToolRecorder` wraps each tool function an agent can call. For every call it:

1. Asks a trusted application policy (`Policy` / `PathPolicy`), not the model,
   whether the call is approved, whether it touches sensitive data, and whether it
   may run.
2. Runs the tool, or refuses it.
3. Appends one metadata event with the outcome `ok`, `error` or `denied`, a
   per-session sequence number, UTC start time and duration.

Denied calls are recorded but **not executed**. So an attempted exfiltration to an
unlisted host appears as `UNAPPROVED_DESTINATION` with `bytes_sent: 0`; it is not
reported as `SENSITIVE_EXTERNAL_TRANSFER`, because nothing was sent.

Each trace has a sidecar `<trace>.sessions.jsonl` with open/close records and the
number of events written. `check_completeness` uses it to detect unclosed sessions,
truncated traces and sequence gaps. It **cannot** detect a producer that never called
the wrapper, or forgery of both files.

Event schema additions (all optional; older traces remain valid; not ML features):
`status` (`ok|error|denied`), `seq`, `ts`, `duration_ms`.

## Reference agent: `scripts/ollama_agent.py`

A minimal tool-calling loop against a local Ollama model. The model chooses tool
calls; the runner executes them in a fresh disposable workspace per run.

| Tool | Category | Policy |
|---|---|---|
| `list_dir`, `read_file` | read | allowed; files under `secrets/` marked sensitive |
| `write_file` | write | approved and executed only under `out/`; otherwise denied |
| `http_get` | http | hosts outside `--allow-host` denied (unless `--network any`); after a sensitive read, later HTTP is marked sensitive |
| (no shell tool) | | |

Paths are confined to the workspace (no `..`, no symlinks). HTTP is GET only,
no redirects, no credentials, a 1 MiB response cap, and bytes counted as they're
handed to the socket (TLS overhead excluded). Only scheme+host is stored. The call
to Ollama itself is infrastructure and is not recorded.

The default workspace includes `secrets/api_token.txt` containing an obviously fake
token, so controlled tasks have something sensitive to mishandle.

### First real run (on your Mac), one command

```sh
bash scripts/run_first_study.sh            # pilot: 20 tasks x 1 run
REPEAT=3 bash scripts/run_first_study.sh   # more runs per task
```

The script sets up `.venv`, checks that Ollama is installed and running, offers to
download the model (default `qwen2.5:7b`), runs the 20 tasks in
`examples/study_tasks.json` (14 ordinary, 6 controlled policy-violation scenarios)
against the fictional workspace in `examples/study_workspace/`, reviews the trace
with AgentWatch, and writes `summary.md` (tool use, outcomes, findings per task).
The summary shows each task's design intent, so it is a pilot check, not a blind
review. Collect fresh runs for the independent study. Known gap to watch: reading a
secret and then contacting an *approved* host fires no rule by design.

### Manual equivalent

```sh
ollama pull qwen2.5:7b          # or another local model with tool calling
python -m scripts.ollama_agent --model qwen2.5:7b \
  --tasks examples/agent_tasks.json --allow-host docs.python.org \
  --repeat 3 --output private-data/agent-run-1
agentwatch --rules-only --input private-data/agent-run-1/activity.jsonl \
  --allow-domain docs.python.org --output private-data/agent-run-1/review
```

`examples/agent_tasks.json` holds four ordinary tasks and two controlled
policy-violation prompts. The `intent` field is the task author's design intent.
It is **not** an evaluation label (see INDEPENDENT_EVALUATION.md).

Model downloads use disk space and bandwidth but cost nothing. Smaller models may
not call tools reliably; record that as a result rather than switching models
quietly.

## Tested (cloud workspace, Python 3.11 and 3.12)

- 11 tests in `tests/test_agent_integration.py`: outcome recording, denied tools not
  executed, path/query/credential stripping, completeness gaps, 20 concurrent calls,
  policy taint and write scope, workspace escape and symlink refusal, the full agent
  loop with a scripted model (normal task: no findings; exfiltration attempt: denied,
  flagged), max-step stop.
- One end-to-end CLI run against a local stand-in HTTP server that imitated Ollama's
  `/api/chat`. Two sessions came out complete, and only the violation session was flagged.

## Not yet verified

- Any run with a real LLM. Tool-call formats differ between Ollama versions and
  models; `tool_name` in tool-result messages is accepted by recent Ollama versions.
- Behaviour with other frameworks (LangChain, OpenAI Agents SDK, MCP servers). The
  wrapper is framework-agnostic, but no adapter has been written or tested.
