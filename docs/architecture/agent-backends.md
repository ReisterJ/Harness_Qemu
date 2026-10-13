# Agent backends

Every pipeline phase drives a headless agent CLI through one seam:
`harness.agent.run_agent()`. Two backends are implemented:

| Backend | CLI | Selection |
| --- | --- | --- |
| `opencode` (default) | opencode 1.17.18, shipped in the agent image | default |
| `codex` | `codex exec` 0.162.1, installed in the agent image | `VULN_PIPELINE_AGENT_BACKEND=codex` |

Both return the same `AgentResult` (tag parsing, transcripts, submissions) and
share the watchdog, resume and transcript machinery. The phase prompts,
submission contract and dynamic-execution protocol are backend-agnostic.

## Running with codex

```sh
VULN_PIPELINE_AGENT_BACKEND=codex \
VULN_PIPELINE_CODEX_MODEL=gpt-6-luna \
VULN_PIPELINE_CODEX_AUTH_FILE="$HOME/.codex/auth.json" \
.venv/bin/python -m harness.cli run targets/canary --model luna --runs 1 \
  --dangerously-no-sandbox --results-dir results/experiments/codex-smoke
```

Environment knobs (all read by `harness/agent_codex.py`):

| Variable | Meaning |
| --- | --- |
| `VULN_PIPELINE_AGENT_BACKEND` | `opencode` (default) or `codex` |
| `VULN_PIPELINE_CODEX_MODEL` | model id; `luna` is accepted as an alias. Defaults to `gpt-6-luna` |
| `VULN_PIPELINE_CODEX_PROVIDER` | `-c model_provider=<name>` for a custom Responses-API provider |
| `VULN_PIPELINE_CODEX_CONFIG` / `_CONFIG_FILE` | `$CODEX_HOME/config.toml` content (inline / host file) |
| `VULN_PIPELINE_CODEX_AUTH_FILE` | host `auth.json` copied into `$CODEX_HOME` (ChatGPT-plan auth) |
| `VULN_PIPELINE_CODEX_EGRESS` | override the egress hosts `harness/auth.py` requires |
| `VULN_PIPELINE_CODEX_REASONING` | `-c model_reasoning_effort=<low..max>` (luna defaults to `medium`) |

### Model

The codex backend defaults to **`gpt-6-luna`** — the fast/affordable Codex
model this harness uses for bulk runs (`luna` works as an alias on the
`--model` flag). `gpt-6-astra` (the interactive default) rejected the
find-phase prompt with an OpenAI cyber-risk classification in our smoke test;
luna did not. Provider-prefixed strings codex cannot serve (for example
`deepseek/deepseek-flash`) fall back to the default with a warning: codex
0.16x dropped `wire_api = "chat"`, so chat-completions-only providers cannot
drive it — a custom provider must speak the Responses API.

### Auth

- **API key** — `OPENAI_API_KEY` is forwarded by `harness.auth.resolve_auth_env`;
  the adapter runs `codex login --with-api-key` inside the container when not
  already logged in. The key never appears in argv.
- **ChatGPT plan** — point `VULN_PIPELINE_CODEX_AUTH_FILE` at the host
  `~/.codex/auth.json`; the adapter copies it into `$CODEX_HOME` per container
  (the host file is left untouched). This is a credential — use it only when
  the containers are considered trusted.

`codex login status` decides which path is needed; custom providers that
authenticate through `env_key` skip the login probe.

### Behaviour notes

- **Events** — the CLI's JSONL (`thread.started` / `turn.*` / `item.*`) is
  normalized into the opencode message shape (`part.type == "text"` / `"tool"`)
  so the rest of the pipeline and the analysis tooling keep working. Raw codex
  events are written next to each transcript as `<name>.raw.jsonl`; token usage
  is printed per turn.
- **Turn cap** — codex has no step cap. `max_turns` is enforced by counting
  completed assistant/tool items and terminating the session at the cap
  (`agent/step_limit`).
- **Resume** — transient failures resume with `codex exec resume <thread_id>`.
  Provider policy blocks (cyber-risk classification) are terminal and are
  surfaced as `agent/policy_blocked` without retrying.
- **Premature stops** — a small/fast model can return a terminal negative
  status (`reached_no_crash` / `false_positive`) long before the phase budget is
  spent. The harness honours it and the run ends; it never nudges, resumes or
  re-prompts the agent to keep working, because steering the agent would change
  what the arm measures. The only lever is on the model side, before launch
  (`VULN_PIPELINE_CODEX_REASONING=high|xhigh`).
- **Goal tracking (audit only)** — the CLI exposes `tools.create_goal` /
  `get_goal` / `update_goal` on a persisted thread (the `goals` feature is
  `stable` and on by default; `--ephemeral` would forbid it). With the codex
  backend the dynamic prompt asks for one goal whose objective states this
  candidate's completion criterion, marked `complete` only for a reproduced
  matching crash and `blocked` otherwise. `codex exec` **never auto-continues**
  an active goal — continuation needs the app-server thread manager, so a goal
  adds no turns and the phase still ends when the model stops. What it buys is
  a machine-readable record: `read_goal_state()` reads
  `$CODEX_HOME/goals_*.sqlite` after the phase (goal calls are *not* in the
  `--json` stream) and the row lands in `dynamic_validation.json` as
  `result.goal`. A run that reports a negative status while leaving the goal
  `active` stopped short of its own declared criterion.
- **Sandbox** — codex's own Landlock/seccomp sandbox is bypassed with
  `--dangerously-bypass-approvals-and-sandbox`: the agent container (gVisor on
  the shipped path) is the trust boundary, which is exactly the use case the
  flag documents.
- **Watchdog** — the phase watchdog distinguishes a quiet model request from a
  live Bash command by sampling the container's process table. The backend CLI
  itself is excluded from that sample and from the kill sweep by executable
  basename (`opencode`, `codex`), because a CLI's own command line carries the
  phase prompt — prose that names python/ruby/node would otherwise read as an
  unbounded helper and kill every run at the 120 s helper deadline.
- **Image** — the agent image installs `@openai/codex@0.162.1` plus
  `codex-code-mode-host` (without it the tool runtime refuses to run commands)
  and copies the native binary into target images. Image tags carry a
  `-codex<version>-r<revision>` suffix so a copy-list change rebuilds instead
  of reusing a stale layer.

### Known limitations

- Running unsandboxed (`--dangerously-no-sandbox`) with the loopback model
  proxy needs `VULN_PIPELINE_AGENT_NETWORK=host` **and**
  `VULN_PIPELINE_DOCKER_BUILD_NETWORK=host`. The dynamic path defaults to host
  network in that mode, but the static/recon standalone paths still default to
  the bridge network — a host without a loopback proxy is unaffected.
- Codex on a ChatGPT plan is subject to OpenAI's content tiering; whether a
  phase is allowed depends on the account and model tier, not on this harness.
- `gpt-6-luna`'s reasoning effort defaults are codex-side; the adapter does
  not set `model_reasoning_effort`.

## Smoke result (2026-10-10)

`targets/canary`, codex + `gpt-6-luna`, `--dangerously-no-sandbox`:

```text
[build] done in 0.2s
[find:0]  done in 179.1s (static=69.1s, dynamic=110.0s), 14 messages
[find:0]  Crash claimed: heap-buffer-overflow at /work/validation/poc-alpha.bin (11 bytes)
[grade:0] done in 63.6s: passed=True, score=1.0
status: crash_found
```

Unit coverage for the backend lives in `tests/test_agent_codex.py`
(normalization, argv/model mapping, auth seeding, resume, step cap, policy
block, goal-state read).
