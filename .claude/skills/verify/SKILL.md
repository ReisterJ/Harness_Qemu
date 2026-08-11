---
name: verify
description: Verify harness changes end-to-end without docker — drive the real pinned opencode CLI against a header-capturing stub server with the exact env resolve_auth_env() produces.
---

# Verifying harness changes on a docker-less host

The pipeline's real surface is the in-container `opencode run` process and its
outbound API requests. Without docker, drive the same pinned CLI binary
directly with the env dict the harness would inject via `docker -e`.

## Recipe

1. **Get the pinned CLI** (version from `harness/agent_image.py:OPENCODE_VERSION`):
   `npm install --no-save opencode-ai@<pin>` in a temp dir → binary at
   `node_modules/opencode-ai/bin/opencode.exe` (the `.exe` name is the real
   compiled entry on Linux too, filled in by the package's postinstall — not a
   Windows leftover).
2. **Stub API server**: a tiny HTTP server that appends each request's
   headers to a JSONL file and returns a 400 `invalid_request_error`
   (non-retryable, so opencode emits an `error` event and exits fast;
   exit != 0 is expected).
3. **Build the agent env exactly as the pipeline does**:
   `python3 -c "from harness.auth import resolve_auth_env; ..."` and dump to
   an `export`-lines file with `shlex.quote` (values can contain newlines —
   NEVER pass via `env $(...)`, word-splitting mangles them; `source` the file).
4. **Emulate the container env**: unset any ambient provider-key / OPENCODE_*
   var not in the resolved dict before sourcing (the harness only forwards the
   resolved set; the agent container sees exactly that).
5. **Run** (point the deepseek provider at the stub via inline config):
   `OPENCODE_CONFIG_CONTENT='{"provider":{"deepseek":{"options":{"baseURL":"http://127.0.0.1:<port>/v1"}}}}'
   timeout 30 opencode run "hi" --model deepseek/deepseek-chat --format json`,
   then read the captured JSONL. `--format json` emits the same raw events the
   harness parses (`step_start`/`text`/`tool`/`step_finish`/`error`).

## Gotchas

- Unit tests in `tests/test_patch.py` / `tests/test_patch_grade.py` need
  docker and fail on docker-less hosts — pre-existing, not your change.
- The docker `-e` injection leg itself can't be exercised without docker;
  it's the same mechanism that carries `DEEPSEEK_API_KEY` in production.
- The agent runs `opencode run --format json --model <provider>/<model>
  --agent <name> --auto`; the per-phase system prompt / steps / permissions
  come from `.opencode/agents/vuln-<phase>.md`, which `harness/agent.py`
  writes into the container before launching.
