# libyaml fuzz target (exploration-memory experiment)

Input-driven YAML parser target for the **exploration-memory experiment**
(see `docs/memory-experiment-plan.md`). Uses upstream libyaml with the
official `tests/run-parser.c` as the fuzz harness — no custom entry.

## Why this target

- **~17k lines of C**, a real-world parser (used by PyYAML, Ruby, go-yaml).
- Input-driven: `run_parser <file>` runs `yaml_parser_parse()` to exhaustion.
- Latest master (`90a56d4`, 2026-08-21) — **we do NOT need a crash**; the
  experiment measures *exploration process quality* (region coverage,
  re-entry, forks, convergence), not find success.

## Layout

| File | Purpose |
|---|---|
| `Dockerfile` | gcc:14 + cmake; clones libyaml @ 90a56d4; builds `libyaml.a` (CMake) + ASAN `run_parser` harness |
| `config.yaml` | pipeline config: `binary_path=/work/run_parser`, `source_root=/work/libyaml`, 4 focus_areas |

## Build

```sh
docker build --network=host \
  --build-arg HTTPS_PROXY=http://127.0.0.1:7897 \
  --build-arg HTTP_PROXY=http://127.0.0.1:7897 \
  -t vuln-pipeline-libyaml:latest targets/libyaml
```

## Run (A/B)

```sh
# A: no memory (control)
vuln-pipeline run targets/libyaml --dangerously-no-sandbox \
  --model deepseek/deepseek-v4-flash --max-turns 100 --runs 3

# B: with exploration memory
vuln-pipeline run targets/libyaml --dangerously-no-sandbox \
  --model deepseek/deepseek-v4-flash --max-turns 100 --runs 3 --memory
```

## Observed behavior (2026-08-31 smoke)

- `run_parser` parses normal/malformed YAML fine; deep nesting is capped by
  `MAX_NESTING_LEVEL` (default 1000) unless `--max-level` is passed.
- ASAN build confirmed working; current master resists easy crashes — by
  design, the experiment does not require one.

## Notes

- Harness: `tests/run-parser.c` accepts `--max-level N` (before file args).
- `focus_areas` cover parser/scanner/reader/emitter+loader.
