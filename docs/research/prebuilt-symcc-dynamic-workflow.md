# Prebuilt SymCC target in dynamic validation

## Goal

The dynamic phase should spend its budget on source understanding and PoC
iteration, not on asking an agent to assemble and compile a source slice. A
target opts into SymCC by supplying a normal executable and a SymCC-instrumented
executable built before the dynamic run, plus the matching source tree.

## Target configuration

The normal executable continues to use `binary_path`. A target that supports
prebuilt SymCC adds:

```yaml
binary_path: /out/target-asan
source_root: /src/project
commit: <40-hex-source-commit>
symbolic_execution:
  default: "off"
  providers:
    - symcc
  symcc:
    binary_path: /out/target-symcc
    commit: <same-40-hex-source-commit>
    # Optional when the SymCC executable needs different CLI flags.
    program_args: ["--input", "{input_file}"]
```

Both executables, their runtime libraries, and the source tree must be present
in the target runtime image. The prebuilt SymCC executable must accept an input
file and use SymCC's `SYMCC_INPUT_FILE` / `SYMCC_OUTPUT_DIR` runtime contract.
The `commit` field is checked against the target's configured source commit;
the harness does not compile either executable.

## Dynamic execution

When `--symbolic-execution symcc` is selected, the harness verifies both
executables and installs a request/response client at
`/work/validation/run-input`. The PoC agent can read the checked-out source and
construct inputs normally. It writes each input under
`/work/validation/inputs/`, creates a request from
`/work/validation/execution/request-template.json`, and invokes the client.

For each request, the harness:

1. Runs the exact input against the ordinary target executable.
2. Runs that same input against the prebuilt SymCC executable.
3. Collects bounded generated files and replays them against the ordinary
   executable.
4. Returns exit status, bounded output, testcase hashes, and replay outcomes to
   the agent; it records the full request observations under the optional
   symbolic-results directory.

SymCC testcase generation is advisory feedback, not reachability or
vulnerability proof. Source-site reach is not inferred from testcase count.
The agent remains responsible for reading source and building a semantically
valid PoC, and the normal grade phase remains the final reproduction check.

## Failure behavior

Selecting SymCC without a configured prebuilt binary, a matching commit, or
executable artifacts fails before the PoC agent starts. The workflow does not
fall back to agent-authored source slices or compilation. Runs with symbolic
execution disabled retain the normal dynamic workflow.
