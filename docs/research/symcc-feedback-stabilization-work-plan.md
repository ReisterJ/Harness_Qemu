# SymCC Feedback Stabilization Work Plan

> 2026-10-09 注：本文（2026-10-02 计划）中的 `targets/mruby-arvo-feedback/` 及
> `targets/mruby-arvo-feedback/static-report-57672-v2.json` 已于 2026-10-08 删除（提交 `a1bb97d6e`），
> 文中命令保留的是当时的事实。mruby-57672 各版本静态报告的内容、使用波次与**最后使用版**
> 见 [`experiment-records/2026-10-09-mruby-57672-static-report-versions.md`](experiment-records/2026-10-09-mruby-57672-static-report-versions.md)。

## 1. Objective

This plan turns the current SymCC feedback prototype into a more reliable
target-directed evidence channel for dynamic validation.

The current issue is not simply that there are too few benchmark samples. The
larger problem is that SymCC feedback is sometimes useful and sometimes
misleading. In particular, function-level or basic-block-level progress can be
mistaken for reaching the real vulnerability operation. When that happens, the
agent may switch too early from "find a path to the site" to "debug a PoC",
which wastes time and makes the experiment hard to explain.

The goal of this round is therefore:

1. Make SymCC feedback semantically precise enough that the agent cannot easily
   over-interpret weak signals.
2. Preserve useful dynamic evidence such as observed source locations, generated
   seeds, and non-target crashes.
3. Keep the original dynamic validation and grade workflow unchanged.
4. Produce experiments whose results can explain whether SymCC helped with
   target-site approach, PoC construction, or neither.

Build automation is out of scope for this plan. Experiments assume the ordinary
target binary, ASan binary if needed, SymCC binary, and matching feedback map
already exist.

## 2. Core Design Change

The current feedback should be treated as execution evidence, not as a final
reachability conclusion. The agent should receive a compact record with clear
truth boundaries:

```json
{
  "request_id": "round-003",
  "input_id": "sha256:...",
  "trace_status": "complete",
  "exact_target_reached": false,
  "target_function_entered": true,
  "target_block_entered": true,
  "target_operation_reached": false,
  "target_reachability": "this_execution_missed",
  "observed_locations": [
    {"source_file": "src/vm.c", "line": 397, "function": "mrb_env_unshare"},
    {"source_file": "src/vm.c", "line": 401, "function": "mrb_env_unshare"}
  ],
  "heuristic_distance": {
    "value": 0,
    "granularity": "basic_block",
    "exposed_to_agent": false,
    "reason": "distance=0 at block granularity does not prove the target operation ran"
  },
  "allowed_conclusion": "entered the target region, but did not observe the precise target operation marker"
}
```

The important rule is:

`target_block_entered=true` and `distance=0` must not authorize
`matched_candidate=true`. Only an exact operation marker hit can prove that the
configured target site was reached in that concrete execution.

## 3. Target Marker Contract

Static reports and dynamic validation need a stricter target description. A
candidate can still include function and root-cause text, but SymCC feedback
needs explicit observation anchors.

Required target fields:

- `target_function`: the function that contains the relevant vulnerability
  region.
- `target_region`: the source range that bounds the relevant code region.
- `target_operation`: the specific source line or marker that should be treated
  as exact site reach.
- `target_condition` optional: a branch or condition that should be observed
  separately if it controls the operation.

For example, the MRuby 57672 target should not stop at:

```text
src/vm.c:397, mrb_env_unshare
```

It should identify the operation being verified, such as:

```text
target_function: mrb_env_unshare
target_region: src/vm.c:397-400
target_operation: src/vm.c:398 or src/vm.c:399
target_condition: p != NULL branch at src/vm.c:397
```

If the operation marker cannot be resolved in the map, the feedback state must
be `unknown`. The harness must not silently fall back to the function entry and
present that as a precise target hit.

## 4. Code Changes

### 4.1 Feedback Schema and Summarization

Files:

- `harness/symbolic/feedback.py`
- `harness/symbolic/symcc_worker.py`
- `harness/execution_protocol.py`
- `tests/test_symcc_feedback.py`
- `tests/test_execution_protocol.py`

Changes:

1. Introduce a feedback schema version for agent-facing compact feedback.
2. Rename or duplicate ambiguous fields so the agent sees:
   - `exact_target_reached`
   - `target_function_entered`
   - `target_block_entered`
   - `target_operation_reached`
   - `target_reachability`
   - `trace_status`
   - `allowed_conclusion`
3. Keep CFG distance in raw harness artifacts, but do not expose it as primary
   navigation unless clearly marked as heuristic and non-authoritative.
4. Ensure observed locations are sorted for usefulness:
   - target function first;
   - target source file second;
   - other observed locations after that.
5. Preserve per-candidate generated seed traces separately from the original
   input trace. A generated seed cannot overwrite the original input result.
6. Add explicit states for:
   - target hit;
   - complete miss;
   - unknown due to truncation;
   - unknown due to missing or mismatched map;
   - non-target crash.

Acceptance tests:

- A trace that enters the target function but misses the operation reports
  `exact_target_reached=false`.
- A trace that enters the target block but misses the operation reports
  `target_block_entered=true` and `exact_target_reached=false`.
- A truncated trace without a positive target flag reports `unknown`, not
  `false`.
- Generated seeds have their own input hash and trace result.
- Raw distance may exist in result artifacts, but compact agent feedback does
  not present `distance=0` as success.

### 4.2 Static Candidate and Target Anchor Handling

Files:

- `harness/prompts/static_analysis_prompt.py`
- `harness/prompts/dynamic_validation_prompt.py`
- `harness/static_analysis.py` if target parsing is centralized there
- `harness/find.py`
- `tests/test_find_split.py`

Changes:

1. Extend the static report contract with `observability_targets` that can
   distinguish function, region, operation, and condition.
2. Keep backward compatibility with old reports, but mark function-only targets
   as coarse.
3. Dynamic validation should warn the agent when the selected target is coarse:
   it can guide exploration, but cannot prove exact site reach.
4. When the target report contains a precise operation marker, dynamic
   validation should use that marker as the exact target.

Acceptance tests:

- Old reports still run, but produce `target_anchor_granularity=function` or
  `region`.
- Reports with operation anchors produce exact target IDs.
- Missing operation anchors do not become false exact hits.

### 4.3 Prompt Changes

Files:

- `harness/prompts/dynamic_validation_prompt.py`
- `harness/execution_protocol.py`
- `tests/test_symcc_iteration_reconciliation.py`

Changes:

1. Replace "prefer using feedback" style wording with mandatory interpretation
   rules:
   - exact target hit is required before claiming the candidate site was reached;
   - block hit and distance are navigation hints only;
   - unknown is not a miss;
   - non-target crashes must be submitted as independent findings;
   - after exact site reach, switch to ordinary PoC debugging.
2. Require every dynamic iteration record to include the request/input ID used
   as evidence.
3. Forbid reporting a candidate as ready based only on heuristic distance,
   target block hit, or model reasoning.

Acceptance tests:

- The dynamic prompt contains the distinction between exact operation hit and
  block/function hit.
- Reconciliation rejects `candidate_ready` when machine evidence says exact
  target was not reached.
- Reconciliation records non-target ASan crashes as separate evidence instead
  of converting them into original-candidate success.

### 4.4 Additional Crash Handling

Files:

- `harness/dynamic_validation.py`
- `harness/find.py`
- `harness/artifacts.py`
- `tests/test_additional_crashes.py`

Changes:

1. If ordinary target execution produces ASan/crash evidence but exact target
   reach is false or unknown, classify it as `additional_crash_candidate`.
2. Preserve the input bytes, request ID, crash stack, sanitizer type, and replay
   command.
3. Do not let an additional crash count as validating the original static
   candidate.
4. Allow final results to report both:
   - original candidate status;
   - additional findings discovered during validation.

Acceptance tests:

- A crash without exact target reach is not `candidate_ready`.
- The same crash is still preserved as an additional finding candidate.
- Grade input generation can select the original candidate PoC or an additional
  finding PoC explicitly.

### 4.5 Experiment Metrics and Result Schema

Files:

- `harness/dynamic_validation.py`
- `harness/find.py`
- `harness/cli.py`
- result summary helpers if present

Changes:

1. Separate timing metrics:
   - first valid input submission time;
   - first feedback delivery time;
   - first exact target reach time;
   - first sanitizer/crash time;
   - first accepted PoC submission time;
   - grade success time if grade is run.
2. Record SymCC worker metrics:
   - queued jobs;
   - completed jobs;
   - timed-out jobs;
   - crashed jobs;
   - unknown traces;
   - generated seeds replayed;
   - generated seeds that improved target evidence.
3. Report experiment status as a tuple instead of one overloaded boolean:
   - `target_site_status`;
   - `poc_status`;
   - `grade_status`;
   - `additional_findings_status`;
   - `feedback_quality_status`.

Acceptance tests:

- A run can be "target reached but no PoC".
- A run can be "PoC found for additional crash but original target unknown".
- A run can be "feedback unavailable" without being counted as target miss.

## 5. Validation Plan

### 5.1 Unit Tests

Run focused tests first:

```sh
.venv/bin/python -m pytest \
  tests/test_symcc_feedback.py \
  tests/test_execution_protocol.py \
  tests/test_symcc_iteration_reconciliation.py \
  tests/test_additional_crashes.py
```

Then run the full suite:

```sh
.venv/bin/python -m pytest
```

### 5.2 Canary Calibration

Before real targets, add or reuse a tiny instrumented target with four cases:

1. enters target function only;
2. enters target block only;
3. reaches exact operation marker;
4. crashes or truncates before exact marker.

Expected result:

- function-only and block-only cases do not become exact target hits;
- operation-marker case is exact hit;
- truncated case is unknown unless runtime target flag is positive.

### 5.3 Real Target Smoke Test

Use MRuby 57672 because it already exposed the function/block ambiguity.

Run:

- `--symbolic-execution off`
- `--symbolic-execution symcc`

Use the same static report, same model, same time budget, same target image.
The purpose of this first run is not to prove SymCC improves success rate. The
purpose is to verify that the transcript contains correct feedback use:

- the agent sees observed source locations;
- the agent does not treat block-distance zero as exact reach;
- the agent changes input based on exact observed locations or clear unknown
  states;
- non-target crashes are preserved separately.

### 5.4 Benchmark Expansion

Only after the feedback semantics pass the MRuby smoke test should we expand to
more CyberGym/ARVO targets.

Recommended first batch:

- MRuby 57672, kept as the known complex lifecycle case;
- ARVO 62290, kept because it exposed additional-crash and target-anchor issues;
- one Ghostscript Type2 target;
- two more CyberGym targets selected for clear static reports and stable build
  artifacts.

For each target:

```text
off group:      3 runs, 3600s each
feedback group: 3 runs, 3600s each
```

The report should not collapse results into "SymCC good/bad". It should answer:

1. Did feedback help the agent reach the exact target operation?
2. Did exact target reach lead to a valid PoC faster?
3. Did feedback create distractions or wrong confidence?
4. Did it discover extra crashes?
5. Were failures caused by feedback quality, agent behavior, target mismatch, or
   environment/tooling?

## 6. Work Order

1. Implement schema and summarization changes in `harness/symbolic/feedback.py`.
2. Update compact feedback delivery in the execution protocol and worker.
3. Update prompt wording so exact operation reach is mandatory for candidate
   validation.
4. Add reconciliation logic that machine evidence overrides agent claims.
5. Add additional-crash preservation.
6. Add or update unit tests.
7. Run canary calibration.
8. Run one MRuby 57672 smoke test.
9. Only then run paired benchmark experiments.

This order is intentional: the benchmark should test whether better feedback
helps, not whether the feedback itself is internally ambiguous.

## 7. Success Criteria

The modification is considered useful only if all of the following hold:

1. The agent-facing feedback never equates basic-block distance zero with exact
   target reach.
2. Exact target reach is tied to operation/source marker evidence, or is
   explicitly `unknown`.
3. The transcript shows the agent using feedback as evidence while still doing
   source-level reasoning.
4. Non-target crashes are retained as valuable independent findings.
5. Experiment reports can separate target-site approach, PoC generation, grade
   success, and extra finding discovery.

If these criteria are met, then larger-scale experiments become meaningful. If
they are not met, more benchmark runs will mostly produce more noise.

## 8. Implementation Progress

Status as of 2026-10-01:

- Implemented feedback schema v2 fields in `harness/symbolic/feedback.py`:
  `exact_target_reached`, `target_operation_reached`,
  `target_function_entered`, `target_block_entered`,
  `target_anchor_granularity`, and `allowed_conclusion`.
- Changed exact target semantics so a function-only or block-only target can no
  longer authorize an exact operation hit. Function/block evidence is still
  retained as context.
- Updated compact protocol feedback so agent-facing summaries carry exact
  operation fields and `allowed_conclusion`, while CFG distance remains omitted
  from compact navigation feedback.
- Updated SymCC reconciliation so `candidate_ready` requires exact target
  evidence from the request-correlated machine record. A legacy or coarse
  `target_reached=true` cannot override `exact_target_reached=null`.
- Updated static-analysis target guidance to prefer `target_operation` and to
  treat function-only targets as coarse exploration anchors.
- Updated target-anchor normalization to prefer `target_operation`; if only a
  region and function are supplied, the runtime goal falls back to a coarse
  function anchor and does not promote the region start line into an exact
  marker.
- Added protocol metrics for feedback experiments:
  first feedback time, first exact target reach time, first sanitizer time,
  exact-hit counts, unknown-trace counts, SymCC completed/timed-out/crashed job
  counts, generated replay counts, and generated replay exact hits.
- Added focused unit tests for function-only coarse anchors, compact feedback
  fields, exact-machine reconciliation, new target-anchor conversion, and
  protocol metrics.
- Added `tests/test_symcc_feedback_calibration.py`, a tiny canary-style
  calibration suite that explicitly distinguishes function entry, block entry,
  exact operation marker reach, and truncated/unknown traces.
- Added `targets/mruby-arvo-feedback/`, a smoke-test target that points to the
  existing local MRuby 57672 site-feedback image and feedback map:
  `local/arvo-57672-site-feedback-nogit:20260924-sitefix1`.
- Added `targets/mruby-arvo-feedback/static-report-57672-v2.json`, which uses
  `target_operation` for `src/vm.c:398` in `mrb_env_unshare` instead of the old
  coarse report. The map resolves this anchor to 5 source-location markers and
  1 target block in the local image.

> 2026-10-09 注：`targets/mruby-arvo-feedback/` 及 `static-report-57672-v2.json` 已于 2026-10-08 删除（提交 `a1bb97d6e`），本文保留的是当时的事实。各版本内容、使用波次与最后使用版见 [`experiment-records/2026-10-09-mruby-57672-static-report-versions.md`](experiment-records/2026-10-09-mruby-57672-static-report-versions.md)。

Verified commands:

```sh
.venv/bin/python -m pytest \
  tests/test_symcc_feedback_calibration.py \
  tests/test_symcc_feedback.py \
  tests/test_execution_protocol.py \
  tests/test_symcc_iteration_reconciliation.py \
  tests/test_additional_crashes.py \
  tests/test_find_split.py

.venv/bin/python -m pytest
```

Latest result: 496 passed, 5 skipped.

MRuby 57672 v2 feedback smoke command:

```sh
.venv/bin/python -m harness.cli dynamic targets/mruby-arvo-feedback \
  --static-report targets/mruby-arvo-feedback/static-report-57672-v2.json \
  --model deepseek-flash \
  --symbolic-execution symcc \
  --max-iterations 1 \
  --phase-timeout 300 \
  --results-dir results/experiments/symcc-feedback-stabilization-smoke-20261001 \
  --dangerously-no-sandbox
```

Smoke result:

- The run did not produce a PoC, which is expected for a short one-iteration
  protocol smoke.
- The first request was submitted after 142.51 seconds.
- The persisted machine evidence correctly reported:
  - `exact_target_reached=false`;
  - `target_operation_reached=false`;
  - `target_function_entered=true`;
  - `target_block_entered=false`;
  - `target_anchor_granularity=source_location`;
  - `allowed_conclusion="entered the target function, but did not observe the
    precise target operation marker"`;
  - closest observed location `src/vm.c:397 in mrb_env_unshare`;
  - heuristic distance `1`.
- The SymCC side produced 8 generated replays, but the request-level SymCC job
  timed out before finding an exact marker hit.
- Reconciliation preserved the machine conclusion and did not allow the
  function-entry evidence to become `candidate_ready`.

The smoke test confirms that the v2 machine-evidence path now prevents the old
false-positive interpretation: entering `mrb_env_unshare` no longer means the
operation at `src/vm.c:398` was reached.

It also exposed two remaining workflow issues:

1. The agent submitted the first executable input within five minutes, but only
   after many tool calls. The current "first input early" rule is prompt-only;
   the harness does not yet enforce or report a tool-call deadline.
2. The final reconciled artifact had ready SymCC evidence, but the agent's final
   message still described the feedback as pending. This means late feedback is
   captured by the harness, but may not be consumed by the agent before a short
   phase ends.

Follow-up implementation:

- Added harness-visible first-input policy metrics to the SymCC prebuilt
  summary:
  - `first_request_policy.time_ok`;
  - `first_request_policy.tool_call_ok`;
  - `first_request_policy.first_request_tool_calls`;
  - `first_request_policy.satisfied`;
  - warning entries when the first runnable input misses the prompt-level time
    or tool-call deadline.
- Added feedback delivery accounting:
  - `feedback_ready`;
  - `feedback_ready_not_auto_delivered`;
  - `feedback_ready_not_auto_delivered_ids`.
- Kept the protocol asynchronous: the worker still does not block PoC
  exploration waiting for SymCC. The new fields explain whether ready feedback
  reached the agent through a later `run-input` response or remained only as a
  persisted artifact.
- Strengthened protocol/prompt text: before ending without a validated PoC, the
  agent must perform one nonblocking `read-feedback REQUEST_ID` check for recent
  queued/pending requests and preserve exact-target fields or pending status in
  the final evidence.

Follow-up verified commands:

```sh
.venv/bin/python -m pytest \
  tests/test_execution_protocol.py \
  tests/test_symcc_iteration_reconciliation.py \
  tests/test_symcc_feedback_calibration.py \
  tests/test_symcc_feedback.py

.venv/bin/python -m pytest
```

Latest follow-up result: 498 passed, 5 skipped.

Second MRuby 57672 smoke command:

```sh
.venv/bin/python -m harness.cli dynamic targets/mruby-arvo-feedback \
  --static-report targets/mruby-arvo-feedback/static-report-57672-v2.json \
  --model deepseek-flash \
  --symbolic-execution symcc \
  --max-iterations 2 \
  --phase-timeout 600 \
  --results-dir results/experiments/symcc-feedback-stabilization-smoke2-20261001 \
  --dangerously-no-sandbox
```

Second smoke result:

- Final status: `iteration_exhausted`.
- Dynamic wall time: 447.17 seconds.
- Agent tool calls: 164.
- Accepted protocol requests: 2.
- `time_to_first_request_s=136.705`, so the first input was submitted within
  five minutes.
- `first_request_policy.first_request_tool_calls=57`, so the first input missed
  the 25-tool-call prompt deadline. The new summary correctly reports:
  `first_request_policy.satisfied=false`, `time_ok=true`, `tool_call_ok=false`.
- `feedback_auto_delivered=1`: round-001 SymCC feedback was automatically
  delivered with a later protocol response and the agent consumed it.
- round-001 evidence was interpreted correctly:
  - complete trace;
  - `target_function_entered=true`;
  - `exact_target_reached=false`;
  - `target_operation_reached=false`;
  - `allowed_conclusion` preserved;
  - the iteration was recorded as a concrete miss for that input, not a false
    positive for the whole candidate.
- round-002 clean execution produced an ASan `negative-size-param` crash in
  `str_bytesplice`, not in the MRuby environment unshare candidate path. The
  agent preserved it through the additional-crash channel instead of using it
  to validate the original candidate.
- round-002 SymCC feedback was still pending when the agent finalized; the
  worker abandoned that background job on phase end, so the SymCC summary is
  `status=incomplete` with `symcc_abandoned=1`.

This smoke test validates two important pieces of the new design:

1. The v2 feedback semantics are now understandable by the agent when delivered:
   it used exact-operation fields and did not confuse target-function entry with
   candidate reach.
2. Additional target crashes can be preserved without contaminating the
   original candidate status.

It also shows that prompt-only deadline control is insufficient. The model
still spent 57 tool calls before the first input even though the prompt says the
first runnable input must be submitted within 25 meaningful tool calls. If early
execution feedback is important to the experiment, the next implementation
should add a harness-enforced or agent-runner-enforced early-input mechanism
instead of relying only on wording.

Early-input watchdog implementation:

- Added an optional `progress_nudge` hook to `harness.agent.run_agent`.
  It is disabled by default and therefore does not affect other phases.
- In prebuilt SymCC dynamic validation, the hook checks whether the agent has
  approached the 25-tool-call first-input deadline without any
  execution-protocol request appearing under the pending/processed/response
  directories. The nudge currently fires at 20 tool calls so the agent still has
  room to write the input file, write the request JSON, and execute `run-input`
  within the 25-tool-call policy.
- If that happens, the runner terminates the current opencode invocation and
  resumes the same session with a corrective prompt requiring an immediate
  baseline/candidate `run-input` submission.
- This is not a generic PoC-generation shortcut. It only prevents the agent
  from spending the entire early phase on source reconnaissance before any
  executable feedback exists.

Watchdog tests:

```sh
.venv/bin/python -m pytest tests/test_agent.py tests/test_execution_protocol.py
.venv/bin/python -m pytest
```

Latest watchdog result: 501 passed, 5 skipped.

First watchdog smoke:

- Command: same MRuby 57672 target with `--max-iterations 1` and
  `--phase-timeout 300`.
- The watchdog fired after the old threshold and forced a first request, but
  the measured `first_request_policy.first_request_tool_calls` was 26. This was
  one call over the policy because the corrective `run-input` itself consumes
  the next tool call.
- The threshold was therefore moved one step earlier, from 25 to 24 tool calls.

Second watchdog smoke:

```sh
.venv/bin/python -m harness.cli dynamic targets/mruby-arvo-feedback \
  --static-report targets/mruby-arvo-feedback/static-report-57672-v2.json \
  --model deepseek-flash \
  --symbolic-execution symcc \
  --max-iterations 1 \
  --phase-timeout 180 \
  --results-dir results/experiments/symcc-feedback-stabilization-watchdog-smoke2-20261001 \
  --dangerously-no-sandbox
```

Result:

- Final dynamic status: `reached_no_crash`.
- Dynamic wall time: 76.57 seconds.
- First request time: `time_to_first_request_s=40.399`.
- First request tool calls: `first_request_policy.first_request_tool_calls=8`.
- `first_request_policy.satisfied=true`, `time_ok=true`, and
  `tool_call_ok=true`.
- The single clean request exited normally with no sanitizer event.
- Because this was a one-iteration short smoke, the agent ended before the
  background SymCC job was ready; the record correctly reports
  `feedback_status=abandoned_agent_finished` and exact target reach remains
  unknown.

This confirms the early-input mechanism can satisfy the policy in practice.
It does not replace the earlier two-iteration smoke, which remains the evidence
that delivered feedback is semantically interpreted correctly.

Third watchdog smoke:

- Command: same MRuby 57672 target with `--max-iterations 2` and
  `--phase-timeout 600`.
- The watchdog fired at 24 tool calls and the agent then submitted a first
  request, but the measured first request still landed at 28 tool calls because
  the agent needed additional file-writing calls before `run-input`.
- The first request was still timely by wall clock (`time_to_first_request_s`
  around 73.8 seconds), and SymCC eventually produced ready feedback:
  `target_function_entered=true`, `exact_target_reached=false`,
  `target_operation_reached=false`, with the expected `allowed_conclusion`.
- The feedback was not auto-delivered to the agent before finalization
  (`feedback_ready_not_auto_delivered=1`), but reconciliation attached the
  machine evidence to the iteration.
- Based on this run, the nudge was moved earlier again, from 24 to 20 tool
  calls, so the corrective prompt leaves enough tool budget for the actual
  input/request submission sequence.

Fourth watchdog smoke:

- Command: same MRuby 57672 target with `--max-iterations 1` and
  `--phase-timeout 180`.
- The first request was submitted very early:
  `time_to_first_request_s=19.907`,
  `first_request_policy.first_request_tool_calls=7`,
  `first_request_policy.satisfied=true`.
- The agent ended before SymCC feedback was ready, so the record correctly
  remained `feedback_status=abandoned_agent_finished` and exact reachability
  was unknown.
- The run exposed a final-status consistency issue: the model reported
  `reached_no_crash` based on source reasoning while machine evidence had not
  confirmed an exact operation hit.

Final-status correction:

- Added a SymCC-specific missing-PoC status guard: if the final inline status is
  `reached_no_crash` or `reached_no_effect`, but no iteration has
  `exact_target_reached=true` or `target_operation_reached=true`, the harness
  downgrades the result to `iteration_exhausted`.
- This keeps the same evidence boundary used for PoC acceptance: model-only
  reasoning, function entry, nearby block evidence, and pending traces cannot
  mark the candidate path reached.
- If an exact target operation hit is present, `reached_no_crash` is preserved.

Correction tests:

```sh
.venv/bin/python -m pytest \
  tests/test_symcc_iteration_reconciliation.py \
  tests/test_execution_protocol.py \
  tests/test_agent.py

.venv/bin/python -m pytest
```

Latest correction result: 503 passed, 5 skipped.

Fifth watchdog smoke:

- Command: same MRuby 57672 target with `--max-iterations 2` and
  `--phase-timeout 600`.
- The first request policy worked:
  `time_to_first_request_s=42.953`,
  `first_request_policy.first_request_tool_calls=15`, and
  `first_request_policy.satisfied=true`.
- SymCC feedback became ready at about 166.8 seconds.  The reconciled machine
  evidence again showed a useful but non-exact hit:
  `target_function_entered=true`, `target_operation_reached=false`, and
  `exact_target_reached=false`.
- The run still ended as `agent_blocked` after the 600-second phase timeout.
  The agent kept reading and manually testing source-level hypotheses after the
  feedback was ready, but did not submit a second execution-protocol request and
  did not reliably consume the ready feedback through `read-feedback`.

This identifies a second stabilization boundary: the first executable input is
now constrained, but ready feedback also needs an explicit delivery nudge.

Feedback-readiness nudge:

- Added a combined prebuilt progress nudge used by the SymCC dynamic agent.
- The first half preserves the existing early-input behavior: before the first
  protocol request, the agent is interrupted near the tool-call deadline and is
  required to submit a runnable input through `/work/validation/run-input`.
- The second half watches the execution-protocol directories.  If exactly one
  request has been submitted and a matching feedback JSON is ready, but no
  follow-up request exists yet, the agent is interrupted and must run
  `/work/validation/read-feedback REQUEST_ID` before continuing.
- The corrective prompt requires the agent to preserve the machine fields
  `exact_target_reached`, `target_operation_reached`,
  `target_function_entered`, `allowed_conclusion`,
  `best_actual_locations`, and generated replay inputs, then immediately either
  submit the next improved protocol input or finalize with evidence.
- Request counting deduplicates the same request id across `processed/` and
  `responses/`, so a normal completed request is still treated as one request.

Focused regression after this change:

```sh
.venv/bin/python -m pytest \
  tests/test_execution_protocol.py \
  tests/test_agent.py \
  tests/test_symcc_feedback.py \
  tests/test_symcc_feedback_calibration.py \
  tests/test_symcc_iteration_reconciliation.py \
  tests/test_find_split.py
```

Result: 93 passed.

Sixth watchdog smoke:

- Command: same MRuby 57672 target with `--max-iterations 2` and
  `--phase-timeout 600`.
- First request remained within policy:
  `time_to_first_request_s=48.012`,
  `first_request_policy.first_request_tool_calls=22`, and
  `first_request_policy.satisfied=true`.
- The first progress nudge fired at 20 tool calls and caused the agent to
  submit `round-001` through the execution protocol.
- The second progress nudge fired when `round-001` feedback became ready.  The
  agent then consumed the feedback, wrote a round-001 iteration record, and
  submitted `round-002` instead of continuing unbounded source reading.
- Protocol summary confirmed the desired loop shape:
  `requests=2`, `feedback_ready=2`, `feedback_auto_delivered=1`,
  `symcc_abandoned=0`, and two reconciled iteration records.
- Both concrete traces entered `mrb_env_unshare` but did not hit the exact
  source-operation marker:
  `target_function_entered=true`,
  `target_operation_reached=false`, and `exact_target_reached=false`.
- The run ended as `invalid_submission` because the agent failed to emit the
  final inline `<dynamic_status>` XML tags after exhausting the two iterations.
  This is a final-status formatting failure, not a feedback-loop failure.

Final-status contract hardening:

- `/work/validation/README.md` now includes the exact inline XML status template
  for no-PoC/no-crash conclusions:

```xml
<dynamic_status>iteration_exhausted</dynamic_status>
<candidate_id>...</candidate_id>
<reached_functions>...</reached_functions>
<reachability_evidence>...</reachability_evidence>
<reason>...</reason>
```

- The README also lists the allowed `dynamic_status` values and explicitly says
  to prefer `iteration_exhausted` when the iteration budget is consumed without
  a validated PoC.
- This prevents the agent from searching the container filesystem for an
  implicit status format at the end of the dynamic phase.

Current regression status:

```sh
.venv/bin/python -m pytest
```

Result: 508 passed, 5 skipped.

Seventh watchdog smoke:

- Command: same MRuby 57672 target with `--max-iterations 2` and
  `--phase-timeout 600` after adding the final-status template.
- The run submitted a first request very quickly
  (`time_to_first_request_s=15.270`, first request at 6 tool calls), and SymCC
  completed quickly (`time_to_first_feedback_s=24.067`).
- Because feedback was ready almost immediately, the feedback-readiness nudge
  fired at only 9 tool calls.  This was too early: the agent had not had enough
  time to form a source-level hypothesis or write a useful iteration record, and
  the run ended as `invalid_submission`.

This shows that feedback delivery must not become an immediate interruption
when SymCC finishes quickly.  The purpose of the feedback is to correct a
stalled or wandering PoC search, not to preempt the agent before it has built
minimal semantic context.

Feedback nudge grace period:

- Added a grace rule after observing the first protocol request.
- The feedback-readiness nudge now waits until both conditions hold:
  1. at least `_FIRST_INPUT_TOOL_CALL_LIMIT` tool calls have occurred; and
  2. at least `_FEEDBACK_READY_NUDGE_GRACE_TOOL_CALLS` additional tool calls
     have elapsed after the first request was observed.
- This preserves the useful behavior from the sixth smoke, where feedback
  corrected prolonged source reading, while avoiding the seventh smoke's
  over-eager interruption.
- Regression status after this change remains:

```sh
.venv/bin/python -m pytest
```

Result: 508 passed, 5 skipped.

Eighth watchdog smoke:

- Command: same MRuby 57672 target with `--max-iterations 2` and
  `--phase-timeout 600` after adding the feedback-readiness grace period and
  final-status README template.
- The first progress nudge fired at 20 tool calls; the agent submitted the
  first request through the execution protocol instead of continuing open-ended
  source reconnaissance.
- The feedback nudge did not fire prematurely.  The agent had time to continue
  source analysis, submit a second request, read both feedback files, write two
  iteration records, and emit final inline status tags.
- Final parsed status:
  `dynamic_status=iteration_exhausted`.
- Runtime summary:
  - `dynamic_validation=333.868s`;
  - `execution_protocol_requests=2`;
  - `first_request_policy.satisfied=true`;
  - `first_request_policy.first_request_tool_calls=22`;
  - `feedback_ready=2`;
  - `symcc_abandoned=0`;
  - `generated_replays=16`;
  - `exact_target_hit_records=0`.
- Reconciled machine evidence for both rounds:
  `target_function_entered=true`,
  `target_operation_reached=false`,
  `exact_target_reached=false`,
  `clean_status=completed`, and `sanitizer_event=false`.
- The final transcript contains the expected XML tags:

```xml
<dynamic_status>iteration_exhausted</dynamic_status>
<candidate_id>candidate_001</candidate_id>
<reached_functions>mrb_env_unshare,mrb_vm_run,mrb_top_run,stack_extend</reached_functions>
...
```

This is the first smoke that satisfies the intended stabilization contract:
early executable input, no premature feedback interruption, ready-feedback
consumption, bounded iteration, and parseable final status.

Feedback consumption metrics:

- The execution protocol now records manual `read-feedback` calls in
  `/work/validation/execution/feedback-reads.jsonl`.
- The worker summary keeps the old compatibility fields:
  - `feedback_auto_delivered`;
  - `feedback_ready_not_auto_delivered`;
  - `feedback_ready_not_auto_delivered_ids`.
- The summary also adds explicit consumption fields:
  - `feedback_manual_reads`: total `read-feedback` calls observed by the
    protocol;
  - `feedback_manually_read_ids`: unique request IDs that were queried;
  - `feedback_ready_manually_read`: number of request IDs read while the
    feedback was already ready;
  - `feedback_ready_manually_read_ids`;
  - `feedback_ready_unconsumed`: ready feedback that was neither auto-delivered
    through a later `run-input` response nor manually read in ready state;
  - `feedback_ready_unconsumed_ids`.

This fixes the smoke8 accounting ambiguity.  A feedback record can now be
"not auto-delivered" and still be correctly counted as consumed if the agent
called `read-feedback` after it became ready.  A pending read does not count as
consumption, because it did not give the agent the machine evidence.

Regression status after this metric change:

```sh
.venv/bin/python -m pytest \
  tests/test_execution_protocol.py \
  tests/test_agent.py \
  tests/test_symcc_feedback.py \
  tests/test_symcc_feedback_calibration.py \
  tests/test_symcc_iteration_reconciliation.py \
  tests/test_find_split.py

.venv/bin/python -m pytest
```

Results: 94 focused tests passed; full suite 508 passed, 5 skipped.

Metric-confirmation smoke:

- Command: same MRuby 57672 target with `--max-iterations 2` and
  `--phase-timeout 600`, after adding manual feedback-read accounting.
- The new metrics matched the transcript:
  - `feedback_ready=1`;
  - `feedback_auto_delivered=0`;
  - `feedback_ready_not_auto_delivered=1`;
  - `feedback_manual_reads=4`;
  - `feedback_ready_manually_read=1`;
  - `feedback_ready_unconsumed=0`.
- This proves that a ready feedback record can be counted as consumed even when
  it was not auto-delivered through a later `run-input` response.
- The run nevertheless ended as `agent_blocked` after 600 seconds.  The agent
  had consumed ready feedback and knew it still had one request left, but kept
  reading source and feedback-map context instead of submitting `round-002`.

Post-feedback-read follow-up nudge:

- Added a third progress nudge after feedback consumption.
- Trigger condition:
  1. exactly one protocol request exists;
  2. the agent has manually read ready feedback for that request;
  3. no follow-up request exists; and
  4. a small tool-call grace period after the ready read has elapsed.
- Corrective action: the next tool call must either submit a fresh `round-002`
  request through `/work/validation/run-input`, or write the iteration record
  and emit final inline status tags if stopping is justified by the evidence.
- This is intentionally separate from the "feedback is ready, read it" nudge.
  The first nudge ensures evidence is consumed; the follow-up nudge prevents
  endless semantic reconnaissance after the evidence has already been consumed.

Regression status after the follow-up nudge:

```sh
.venv/bin/python -m pytest \
  tests/test_execution_protocol.py \
  tests/test_agent.py \
  tests/test_symcc_feedback.py \
  tests/test_symcc_feedback_calibration.py \
  tests/test_symcc_iteration_reconciliation.py \
  tests/test_find_split.py

.venv/bin/python -m pytest
```

Results: 96 focused tests passed; full suite 510 passed, 5 skipped.

Follow-up nudge smoke:

- Command: same MRuby 57672 target with `--max-iterations 2` and
  `--phase-timeout 600`.
- The first-input nudge fired at 20 tool calls.
- The feedback-ready nudge fired at 53 tool calls.
- The post-feedback-read follow-up nudge fired at 74 tool calls.
- The third nudge succeeded in the important behavioral sense: the agent
  submitted `round-002`, consumed both feedback records, wrote both iteration
  records, and emitted final inline XML tags.
- Summary:
  - `execution_protocol_requests=2`;
  - `feedback_ready=2`;
  - `feedback_auto_delivered=1`;
  - `feedback_manual_reads=20`;
  - `feedback_ready_manually_read=2`;
  - `feedback_ready_unconsumed=0`;
  - `first_request_policy.satisfied=true`;
  - `exact_target_hit_records=0`.
- Both rounds had reconciled machine evidence:
  `target_function_entered=true`,
  `target_operation_reached=false`,
  `exact_target_reached=false`,
  `clean_status=completed`, and `sanitizer_event=false`.
- The remaining issue was status priority: the transcript contained
  `<dynamic_status>iteration_exhausted</dynamic_status>`, but the harness still
  reported `agent_blocked` because the agent process hit the phase watchdog
  immediately after producing the final text.

Final-status precedence fix:

- In the no-PoC branch, a valid inline `dynamic_status` now takes precedence
  over a later `agent/model_blocked` or other backend error.
- Backend errors still produce `agent_blocked`/`agent_failed` when no valid
  inline status exists.
- This preserves the evidence contract: a completed, parseable final answer
  should not be discarded solely because the backend exited poorly after the
  answer was already present in the transcript.
- Regression status after this fix:

```sh
.venv/bin/python -m pytest \
  tests/test_execution_protocol.py \
  tests/test_agent.py \
  tests/test_symcc_feedback.py \
  tests/test_symcc_feedback_calibration.py \
  tests/test_symcc_iteration_reconciliation.py \
  tests/test_find_split.py

.venv/bin/python -m pytest
```

Results: 97 focused tests passed; full suite 511 passed, 5 skipped.

Remaining work:

- Run paired off/feedback experiments using the stabilized protocol.  The smoke
  gate is now satisfied for MRuby, but larger comparisons still need repeated
  runs and more targets.
- Run one more MRuby feedback smoke after the final-status precedence fix.  The
  expected terminal status is `iteration_exhausted`, not `agent_blocked`, when
  the agent emits valid final tags after consuming the full iteration budget.

Evidence ledger implementation:

- Added an experiment-facing evidence ledger for prebuilt SymCC dynamic
  validation.  The ledger is derived from machine-owned execution-protocol
  records and the `read-feedback` audit log, not from the agent's textual
  explanation.
- Each SymCC protocol summary now contains `evidence_ledger`, and the same
  event stream is written as JSONL to:
  - `symbolic_execution/evidence_ledger.jsonl`;
  - the dynamic run root as `evidence_ledger.jsonl` when the result path is the
    standard `symbolic_execution` directory.
- The ledger currently records:
  - accepted or rejected execution requests;
  - ordinary target execution results;
  - sanitizer events observed by the ordinary target;
  - SymCC feedback readiness, exact-target evidence and generated replay
    counts;
  - abandoned SymCC feedback;
  - manual `read-feedback` calls with ready/pending status.
- The `read-feedback` helper now appends `wall_time_s` to
  `feedback-reads.jsonl`, allowing the ledger to reconstruct whether feedback
  was read before or after it became ready.
- Focused regression covered the new ledger and existing protocol behavior:

```sh
.venv/bin/python -m pytest tests/test_execution_protocol.py
.venv/bin/python -m pytest \
  tests/test_execution_protocol.py \
  tests/test_agent.py \
  tests/test_symcc_feedback.py \
  tests/test_symcc_feedback_calibration.py \
  tests/test_symcc_iteration_reconciliation.py \
  tests/test_additional_crashes.py \
  tests/test_find_split.py
```

Results: 42 protocol tests passed; 105 focused dynamic/SymCC tests passed.

Status-breakdown and no-wait feedback correction:

- A subsequent MRuby 57672 smoke showed the new ledger working but exposed a
  behavioral issue: after submitting `round-002`, the agent ran a long
  `sleep 180; read-feedback` command waiting for SymCC.  It eventually read
  ready feedback but had almost no phase budget left to emit final
  `<dynamic_status>` tags, so the run ended as `invalid_submission`.
- This run was useful because the evidence ledger made the failure mode
  unambiguous:
  - `round-001` was accepted at 52.334s;
  - `round-001` feedback was ready at 176.021s and read at 179.313s;
  - `round-002` was accepted at 393.910s;
  - `round-002` feedback was pending through several reads;
  - `round-002` feedback became ready at 517.523s and was read at 518.313s;
  - the final status contract was not satisfied before the 600s budget ended.
- Implemented a result `status_breakdown` attached to
  `DynamicValidationResult`.  The top-level legacy status is preserved, but the
  result now also reports:
  - `target_site_status`;
  - `poc_status`;
  - `grade_status`;
  - `additional_findings_status`;
  - `feedback_quality_status`.
- Strengthened the prebuilt SymCC prompt and execution README:
  - `sleep`, `timeout sleep`, `watch`, polling loops, and blocking waits for
    SymCC feedback are forbidden;
  - if feedback is still pending at the final check or request limit, the agent
    must report pending status immediately instead of waiting for it to become
    ready.
- Added tests for the status breakdown and the no-wait wording.

Regression:

```sh
.venv/bin/python -m pytest \
  tests/test_find_split.py \
  tests/test_execution_protocol.py \
  tests/test_symcc_iteration_reconciliation.py

.venv/bin/python -m pytest \
  tests/test_execution_protocol.py \
  tests/test_agent.py \
  tests/test_symcc_feedback.py \
  tests/test_symcc_feedback_calibration.py \
  tests/test_symcc_iteration_reconciliation.py \
  tests/test_additional_crashes.py \
  tests/test_find_split.py

.venv/bin/python -m pytest
```

Results: 74 related tests passed; 106 focused dynamic/SymCC tests passed; full
suite 514 passed, 5 skipped.

No-wait MRuby smoke:

```sh
.venv/bin/python -m harness.cli dynamic targets/mruby-arvo-feedback \
  --static-report targets/mruby-arvo-feedback/static-report-57672-v2.json \
  --model deepseek-flash \
  --symbolic-execution symcc \
  --max-iterations 2 \
  --phase-timeout 600 \
  --results-dir results/experiments/symcc-feedback-no-wait-smoke-20261001 \
  --dangerously-no-sandbox
```

Result directory:

`results/experiments/symcc-feedback-no-wait-smoke-20261001/mruby-arvo-feedback/dynamic-20261001T142515Z`

Result:

- Final dynamic status: `iteration_exhausted`.
- `status_breakdown`:
  - `target_site_status=function_only`;
  - `poc_status=no_poc`;
  - `grade_status=not_run`;
  - `additional_findings_status=none`;
  - `feedback_quality_status=consumed_no_improvement`.
- Runtime:
  - `dynamic_validation=247.257s`;
  - `execution_protocol_requests=1`;
  - `first_request_policy.satisfied=true`;
  - first request at 20 tool calls;
  - `feedback_ready=1`;
  - `feedback_ready_manually_read=1`;
  - `feedback_ready_unconsumed=0`;
  - `symcc_completed_jobs=1`;
  - `generated_replays=8`;
  - `exact_target_hit_records=0`.
- Evidence ledger was written to both:
  - `evidence_ledger.jsonl`;
  - `symbolic_execution/evidence_ledger.jsonl`.
- Ledger sequence:
  - request accepted at 72.378s;
  - ordinary target completed without ASan;
  - first feedback read was pending at 77.419s;
  - SymCC feedback became ready at 86.397s;
  - ready feedback was read at 86.419s;
  - the final result correctly separated function-only approach from missing PoC.

This smoke validates the intended stabilization behavior for a short MRuby run:
early input, no blocking wait for SymCC, ready feedback consumption, explicit
status breakdown, and parseable final status.

Minimal paired MRuby smoke:

After the no-wait feedback smoke, an `off`-arm smoke was run with the same
target, static report, model, iteration limit, and 600s phase budget:

```sh
.venv/bin/python -m harness.cli dynamic targets/mruby-arvo-feedback \
  --static-report targets/mruby-arvo-feedback/static-report-57672-v2.json \
  --model deepseek-flash \
  --symbolic-execution off \
  --max-iterations 2 \
  --phase-timeout 600 \
  --results-dir results/experiments/symcc-feedback-paired-smoke-20261002/off \
  --dangerously-no-sandbox
```

Off-arm result directory:

`results/experiments/symcc-feedback-paired-smoke-20261002/off/mruby-arvo-feedback/dynamic-20261002T033121Z`

Comparison with the preceding feedback smoke:

| Arm | Status | Wall time | Tool calls | Requests | Target-site status | Feedback quality |
| --- | --- | ---: | ---: | ---: | --- | --- |
| off | `reached_no_crash` | 342.918s | 70 | n/a | `unknown` | `unavailable` |
| feedback | `iteration_exhausted` | 247.257s | 43 | 1 | `function_only` | `consumed_no_improvement` |

Interpretation:

- This is only a smoke pair, not a statistical result.
- The `off` arm could make a model-level reachability claim, but the new
  `status_breakdown` correctly keeps `target_site_status=unknown` because there
  is no machine-owned exact-target evidence.
- The feedback arm produced a lower-confidence top-level conclusion
  (`iteration_exhausted`), but a more explainable one: machine evidence showed
  function entry without exact operation marker reach.
- The feedback arm also consumed less wall time and fewer tool calls in this
  short run, and its ledger explains exactly what happened.
- This supports the next experiment step: run repeated off/feedback pairs with
  the same status-breakdown and evidence-ledger analysis, rather than judging
  by the overloaded legacy status alone.

Experiment summary CLI:

- Added `harness/experiment_summary.py`, a post-hoc summarizer for
  `dynamic_validation.json` experiment trees.
- Added the CLI command:

```sh
.venv/bin/python -m harness.cli summarize-experiments <result-dir>...
```

- The command accepts one or more result roots, finds nested
  `dynamic_validation.json` files, and emits:
  - a machine-readable JSON summary;
  - a Markdown table suitable for experiment notes and reports;
  - aggregate grouping by `off` and `feedback` arm;
  - per-run wall time, tool calls, request counts, status breakdown, feedback
    quality, ready/read/unconsumed feedback counts, exact-hit counters,
    generated replay counts, additional-finding status, and evidence-ledger
    event counts.
- Added `tests/test_experiment_summary.py` to cover loading one dynamic run,
  grouping by arm, rendering Markdown, and reading SymCC metrics from
  `symbolic_execution/summary.json`.

Verification command:

```sh
.venv/bin/python -m harness.cli summarize-experiments \
  results/experiments/symcc-feedback-paired-smoke-20261002 \
  results/experiments/symcc-feedback-no-wait-smoke-20261001 \
  --json-out results/experiments/symcc-feedback-paired-smoke-20261002/summary.json \
  --markdown-out results/experiments/symcc-feedback-paired-smoke-20261002/summary.md
```

Generated summary:

| Arm | Runs | Validated | Avg wall s | Avg tool calls | Exact target hits | Feedback consumed | Feedback unconsumed | Additional crash runs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| feedback | 1 | 0 | 247.257 | 43 | 0 | 1 | 0 | 0 |
| off | 1 | 0 | 342.918 | 70 | 0 | 0 | 0 | 0 |

The summary also preserves per-run detail:

| Arm | Target | Status | Target site | PoC | Additional | Feedback | Ready/Read/Unconsumed | Requests | Ledger |
| --- | --- | --- | --- | --- | --- | --- | ---: | ---: | ---: |
| feedback | mruby-arvo-feedback | `iteration_exhausted` | `function_only` | `no_poc` | `none` | `consumed_no_improvement` | 1/1/0 | 1 | 6 |
| off | mruby-arvo-feedback | `reached_no_crash` | `unknown` | `no_poc` | `none` | `unavailable` | -/-/- | n/a | 0 |

Regression after adding the summarizer:

```sh
.venv/bin/python -m pytest tests/test_experiment_summary.py -q

.venv/bin/python -m pytest \
  tests/test_experiment_summary.py \
  tests/test_execution_protocol.py \
  tests/test_find_split.py \
  tests/test_symcc_iteration_reconciliation.py -q

.venv/bin/python -m pytest -q
```

Results after the first summarizer implementation: experiment-summary tests
passed; 76 focused tests passed; full suite 516 passed, 5 skipped.

The summary tables were then expanded to surface feedback consumption and
additional-finding counts directly in both aggregate and per-run rows.  This
keeps future experiment analysis from collapsing "feedback unavailable",
"feedback ready but unread", and "feedback consumed but no improvement" into
one bucket.

Regression after the expanded summary table:

```sh
.venv/bin/python -m pytest tests/test_experiment_summary.py -q

.venv/bin/python -m pytest \
  tests/test_experiment_summary.py \
  tests/test_execution_protocol.py \
  tests/test_find_split.py \
  tests/test_symcc_iteration_reconciliation.py -q

.venv/bin/python -m pytest -q
```

Results: experiment-summary tests passed; 76 focused tests passed; full suite
516 passed, 5 skipped.

Generic off-arm evidence ledger:

- The prebuilt SymCC path already writes a machine-owned evidence ledger from
  protocol request records and feedback-read audit logs.  The off arm did not
  previously write any ledger, so summaries could compare high-level status but
  not the presence or absence of dynamic evidence.
- Added a provider-neutral generic ledger for non-SymCC dynamic runs.  It is
  derived from bounded dynamic artifacts rather than agent narration:
  - persisted iteration records;
  - additional crash submissions;
  - accepted final crash or logic PoC artifact;
  - final dynamic status and `status_breakdown`.
- The generic ledger is written to the dynamic run root as:

```text
evidence_ledger.jsonl
```

- This does not pretend that off has SymCC evidence.  It simply gives off runs
  a comparable audit spine so later summaries can distinguish "no protocol
  evidence existed" from "no ledger was produced".

Focused tests:

```sh
.venv/bin/python -m pytest \
  tests/test_find_split.py \
  tests/test_experiment_summary.py \
  tests/test_execution_protocol.py \
  tests/test_symcc_iteration_reconciliation.py -q
```

Result: 77 passed.

Short off-arm ledger smoke:

```sh
.venv/bin/python -m harness.cli dynamic targets/mruby-arvo-feedback \
  --static-report targets/mruby-arvo-feedback/static-report-57672-v2.json \
  --model deepseek-flash \
  --symbolic-execution off \
  --max-iterations 1 \
  --phase-timeout 180 \
  --results-dir results/experiments/off-generic-ledger-smoke-20261002 \
  --dangerously-no-sandbox
```

Result directory:

`results/experiments/off-generic-ledger-smoke-20261002/mruby-arvo-feedback/dynamic-20261002T034920Z`

Result:

- Final dynamic status: `agent_blocked` after the short 180s smoke budget.
- `evidence_ledger.jsonl` was written at the run root.
- The ledger contains a `dynamic_result_finalized` event with:
  - `target_site_status=unknown`;
  - `poc_status=agent_blocked`;
  - `additional_findings_status=none`;
  - `feedback_quality_status=unavailable`.
- The experiment summary CLI reports this off run with `Ledger=1`, confirming
  that non-SymCC runs now have a minimal audit trail.

Full regression after adding the generic off-arm ledger:

```sh
.venv/bin/python -m pytest -q
```

Result: 517 passed, 5 skipped.

Paired dynamic experiment runner:

- Added a dedicated CLI for repeated off/feedback dynamic-validation pairs:

```sh
.venv/bin/python -m harness.cli dynamic-pairs <target> \
  --static-report <static_analysis.json> \
  --model <model> \
  --runs 3 \
  --phase-timeout 3600 \
  --max-iterations 8 \
  --results-dir results/experiments \
  --experiment-name <name> \
  --dangerously-no-sandbox
```

- For each pair, the runner executes the selected arms under fixed variables:
  - `off` maps to `--symbolic-execution off`;
  - `feedback` maps to `--symbolic-execution symcc`;
  - target, static report, candidate id, model, turn budget, iteration budget,
    phase timeout, instrumentation setting, and Docker params are shared.
- Output layout:

```text
<results-dir>/<experiment-name>/
  manifest.json
  summary.json
  summary.md
  pair-1/
    off/<target>/dynamic-.../
    feedback/<target>/dynamic-.../
  pair-2/
    ...
```

- The runner treats both validated and no-PoC dynamic outcomes as completed
  experiment arms.  Infrastructure failures still make the command fail, but a
  normal `iteration_exhausted`, `reached_no_crash`, or no-PoC result does not
  abort later pairs.
- After all arms finish, it automatically runs the experiment summarizer and
  writes `summary.json` and `summary.md` at the experiment root.

This command is intended to reduce experimental drift.  Future 3×off + 3×feedback
runs should use `dynamic-pairs` instead of manually launching six separate
commands.

Regression after adding the paired runner:

```sh
.venv/bin/python -m harness.cli --help

.venv/bin/python -m pytest \
  tests/test_dynamic_pairs_cli.py \
  tests/test_experiment_summary.py \
  tests/test_find_split.py \
  tests/test_execution_protocol.py \
  tests/test_symcc_iteration_reconciliation.py -q

.venv/bin/python -m pytest -q
```

Results: CLI help lists `dynamic-pairs`; 78 focused tests passed; full suite
518 passed, 5 skipped.

Real paired-runner smoke:

The fake-unit test proves dispatch and output wiring.  A short real smoke was
then run against MRuby 57672 to verify that `dynamic-pairs` works with actual
containers, target preparation, agents, manifests, ledgers, and summaries.

Command:

```sh
.venv/bin/python -m harness.cli dynamic-pairs targets/mruby-arvo-feedback \
  --static-report targets/mruby-arvo-feedback/static-report-57672-v2.json \
  --model deepseek-flash \
  --runs 1 \
  --phase-timeout 180 \
  --max-iterations 1 \
  --results-dir results/experiments \
  --experiment-name mruby-dynamic-pairs-smoke-20261002 \
  --dangerously-no-sandbox
```

Result root:

`results/experiments/mruby-dynamic-pairs-smoke-20261002`

Generated files:

```text
manifest.json
summary.json
summary.md
pair-1/off/mruby-arvo-feedback/dynamic-20261002T035640Z/
pair-1/feedback/mruby-arvo-feedback/dynamic-20261002T035943Z/
```

Manifest result:

| Pair | Arm | Symbolic execution | Return code |
| ---: | --- | --- | ---: |
| 1 | off | off | 2 |
| 1 | feedback | symcc | 2 |

Summary:

| Arm | Runs | Status | Wall s | Tool calls | Requests | Ledger | Feedback |
| --- | ---: | --- | ---: | ---: | ---: | ---: | --- |
| off | 1 | `agent_blocked` | 181.969 | 34 | n/a | 1 | unavailable |
| feedback | 1 | `iteration_exhausted` | 70.236 | 26 | 1 | 5 | unavailable |

Feedback-arm ledger sequence:

- execution request `round-001` accepted at 59.737s;
- ordinary ASan target execution completed with exit code 0 and no sanitizer
  event;
- the agent performed two nonblocking `read-feedback` calls while feedback was
  still pending;
- the background SymCC job was abandoned when the short one-iteration smoke
  finished (`symcc_abandoned=1`).

Interpretation:

- This is a workflow smoke only, not a SymCC effectiveness result.
- It verifies that the paired runner can execute both arms, preserve
  non-success dynamic outcomes without aborting the experiment, write per-arm
  ledgers, and automatically produce experiment summaries.
- The 180s/1-iteration budget was intentionally too short for a meaningful
  feedback evaluation; the feedback arm submitted a real protocol request but
  ended before SymCC feedback was ready.

Paired-runner resume support:

- Added `--resume` to `dynamic-pairs`.
- When enabled, the runner checks each `pair-N/<arm>/` directory.  If it already
  contains one or more `dynamic_validation.json` files, that arm is skipped and
  recorded in `manifest.json` with:
  - `skipped=true`;
  - `return_code=null`;
  - `existing_dynamic_results=[...]`.
- Missing arms are still executed normally.  This makes long 1-hour repeated
  experiments recoverable after interruption without re-running completed arms.

Resume command used against the completed smoke experiment:

```sh
.venv/bin/python -m harness.cli dynamic-pairs targets/mruby-arvo-feedback \
  --static-report targets/mruby-arvo-feedback/static-report-57672-v2.json \
  --model deepseek-flash \
  --runs 1 \
  --phase-timeout 180 \
  --max-iterations 1 \
  --results-dir results/experiments \
  --experiment-name mruby-dynamic-pairs-smoke-20261002 \
  --resume \
  --dangerously-no-sandbox
```

Observed behavior:

- `pair=1 arm=off` was skipped because one existing dynamic result was present.
- `pair=1 arm=feedback` was skipped because one existing dynamic result was
  present.
- No new agent run was started.
- `summary.json` and `summary.md` were regenerated from the existing result
  tree.

Regression after adding resume support:

```sh
.venv/bin/python -m pytest \
  tests/test_dynamic_pairs_cli.py \
  tests/test_experiment_summary.py \
  tests/test_find_split.py \
  tests/test_execution_protocol.py \
  tests/test_symcc_iteration_reconciliation.py -q

.venv/bin/python -m pytest -q
```

Results: 79 focused tests passed; full suite 519 passed, 5 skipped.

Experiment target matrix:

- Added a machine-readable target matrix:

```text
docs/research/symcc-feedback-experiment-targets.json
```

- Added a human-readable companion document with ready/deferred targets and
  copy-pasteable `dynamic-pairs` commands:

```text
docs/research/symcc-feedback-experiment-targets.md
```

- Ready targets for the first controlled batch:

| ID | Target path | Static report | Role |
| --- | --- | --- | --- |
| `mruby-57672` | `targets/mruby-arvo-feedback` | `targets/mruby-arvo-feedback/static-report-57672-v2.json` | complex GC/lifecycle baseline |
| `arvo-62290` | `targets/arvo-62290-experiment` | `results/experiments/symcc-target-site-feedback-20260924/shared/arvo-62290-static-report.json` | anchor/noise/additional-crash case |
| `arvo-38283` | `results/experiments/cybergym-symcc-followup-20260928/targets/arvo-38283` | `results/experiments/cybergym-symcc-followup-20260928/targets/arvo-38283/static_analysis.json` | protocol parser structured input |
| `arvo-55020` | `results/experiments/cybergym-symcc-followup-20260928/targets/arvo-55020` | `results/experiments/cybergym-symcc-followup-20260928/targets/arvo-55020/static_analysis.json` | binary format / relocation handling |

- `ghostscript-51089` is kept as deferred for the first controlled batch
  because the available configuration is manual/build-style rather than the
  stabilized prebuilt feedback contract.
- Added `tests/test_symcc_experiment_targets.py` to verify that every ready
  matrix entry has:
  - a target directory;
  - `config.yaml`;
  - a static report with at least one finding;
  - `symbolic_execution.symcc` configuration;
  - a feedback map path.

Recommended formal command pattern:

```sh
.venv/bin/python -m harness.cli dynamic-pairs <target-path> \
  --static-report <static-report> \
  --model deepseek-flash \
  --runs 3 \
  --phase-timeout 3600 \
  --max-iterations 8 \
  --results-dir results/experiments \
  --experiment-name <target-id>-feedback-paired \
  --dangerously-no-sandbox
```

Regression after adding the target matrix:

```sh
.venv/bin/python -m pytest \
  tests/test_symcc_experiment_targets.py \
  tests/test_experiment_summary.py \
  tests/test_dynamic_pairs_cli.py -q

.venv/bin/python -m pytest -q
```

Results: 6 focused tests passed; full suite 521 passed, 5 skipped.

Cross-target summary aggregation:

- Expanded `harness/experiment_summary.py` with `by_target` aggregation so
  multi-target batches can be inspected without reading every run row.
- The JSON summary now includes, for each target:
  - total run count;
  - arms observed;
  - per-arm run counts;
  - per-arm validated counts;
  - per-arm average wall time;
  - per-arm exact-target-hit counts;
  - per-arm feedback-consumed counts;
  - per-arm failure categories;
  - dominant failure category.
- The Markdown summary now contains:

```text
## Aggregate by target and arm
```

Example from the MRuby paired-runner smoke:

| Target | Arm | Runs | Validated | Avg wall s | Exact target hits | Feedback consumed | Dominant failure |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| mruby-arvo-feedback | feedback | 1 | 0 | 70.236 | 0 | 0 | feedback_unavailable_or_not_ready |
| mruby-arvo-feedback | off | 1 | 0 | 181.969 | 0 | 0 | agent_blocked_or_failed |

This table is the one to use first when the four-target batch completes: it
shows at a glance whether a target has both off and feedback arms, whether
only one target is dominating failures, and whether feedback helps in one input
domain while hurting in another.

Regression after adding cross-target aggregation:

```sh
.venv/bin/python -m pytest \
  tests/test_experiment_summary.py \
  tests/test_dynamic_pairs_cli.py \
  tests/test_symcc_experiment_targets.py -q

.venv/bin/python -m pytest -q
```

Results: 7 focused tests passed; full suite 522 passed, 5 skipped.

Outcome and failure-category classification:

- Expanded `harness/experiment_summary.py` so every dynamic run summary now
  includes:
  - `outcome_category`;
  - `failure_category`.
- These fields do not replace raw status, `status_breakdown`, or ledger data.
  They are a post-hoc analysis aid for larger experiments, so repeated runs can
  be grouped by failure mode without manually reading every transcript.
- Current outcome categories include:
  - `validated_poc`;
  - `additional_finding`;
  - `target_reached_no_poc`;
  - `target_approach_only`;
  - `protocol_or_agent_failure`;
  - `no_validated_poc`.
- Current failure categories include:
  - `none`;
  - `additional_finding_not_original_candidate`;
  - `submission_failure`;
  - `agent_blocked_or_failed`;
  - `no_protocol_input`;
  - `feedback_ready_unconsumed`;
  - `feedback_unavailable_or_not_ready`;
  - `feedback_ready_not_read`;
  - `target_reached_but_no_poc`;
  - `target_approach_only`;
  - `no_target_evidence`;
  - `unknown`.
- The Markdown summary now adds a "Failure categories by arm" table and adds
  outcome/failure columns to the per-run table.

Re-generated summary for the real paired-runner smoke:

```sh
.venv/bin/python -m harness.cli summarize-experiments \
  results/experiments/mruby-dynamic-pairs-smoke-20261002 \
  --json-out results/experiments/mruby-dynamic-pairs-smoke-20261002/summary.json \
  --markdown-out results/experiments/mruby-dynamic-pairs-smoke-20261002/summary.md
```

Failure-category output:

| Arm | Category | Runs |
| --- | --- | ---: |
| feedback | `feedback_unavailable_or_not_ready` | 1 |
| off | `agent_blocked_or_failed` | 1 |

This correctly explains the short smoke: the feedback arm submitted one
protocol request, but the 180s/1-iteration budget ended before SymCC feedback
was ready; the off arm hit an agent/backend blocking condition.  Neither result
should be interpreted as evidence for or against SymCC effectiveness.

Regression after adding outcome/failure categories:

```sh
.venv/bin/python -m pytest \
  tests/test_experiment_summary.py \
  tests/test_dynamic_pairs_cli.py \
  tests/test_find_split.py \
  tests/test_execution_protocol.py \
  tests/test_symcc_iteration_reconciliation.py -q

.venv/bin/python -m pytest -q
```

Results: 79 focused tests passed; full suite 519 passed, 5 skipped.
