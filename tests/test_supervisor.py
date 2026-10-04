import json

from harness.agent import AgentResult
from harness.supervisor import (
    SearchPolicySupervisor,
    combine_progress_nudges,
    make_supervisor_progress_nudge,
)


def _tool(command: str, *, output: str = "", call_id: str = "call-1") -> dict:
    return {
        "type": "tool_use",
        "sessionID": "ses-1",
        "part": {
            "type": "tool",
            "tool": "bash",
            "callID": call_id,
            "state": {
                "status": "completed",
                "input": {"command": command},
                "output": output,
            },
        },
    }


def test_supervisor_flags_broad_fuzzing(tmp_path):
    event_path = tmp_path / "supervisor_events.jsonl"
    supervisor = SearchPolicySupervisor(event_path=event_path)
    decision = supervisor.review([
        _tool("/out/mruby_fuzzer -max_total_time=280 -artifact_prefix=/tmp/r/ /tmp/corpus")
    ])

    assert decision is not None
    assert decision.decision == "correct"
    assert decision.violation_type == "broad_fuzzing"
    assert "Broad fuzzing" in decision.reason
    lines = event_path.read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["violation_type"] == "broad_fuzzing"


def test_supervisor_flags_background_fuzzer_sprawl_before_general_fuzzing():
    supervisor = SearchPolicySupervisor()
    decision = supervisor.review([
        _tool(
            "for i in 0 1 2 3; do "
            "(timeout 300 /out/mruby_fuzzer -max_total_time=280 "
            "-artifact_prefix=/tmp/r$i/ /tmp/merged >/tmp/r$i.log 2>&1) & "
            "done"
        )
    ])

    assert decision is not None
    assert decision.decision == "interrupt"
    assert decision.violation_type == "background_worker_sprawl"


def test_supervisor_does_not_treat_stderr_redirect_as_background():
    supervisor = SearchPolicySupervisor()
    decision = supervisor.review([
        _tool(
            "timeout 150 /out/mruby_fuzzer -max_total_time=110 "
            "-artifact_prefix=/tmp/artifacts/ /tmp/corpus 2>&1 | tail -60"
        )
    ])

    assert decision is not None
    assert decision.decision == "correct"
    assert decision.violation_type == "broad_fuzzing"


def test_supervisor_flags_observed_process_sprawl():
    supervisor = SearchPolicySupervisor(max_background_target_processes=8)
    decision = supervisor.review([
        _tool(
            "ps aux | grep -c mruby_fuzzer",
            output="101\n",
        )
    ])

    assert decision is not None
    assert decision.violation_type == "background_worker_sprawl"
    assert "101" in decision.evidence[0]


def test_supervisor_does_not_treat_arbitrary_counts_as_process_sprawl():
    supervisor = SearchPolicySupervisor(max_background_target_processes=8)
    decision = supervisor.review([
        _tool(
            "ls /src/mruby/test/t | wc -l; ls /src/mruby/mrbgems | head",
            output="43\nmruby-array-ext\nmruby-bigint\n",
        )
    ])

    assert decision is None


def test_supervisor_flags_blocking_wait():
    supervisor = SearchPolicySupervisor(max_blocking_wait_s=20)
    decision = supervisor.review([
        _tool("sleep 90; tail -10 /tmp/result.log")
    ])

    assert decision is not None
    assert decision.decision == "correct"
    assert decision.violation_type == "blocking_wait"


def test_supervisor_allows_single_input_libfuzzer_replay(tmp_path):
    supervisor = SearchPolicySupervisor(event_path=tmp_path / "events.jsonl")
    decision = supervisor.review([
        _tool("timeout 30 /out/mruby_fuzzer -runs=1 /work/validation/inputs/poc.rb")
    ])

    assert decision is None
    assert not (tmp_path / "events.jsonl").exists()


def test_supervisor_progress_nudge_returns_corrective_prompt_once():
    supervisor = SearchPolicySupervisor()
    nudge = make_supervisor_progress_nudge(supervisor)
    assert nudge is not None
    result = AgentResult(messages=[
        _tool("/out/mruby_fuzzer -max_total_time=300 /tmp/corpus")
    ])

    prompt = nudge(result)
    assert prompt is not None
    assert "Supervisor intervention" in prompt
    assert "broad_fuzzing" in prompt
    assert nudge(result) is None


def test_supervisor_progress_nudge_invokes_decision_hook():
    supervisor = SearchPolicySupervisor()
    seen = []
    nudge = make_supervisor_progress_nudge(
        supervisor,
        on_decision=lambda decision: seen.append(decision.violation_type),
    )
    assert nudge is not None
    result = AgentResult(messages=[
        _tool(
            "for i in 0 1; do "
            "(/out/mruby_fuzzer -max_total_time=60 -artifact_prefix=/tmp/r$i/ /tmp/corpus) & "
            "done"
        )
    ])

    assert nudge(result) is not None
    assert seen == ["background_worker_sprawl"]


def test_combine_progress_nudges_preserves_priority():
    def first(_result):
        return None

    def second(_result):
        return "second"

    combined = combine_progress_nudges(first, second)
    assert combined is not None
    assert combined(AgentResult()) == "second"
