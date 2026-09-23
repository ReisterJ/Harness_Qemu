from __future__ import annotations

from harness.artifacts import StaticFinding
from harness.dynamic_validation import (
    _has_candidate_ready_iteration,
    _has_crash_without_candidate_site,
    _reconcile_symcc_iterations,
)


def _protocol_record(*, reached=False, complete=True, valid=True, sanitizer=True):
    return {
        "request_id": "round-001",
        "round_id": 1,
        "input_id": "input-sha256",
        "parent_input_id": None,
        "target_commit": "commit-123",
        "feedback_status": "ready",
        "clean": {
            "status": "failed" if sanitizer else "completed",
            "sanitizer_event": sanitizer,
        },
        "symcc": {"status": "timed_out"},
        "symcc_observation": {
            "status": "ready",
            "trace_status": "completed" if complete else "incomplete",
            "trace_complete": complete,
            "trace_truncated": not complete,
            "target_ids_configured": True,
            "target_ids_valid": valid,
            "target_reached": reached,
            "target_block_reached": True,
            "closest_observed_location": {
                "function": "candidate_site",
                "source_file": "src/target.c",
                "line": 40,
            },
            "distance": 0,
            "distance_kind": "static_icfg_edges",
            "distance_is_heuristic": True,
        },
    }


def _agent_iteration(*, input_id="input-sha256", site=True):
    return {
        "round_id": 1,
        "request_id": "round-001",
        "input_id": input_id,
        "candidate_id": "candidate_001",
        "hypothesis": {"target_site": "src/target.c:40"},
        "observations": {
            "site_reached": site,
            "sanitizer_event": True,
            "matched_candidate": True,
            "bad_state_observed": False,
            "bad_effect_observed": True,
        },
        "decision": "candidate_ready",
        "reason": "agent assessment",
    }


def test_complete_runtime_miss_overrides_agent_distance_zero_claim():
    records, errors = _reconcile_symcc_iterations(
        [_agent_iteration()],
        {"records": [_protocol_record(reached=False, complete=True)]},
        candidate_id="candidate_001",
        detector="asan",
    )

    assert not errors
    assert records[0]["observations"]["site_reached"] is False
    assert records[0]["observations"]["sanitizer_event"] is True
    assert records[0]["observations"]["matched_candidate"] is False
    assert records[0]["agent_claims"]["site_reached"] is True
    assert records[0]["machine_evidence"]["distance"] == 0
    assert records[0]["machine_evidence"]["target_block_reached"] is True
    assert not _has_candidate_ready_iteration(records, "asan")
    assert _has_crash_without_candidate_site(records)


def test_incomplete_trace_cannot_be_promoted_to_hit_or_miss():
    records, _errors = _reconcile_symcc_iterations(
        [_agent_iteration()],
        {"records": [_protocol_record(reached=False, complete=False)]},
        candidate_id="candidate_001",
        detector="asan",
    )

    assert records[0]["observations"]["site_reached"] is None
    assert records[0]["observations"]["matched_candidate"] is False
    assert not _has_crash_without_candidate_site(records)


def test_exact_machine_hit_and_request_input_identity_can_authorize_candidate():
    records, errors = _reconcile_symcc_iterations(
        [_agent_iteration(site=True)],
        {"records": [_protocol_record(reached=True, complete=True)]},
        candidate_id="candidate_001",
        detector="asan",
    )

    assert not errors
    assert records[0]["observations"]["site_reached"] is True
    assert records[0]["observations"]["matched_candidate"] is True
    assert _has_candidate_ready_iteration(records, "asan")


def test_mismatched_input_id_does_not_authorize_model_semantic_claim():
    records, errors = _reconcile_symcc_iterations(
        [_agent_iteration(input_id="different-input")],
        {"records": [_protocol_record(reached=True, complete=True)]},
        candidate_id="candidate_001",
        detector="asan",
    )

    assert errors
    assert records[0]["observations"]["site_reached"] is True
    assert records[0]["observations"]["matched_candidate"] is False
    assert records[0]["association"] == "round_only"
    assert not _has_candidate_ready_iteration(records, "asan")


def test_invalid_target_mapping_leaves_reachability_unknown():
    records, _errors = _reconcile_symcc_iterations(
        [_agent_iteration()],
        {"records": [_protocol_record(reached=False, complete=True, valid=False)]},
        candidate_id="candidate_001",
        detector="asan",
    )

    assert records[0]["observations"]["site_reached"] is None
    assert records[0]["observations"]["matched_candidate"] is False


def test_symcc_prompt_separates_exploration_wrapper_from_grade_replay_command():
    from harness.prompts.dynamic_validation_prompt import build_dynamic_validation_prompt

    prompt = build_dynamic_validation_prompt(
        candidate=StaticFinding(
            candidate_id="candidate_001",
            bug_class="heap-use-after-free",
            location="src/target.c:40",
            static_call_chain="input -> parse",
            entry_points="file input",
            attacker_controlled_data="input bytes",
            reachability_evidence="external input to parser",
            required_conditions="not yet known",
            root_cause="suspected lifetime bug",
            verification_plan="reach and reproduce",
            confidence=0.7,
        ),
        github_url="https://example.invalid/project",
        commit="commit-123",
        source_root="/src/project",
        binary_path="/out/target",
        symbolic_context={
            "status": "ready",
            "provider": "symcc",
            "orchestration": "prebuilt_protocol",
            "input_root": "/work/validation/inputs",
            "request_template": "/work/validation/execution/request-template.json",
            "runner": "/work/validation/run-input",
            "feedback_reader": "/work/validation/read-feedback",
            "symcc_program_args": ["{input_file}"],
        },
    )

    assert "distance: 0" in prompt
    assert "target_block_reached: true" in prompt
    assert "request_id` and `input_id`" in prompt
    assert "do not put a `run-input` command" in prompt.lower()
    assert "Grade runs that command in a fresh container" in prompt
