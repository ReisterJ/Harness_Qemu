"""Tests for the dynamic symbolic-execution bridge and its bounded request API."""

from pathlib import Path

import pytest

from harness.artifacts import StaticFinding
from harness.dynamic_validation import _summarize_replay_for_model
from harness.config import TargetConfig
from harness.prompts.dynamic_validation_prompt import (
    build_dynamic_validation_prompt,
    build_poc_generation_prompt,
    build_symcc_planner_prompt,
)
from harness.symbolic import select_symbolic_execution
from harness.symbolic.worker import (
    compiler_flags,
    compiler_for,
    klee_flags,
    parse_ktest_output,
    relative_path,
    runtime_arguments,
    symbolic_file_objects,
)
from harness.symbolic.klee import _persist_job_source_tree
from harness.symbolic.seed_plan import SeedPlanError, parse_seed_plan
from harness.symbolic.symcc_worker import (
    compiler_flags as symcc_compiler_flags,
    link_flags,
    per_seed_testcase_budget,
    program_arguments,
)


def _finding() -> StaticFinding:
    return StaticFinding(
        candidate_id="candidate_001",
        bug_class="memory-safety",
        location="src/example.c:10",
        static_call_chain="",
        entry_points="",
        attacker_controlled_data="",
        reachability_evidence="",
        required_conditions="",
        root_cause="",
        verification_plan="",
        confidence=0.5,
    )


def test_symbolic_provider_selection_is_opt_in_and_target_configurable():
    assert select_symbolic_execution(None, None) is None
    assert select_symbolic_execution("off", {"default": "klee"}) is None
    assert select_symbolic_execution(None, {"default": "klee"}) == "klee"
    assert select_symbolic_execution("auto", {"providers": ["other"]}) is None
    assert select_symbolic_execution("auto", {"providers": ["klee"]}) == "klee"
    assert select_symbolic_execution("auto", {"providers": ["klee", "symcc"]}) == "symcc"
    assert select_symbolic_execution("symcc", {}) == "symcc"
    with pytest.raises(ValueError, match="unknown symbolic-execution"):
        select_symbolic_execution("unknown", {})


def test_prebuilt_mruby_experiment_target_resolves_without_revealing_bug():
    root = Path(__file__).resolve().parents[1]
    target = TargetConfig.load(root / "targets" / "mruby-arvo")
    assert target.runtime_image_tag == "local/mruby-arvo-prebuilt-symcc:2de602b"
    assert target.source_root == "/src/mruby"
    assert target.binary_path == "/out/mruby_fuzzer"
    assert target.known_bugs == []
    assert target.symbolic_execution == {
        "default": "off",
        "providers": ["symcc", "klee"],
        "symcc": {
            "binary_path": "/out/mruby_fuzzer_symcc",
            "commit": "2de602b8696bc21e4cbc2c6e08e2fae27b1ad79b",
        },
    }


def test_prebuilt_symcc_protocol_is_the_final_dynamic_prompt_override():
    prompt = build_dynamic_validation_prompt(
        candidate=_finding(),
        github_url="local",
        commit="a" * 40,
        source_root="/src/project",
        binary_path="/out/target",
        symbolic_context={
            "provider": "symcc",
            "status": "ready",
            "orchestration": "prebuilt_protocol",
            "artifact_commit": "a" * 40,
            "runner": "/work/validation/run-input",
            "input_root": "/work/validation/inputs",
            "request_template": "/work/validation/execution/request-template.json",
        },
    )
    assert "queues the prebuilt SymCC execution in the background" in prompt
    assert "its response may include `ready_feedback`" in prompt
    assert "mandatory" in prompt and "inspect it before choosing the next" in prompt
    assert "preserve and print a concise" in prompt
    assert "summary of every `ready_feedback` record" in prompt
    assert "Do not filter" in prompt
    assert "output or silently discard" in prompt
    assert "read-feedback" in prompt
    assert "`skipped_busy` means" in prompt and "no feedback for that request" in prompt
    assert "If the reader returns `pending`, do" in prompt
    assert "Do not compile a source slice" in prompt
    assert prompt.rfind("Harness execution override") > prompt.rfind(
        "Dynamic-validation scope"
    )
    assert prompt.rstrip().endswith("Grade remains the final reproduction check.")


def test_ready_symbolic_context_teaches_the_tool_contract_not_the_answer():
    prompt = build_dynamic_validation_prompt(
        candidate=_finding(),
        github_url="local",
        commit="test",
        source_root="/src",
        binary_path="/out/target",
        symbolic_context={
            "provider": "klee",
            "status": "ready",
            "client": "/work/symbolic/klee-submit",
        },
    )
    assert "/work/symbolic/klee-submit" in prompt
    assert "materialized external input" in prompt
    assert "replay any external candidate through the real target binary" in prompt.lower()
    assert "your next tool action must submit" in prompt
    assert "Do not inspect VCS history" in prompt
    assert "at most 300 seconds per invocation" in prompt
    assert "reserve at least 300 seconds" in prompt
    assert "Write each record immediately" in prompt
    assert prompt.index("Required first-step symbolic-execution probe") < prompt.index(
        "You are conducting authorized security research"
    )
    assert "mrb_env_unshare" not in prompt


def test_symcc_prompt_requires_concrete_seeds_and_original_target_replay():
    prompt = build_dynamic_validation_prompt(
        candidate=_finding(),
        github_url="local",
        commit="test",
        source_root="/src",
        binary_path="/out/target",
        symbolic_context={
            "provider": "symcc",
            "status": "ready",
            "client": "/work/symbolic/symcc-submit",
        },
    )
    assert "Required first-step symbolic-execution probe (SymCC)" in prompt
    assert "seed's length fixed" in prompt
    assert "{input_file}" in prompt
    assert "clean original target binary" in prompt
    assert "mrb_env_unshare" not in prompt


def test_harness_managed_symcc_prompt_requests_a_declarative_plan():
    prompt = build_dynamic_validation_prompt(
        candidate=_finding(),
        github_url="local",
        commit="test",
        source_root="/src/project",
        binary_path="/out/target",
        symbolic_context={
            "provider": "symcc",
            "status": "ready",
            "orchestration": "harness",
            "source_root": "/src/project",
            "client": "/work/symbolic/symcc-submit",
        },
        symbolic_round=2,
        symbolic_feedback={"progress": {"distance_to_candidate": 1}},
    )
    assert "Harness-managed symbolic execution — SymCC round 2" in prompt
    assert "Do **not** invoke" in prompt
    assert "<symbolic_seed_plan>" in prompt
    assert '"working_dir": "jobs/round-002"' in prompt
    assert '"distance_to_candidate": 1' in prompt


def test_symcc_handoff_prompt_returns_control_to_agent_without_new_plan():
    prompt = build_dynamic_validation_prompt(
        candidate=_finding(),
        github_url="local",
        commit="test",
        source_root="/src/project",
        binary_path="/out/target",
        symbolic_context={
            "provider": "symcc",
            "status": "ready",
            "orchestration": "agent_handoff",
            "source_root": "/src/project",
        },
        symbolic_round=1,
        symbolic_feedback={
            "progress": {"site_reached": True, "distance_to_candidate": 1}
        },
        symbolic_finalize=True,
    )
    assert "SymCC-to-agent handoff" in prompt
    assert "site_reached" in prompt
    assert "Do not invoke" in prompt
    assert "do not emit a" in prompt
    assert "clean-target replay" in prompt


def test_symcc_planner_prompt_has_only_seed_plan_contract():
    prompt = build_symcc_planner_prompt(
        candidate=_finding(),
        github_url="local",
        commit="test",
        source_root="/src/project",
        binary_path="/out/target",
        detector="asan",
        runtime_context={"artifact": {"path": "/out/target"}},
        symbolic_context={"provider": "symcc", "status": "ready"},
        round_id=1,
    )
    assert "SymCC planning agent" in prompt
    assert "<symbolic_seed_plan>" in prompt
    assert "crash-result.xml" in prompt
    assert "Do not create a PoC" in prompt
    assert "Do not invoke /work/symbolic/symcc-submit" in prompt
    assert "Do not perform broad fuzzing" in prompt
    assert "dynamic-status or crash" in prompt
    assert "You are conducting authorized security research" not in prompt


def test_poc_generation_prompt_does_not_expose_provider_contract():
    prompt = build_poc_generation_prompt(
        candidate=_finding(),
        github_url="local",
        commit="test",
        source_root="/src/project",
        binary_path="/out/target",
        detector="asan",
        runtime_context={"artifact": {"path": "/out/target"}},
        symbolic_feedback={"progress": {"site_reached": True}},
    )
    assert "SymCC handoff from the previous agent" in prompt
    assert "Do not invoke SymCC" in prompt
    assert "symbolic_seed_plan" in prompt
    assert "provider contract" not in prompt.lower()
    assert "clean target" in prompt


def test_symcc_feedback_keeps_concrete_seeds_and_bounds_mutation_examples():
    cases = [
        {
            "path": "jobs/round-001/seeds/seed-001",
            "kind": "seed",
            "seed_name": "seed-001",
            "size": 43,
            "exit_code": 0,
            "status": "observed",
            "output_tail": "seed output",
        }
    ]
    cases.extend(
        {
            "path": f"generated/{index:03d}",
            "kind": "generated",
            "seed_name": "seeds/seed-001",
            "size": 43,
            "exit_code": 0,
            "status": "observed",
            "output_tail": "syntax error" * 500,
        }
        for index in range(128)
    )

    summary = _summarize_replay_for_model(
        {
            "round_id": 1,
            "status": "completed",
            "cases": cases,
            "testcase_count": len(cases),
            "seed_case_count": 1,
            "generated_case_count": 128,
            "site_reached": False,
            "matched_candidate": False,
            "sanitizer_event": False,
            "distance_to_candidate": None,
            "anchors": ["mrb_env_unshare"],
            "errors": [],
        }
    )

    assert summary["seed_case_count"] == 1
    assert summary["generated_case_count"] == 128
    assert summary["seed_results"][0]["seed_name"] == "seed-001"
    assert len(summary["generated_examples"]) == 20
    assert len(summary["generated_examples"][0]["output_tail"]) <= 1600


def test_seed_plan_parser_validates_agent_owned_plan_without_running_provider():
    response = '''<symbolic_seed_plan>
    {
      "schema_version": 1,
      "candidate_id": "candidate_001",
      "working_dir": "jobs/round-001",
      "sources": ["target.c", "driver.c"],
      "compile_flags": ["-g", "-O0"],
      "link_flags": [],
      "program_args": ["--input", "{input_file}"],
      "seeds": [{"name": "seed-001", "encoding": "base64", "data": "YWJj"}],
      "timeout_s": 30,
      "max_testcases": 4,
      "target_anchors": ["target_function"]
    }
    </symbolic_seed_plan>'''
    plan = parse_seed_plan(response, candidate_id="candidate_001")
    assert plan.seeds[0].data == b"abc"
    assert plan.program_args[-1] == "{input_file}"
    with pytest.raises(SeedPlanError, match="candidate_id"):
        parse_seed_plan(response, candidate_id="candidate_002")


def test_worker_request_options_are_narrowly_validated():
    assert compiler_flags(["-g", "-O0", "-Iinclude", "-DDEBUG=1"])
    assert klee_flags(["--libc=uclibc", "--posix-runtime"])
    assert runtime_arguments(["A", "-sym-files", "1", "32"])
    with pytest.raises(ValueError, match="unsupported compiler flag"):
        compiler_flags(["-Xclang", "-load", "payload.so"])
    with pytest.raises(ValueError, match="unsupported KLEE argument"):
        klee_flags(["--external-calls=all"])
    with pytest.raises(ValueError, match="unsupported POSIX"):
        runtime_arguments(["-sym-file", "/etc/passwd"])
    with pytest.raises(ValueError, match="stay inside"):
        relative_path("../outside.c", "source")


def test_symcc_request_options_are_bounded_and_require_external_seed_file():
    assert symcc_compiler_flags(["-g", "-O0", "-DMRB_NO_PRESYM", "-Iinclude"])
    assert link_flags(["-lm", "-pthread"])
    assert program_arguments(["--one-input", "{input_file}"])
    with pytest.raises(ValueError, match="unsupported compiler flag"):
        symcc_compiler_flags(["-Xclang", "-load", "payload.so"])
    with pytest.raises(ValueError, match="unsupported link flag"):
        link_flags(["-Wl,-rpath,/tmp"])
    with pytest.raises(ValueError, match="exactly once"):
        program_arguments(["--no-input"])


def test_symcc_testcase_budget_is_shared_across_seeds():
    remaining_cases = 64
    budgets = []
    for remaining_seeds in range(5, 0, -1):
        budget = per_seed_testcase_budget(remaining_cases, remaining_seeds)
        budgets.append(budget)
        remaining_cases -= budget

    assert budgets == [12, 13, 13, 13, 13]
    with pytest.raises(ValueError, match="at least one case per remaining seed"):
        per_seed_testcase_budget(2, 3)


def test_compiler_resolution_accepts_image_clang_aliases(monkeypatch):
    available = {"clang++": "/toolchain/bin/clang++"}
    monkeypatch.setattr("harness.symbolic.worker.shutil.which", available.get)
    assert compiler_for("c++") == "/toolchain/bin/clang++"
    with pytest.raises(ValueError, match=r"language must be c or c\+\+"):
        compiler_for("rust")


def test_ktest_parser_keeps_symbolic_file_data_separate_from_posix_metadata():
    objects = parse_ktest_output(
        """object 0: name: 'A_data'
object 0: size: 4
object 0: data: b'A\\xff\\x00\\x01'
object 1: name: 'A_data_stat'
object 1: size: 16
object 1: data: b'0123456789abcdef'
"""
    )

    symbolic_files = symbolic_file_objects(objects)
    assert len(symbolic_files) == 1
    assert symbolic_files[0]["name"] == "A_data"
    assert symbolic_files[0]["data"] == b"A\xff\x00\x01"


def test_ktest_parser_extracts_symbolic_stdin_but_not_its_metadata():
    objects = parse_ktest_output(
        """object 0: name: 'stdin'
object 0: size: 4
object 0: data: b'puts'
object 1: name: 'stdin_stat'
object 1: size: 16
object 1: data: b'0123456789abcdef'
"""
    )

    symbolic_inputs = symbolic_file_objects(objects)
    assert len(symbolic_inputs) == 1
    assert symbolic_inputs[0]["name"] == "stdin"
    assert symbolic_inputs[0]["data"] == b"puts"


def test_ktest_parser_recognizes_fuzzer_input_objects_but_not_metadata():
    objects = [
        {"name": "input", "size": 4, "data": b"puts"},
        {"name": "input_stat", "size": 16, "data": b"0" * 16},
        {"name": "env", "size": 4, "data": b"\x00" * 4},
    ]

    symbolic_inputs = symbolic_file_objects(objects)
    assert [item["name"] for item in symbolic_inputs] == ["input"]


def test_klee_source_archive_preserves_harness_and_skips_vcs(tmp_path):
    workspace = tmp_path / "workspace"
    job_dir = workspace / "jobs" / "sample"
    job_dir.mkdir(parents=True)
    (job_dir / "harness.c").write_text("int main(void) { return 0; }\n")
    (job_dir / ".git").mkdir()
    (job_dir / ".git" / "HEAD").write_text("ref: refs/heads/private\n")
    request = tmp_path / "request.json"
    request.write_text('{"working_dir":"jobs/sample"}')
    destination = tmp_path / "archive"

    manifest = _persist_job_source_tree(workspace, request, destination)

    assert manifest["status"] == "complete"
    assert (destination / "harness.c").is_file()
    assert not (destination / ".git").exists()
