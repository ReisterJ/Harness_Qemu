"""Tests for the dynamic symbolic-execution bridge and its bounded request API."""

from pathlib import Path

import pytest

from harness.artifacts import StaticFinding
from harness.config import TargetConfig
from harness.prompts.dynamic_validation_prompt import build_dynamic_validation_prompt
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
    assert target.runtime_image_tag == "n132/arvo:57672-vul"
    assert target.source_root == "/src/mruby"
    assert target.binary_path == "/out/mruby_fuzzer"
    assert target.known_bugs == []
    assert target.symbolic_execution == {
        "default": "off", "providers": ["symcc", "klee"]
    }


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
