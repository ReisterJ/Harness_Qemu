import json
from pathlib import Path


MATRIX = Path("docs/research/symcc-feedback-experiment-targets.json")


def test_symcc_feedback_experiment_target_matrix_is_well_formed():
    payload = json.loads(MATRIX.read_text())
    assert payload["schema_version"] == 1
    assert "{target_path}" in payload["default_command_template"]
    assert "{static_report}" in payload["default_command_template"]
    targets = payload["targets"]
    assert len(targets) >= 4
    ids = [item["id"] for item in targets]
    assert len(ids) == len(set(ids))

    ready = [item for item in targets if item["status"] == "ready"]
    assert {item["id"] for item in ready} >= {
        "mruby-57672",
        "arvo-62290",
        "arvo-38283",
        "arvo-55020",
    }
    for item in targets:
        assert item["id"]
        assert item["label"]
        assert item["target_path"]
        assert item["static_report"]
        assert item["status"] in {"ready", "deferred"}
        assert item["reason"]


def test_ready_symcc_feedback_experiment_targets_have_required_files():
    payload = json.loads(MATRIX.read_text())
    for item in payload["targets"]:
        if item["status"] != "ready":
            continue
        target_path = Path(item["target_path"])
        static_report = Path(item["static_report"])
        config_path = target_path / "config.yaml"
        assert target_path.is_dir(), item["id"]
        assert config_path.is_file(), item["id"]
        assert static_report.is_file(), item["id"]

        config = config_path.read_text()
        assert "symbolic_execution:" in config, item["id"]
        assert "symcc:" in config, item["id"]
        assert "binary_path:" in config, item["id"]
        assert "feedback_map_path:" in config, item["id"]

        report = json.loads(static_report.read_text())
        assert report.get("phase") == "static_analysis", item["id"]
        assert report.get("status") in {None, "candidates_found"}, item["id"]
        findings = report.get("findings")
        assert isinstance(findings, list) and findings, item["id"]
        assert findings[0].get("candidate_id"), item["id"]
