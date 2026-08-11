# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""harness.cli._load_dotenv: KEY=VALUE .env loading at CLI startup."""
import os

from harness.cli import _load_dotenv


def _env_file(tmp_path, content: str):
    p = tmp_path / ".env"
    p.write_text(content)
    return p


def test_loads_key_and_strips_quotes(tmp_path, monkeypatch):
    _env_file(tmp_path, "# comment\nDEEPSEEK_API_KEY=sk-test123\nQUOTED=\"abc\"\n")
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.setenv("VULN_PIPELINE_ENV_FILE", str(tmp_path / ".env"))
    _load_dotenv()
    assert os.environ["DEEPSEEK_API_KEY"] == "sk-test123"
    assert os.environ["QUOTED"] == "abc"


def test_blank_and_comment_lines_skipped(tmp_path, monkeypatch):
    _env_file(tmp_path, "\n   \n# only a comment\nA=1\n# trailing comment line\n")
    monkeypatch.delenv("A", raising=False)
    monkeypatch.setenv("VULN_PIPELINE_ENV_FILE", str(tmp_path / ".env"))
    _load_dotenv()
    assert os.environ["A"] == "1"


def test_existing_env_wins_over_file(tmp_path, monkeypatch):
    _env_file(tmp_path, "DEEPSEEK_API_KEY=sk-from-file\n")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-manual-export")
    monkeypatch.setenv("VULN_PIPELINE_ENV_FILE", str(tmp_path / ".env"))
    _load_dotenv()
    assert os.environ["DEEPSEEK_API_KEY"] == "sk-manual-export"


def test_missing_file_is_noop(tmp_path, monkeypatch):
    monkeypatch.setenv("VULN_PIPELINE_ENV_FILE", str(tmp_path / "nope.env"))
    _load_dotenv()  # must not raise


def test_unreadable_file_is_noop(tmp_path, monkeypatch):
    p = tmp_path / "locked.env"
    p.write_text("A=1\n")
    p.chmod(0)
    monkeypatch.setenv("VULN_PIPELINE_ENV_FILE", str(p))
    try:
        _load_dotenv()  # must not raise (OSError swallowed)
    finally:
        p.chmod(0o644)
