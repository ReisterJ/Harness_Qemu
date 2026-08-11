# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""harness.auth — opencode provider/auth resolution and egress derivation."""
import pytest

from harness.auth import (
    NO_AUTH_MSG,
    check_egress_satisfied,
    required_egress_hosts,
    resolve_auth_env,
    warn_bedrock_model,
)


AUTH_VARS = (
    "DEEPSEEK_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENROUTER_API_KEY",
    "XAI_API_KEY",
    "GROQ_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_GENERATIVE_AI_API_KEY",
    "MISTRAL_API_KEY",
    "MOONSHOT_API_KEY",
    "ZAI_API_KEY",
    "GLM_API_KEY",
    "TOGETHER_API_KEY",
    "NVIDIA_API_KEY",
    "OPENCODE_ZEN_API_KEY",
    "GITHUB_TOKEN",
    "OPENCODE_CONFIG",
    "OPENCODE_CONFIG_DIR",
    "OPENCODE_CONFIG_CONTENT",
    "OPENCODE_DISABLE_AUTOUPDATE",
    "OPENCODE_DISABLE_CLAUDE_CODE",
    "OPENCODE_DISABLE_MODELS_FETCH",
)


@pytest.fixture(autouse=True)
def _clear_auth(monkeypatch):
    for v in AUTH_VARS:
        monkeypatch.delenv(v, raising=False)


# ── resolve_auth_env ────────────────────────────────────────────────────────

def test_deepseek_key(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-ds-x")
    env = resolve_auth_env()
    assert env and env["DEEPSEEK_API_KEY"] == "sk-ds-x"
    # opencode runtime defaults are always stamped on
    assert env["OPENCODE_DISABLE_AUTOUPDATE"] == "1"
    assert env["OPENCODE_DISABLE_CLAUDE_CODE"] == "1"
    assert env["OPENCODE_DISABLE_MODELS_FETCH"] == "1"


def test_openai_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
    env = resolve_auth_env()
    assert env and env["OPENAI_API_KEY"] == "sk-openai"


def test_forward_opencode_env(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk")
    monkeypatch.setenv("OPENCODE_CONFIG_CONTENT", '{"model":"deepseek/deepseek-chat"}')
    env = resolve_auth_env()
    assert env["DEEPSEEK_API_KEY"] == "sk"
    assert env["OPENCODE_CONFIG_CONTENT"].startswith('{"model"')


def test_none_when_no_provider_key(monkeypatch):
    # Config env alone is not auth
    monkeypatch.setenv("OPENCODE_CONFIG_CONTENT", '{"x":1}')
    assert resolve_auth_env() is None


# ── egress ──────────────────────────────────────────────────────────────────

def test_required_egress_hosts_deepseek(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk")
    assert required_egress_hosts() == ["api.deepseek.com:443"]


def test_required_egress_hosts_anthropic(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk")
    assert required_egress_hosts() == ["api.anthropic.com:443"]


def test_required_egress_hosts_default(monkeypatch):
    assert required_egress_hosts() == ["api.anthropic.com:443"]


def test_check_egress_satisfied_ok(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk")
    check_egress_satisfied("api.deepseek.com:443")  # must not raise/exit


def test_check_egress_satisfied_missing(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk")
    with pytest.raises(SystemExit):
        check_egress_satisfied("api.anthropic.com:443")


# ── misc ────────────────────────────────────────────────────────────────────

def test_no_auth_msg_lists_opencode_providers():
    assert "DEEPSEEK_API_KEY" in NO_AUTH_MSG
    assert "deepseek/deepseek-chat" in NO_AUTH_MSG


def test_warn_bedrock_model_is_noop():
    assert warn_bedrock_model("any-model") is None
