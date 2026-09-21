# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Provider/auth resolution for the opencode backend.

The in-container agent is the opencode CLI, which discovers providers from
environment variables (``<PROVIDER>_API_KEY``) and its config files. This
module is the single source of truth for what the pipeline forwards into the
agent container and which egress hosts a provider needs (setup_sandbox.sh /
vp-sandboxed)."""
import os
import re
import sys

_REGION_RE = re.compile(r"^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$")

# API-key env vars opencode reads for its built-in providers. Forward whichever
# are set on the host into the agent container (opencode picks the provider by
# the presence of its key). Add providers here as needed.
_API_KEY_ENVS = (
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
    "GITHUB_TOKEN",  # GitHub Copilot provider
)

# opencode runtime env the pipeline forwards / sets on agent containers.
_OPENCODE_ENVS = (
    "OPENCODE_CONFIG",
    "OPENCODE_CONFIG_DIR",
    "OPENCODE_CONFIG_CONTENT",
    "OPENCODE_DISABLE_AUTOUPDATE",
    "OPENCODE_DISABLE_CLAUDE_CODE",
    "OPENCODE_DISABLE_MODELS_FETCH",
    "OPENCODE_EXPERIMENTAL_BASH_DEFAULT_TIMEOUT_MS",
)

# OpenCode's built-in Bash tool otherwise stops a foreground command after
# roughly two minutes.  Dynamic validation may legitimately need to compile
# an observed copy or run a long-lived protocol harness, so use the same
# 30-minute budget as the target build workflow.  A host-provided value still
# wins, which keeps this adjustable for operators and tests.
DEFAULT_BASH_TIMEOUT_MS = "1800000"

NO_AUTH_MSG = (
    "error: no model-API auth found. Set one of these provider API keys in the "
    "environment (the in-container backend is opencode):\n"
    "  DEEPSEEK_API_KEY                  (DeepSeek)\n"
    "  OPENAI_API_KEY                    (OpenAI)\n"
    "  ANTHROPIC_API_KEY                 (Anthropic)\n"
    "  OPENROUTER_API_KEY                (OpenRouter)\n"
    "  GEMINI_API_KEY / XAI_API_KEY / GROQ_API_KEY / ... (other opencode providers)\n"
    "Then run with --model <provider>/<model>, e.g. --model deepseek/deepseek-chat"
)


def resolve_auth_env() -> dict[str, str] | None:
    """Resolve auth/env for the in-container ``opencode`` process.

    Forwards the configured provider API key(s) plus opencode runtime env into
    the agent container. Returns None if no provider key is configured (callers
    then print NO_AUTH_MSG)."""
    env: dict[str, str] = {}
    for k in _API_KEY_ENVS + _OPENCODE_ENVS:
        if v := os.environ.get(k):
            env[k] = v
    if not any(k in env for k in _API_KEY_ENVS):
        return None
    # opencode behavior inside the isolated agent container: no self-update
    # checks, no reading .claude/, no remote model-metadata fetches.
    env.setdefault("OPENCODE_DISABLE_AUTOUPDATE", "1")
    env.setdefault("OPENCODE_DISABLE_CLAUDE_CODE", "1")
    env.setdefault("OPENCODE_DISABLE_MODELS_FETCH", "1")
    env.setdefault(
        "OPENCODE_EXPERIMENTAL_BASH_DEFAULT_TIMEOUT_MS",
        DEFAULT_BASH_TIMEOUT_MS,
    )
    return env


def warn_bedrock_model(model: str | None) -> None:
    """No-op retained for CLI back-compat (Bedrock is opencode-native now)."""


def required_egress_hosts() -> list[str]:
    """host:port entries the configured provider needs on the proxy allowlist.
    Called from setup_sandbox.sh / vp-sandboxed via ``python3 -c``; exits
    non-zero on misconfig so the shell ``|| die`` fires."""
    if os.environ.get("DEEPSEEK_API_KEY"):
        return ["api.deepseek.com:443"]
    if os.environ.get("OPENAI_API_KEY"):
        return ["api.openai.com:443"]
    if os.environ.get("ANTHROPIC_API_KEY"):
        return ["api.anthropic.com:443"]
    if os.environ.get("OPENROUTER_API_KEY"):
        return ["openrouter.ai:443"]
    if os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_GENERATIVE_AI_API_KEY"):
        return ["generativelanguage.googleapis.com:443"]
    return ["api.anthropic.com:443"]


def _host_allowed(target: str, allow: set[str]) -> bool:
    """Mirror of scripts/egress_proxy.py:_allowed — keep in sync."""
    t = target.lower()
    return any(t == e or (e.startswith("*.") and t.endswith(e[1:])) for e in allow)


def check_egress_satisfied(proxy_allow_csv: str) -> None:
    """Preflight for vp-sandboxed: exit non-zero if any required host is not
    covered by the running proxy's allowlist."""
    allow = {h.strip().lower() for h in proxy_allow_csv.split(",") if h.strip()}
    needed = required_egress_hosts()
    missing = [h for h in needed if not _host_allowed(h, allow)]
    if missing:
        sys.exit(
            f"error: egress proxy allowlist ({proxy_allow_csv}) does not cover "
            f"required host(s): {', '.join(missing)}"
        )
