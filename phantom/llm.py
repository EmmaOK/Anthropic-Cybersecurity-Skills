"""
llm.py — Claude client factory for Phantom.

Selects between the first-party Anthropic API and Amazon Bedrock at runtime,
so the same reasoning code (server.py, orchestrator.py) runs against either
backend without change. Bedrock is opt-in via an env var; the default stays
the first-party API (ADR-0011).

Env vars:
  PHANTOM_USE_BEDROCK   "1"/"true"/"yes" → route through Amazon Bedrock
                        (AnthropicBedrockMantle, the Messages-API endpoint)
  PHANTOM_BEDROCK_MODEL override the Bedrock model id
                        (default: "anthropic." + the caller's model id)
  AWS_REGION            region for Bedrock (required on Bedrock; ECS sets it)
  ANTHROPIC_API_KEY     used only on the first-party API path

On Bedrock the client authenticates via the standard AWS credential chain
(on ECS: the task role) — no API key is read. Bedrock model ids take an
"anthropic." prefix, e.g. "anthropic.claude-opus-4-8".
"""

import os


def use_bedrock() -> bool:
    """True when Phantom should route inference through Amazon Bedrock."""
    return os.environ.get("PHANTOM_USE_BEDROCK", "").lower() in ("1", "true", "yes")


def _region() -> str:
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")


def resolve_model(default: str) -> str:
    """Map a first-party model id to the one the active backend expects."""
    if use_bedrock():
        return os.environ.get("PHANTOM_BEDROCK_MODEL") or f"anthropic.{default}"
    return default


def make_async_client():
    """Async Claude client for the active backend (used by server.py)."""
    if use_bedrock():
        from anthropic import AsyncAnthropicBedrockMantle
        return AsyncAnthropicBedrockMantle(aws_region=_region())
    from anthropic import AsyncAnthropic
    return AsyncAnthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))


def make_sync_client(api_key: str | None = None):
    """Sync Claude client for the active backend (used by orchestrator.py)."""
    if use_bedrock():
        from anthropic import AnthropicBedrockMantle
        return AnthropicBedrockMantle(aws_region=_region())
    import anthropic
    return anthropic.Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY", ""))
