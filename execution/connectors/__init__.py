"""
execution/connectors/__init__.py
---------------------------------
Connector registry — maps model name strings to the right connector class.

Usage:
    from execution.connectors import get_connector
    connector = get_connector("gpt-4o")
    connector = get_connector("claude-opus-4-6")
    connector = get_connector("gemini-2.5-flash")
    connector = get_connector("llama3")          # routed to Ollama
"""

from __future__ import annotations

from execution.connectors.base import ModelConnector
from execution.connectors.openai_connector import OpenAIConnector
from execution.connectors.anthropic_connector import AnthropicConnector
from execution.connectors.gemini_connector import GeminiConnector
from execution.connectors.ollama_connector import OllamaConnector

# Model name prefix → connector class
_OPENAI_PREFIXES = ("gpt-", "o1", "o3", "o4", "text-")
_ANTHROPIC_PREFIXES = ("claude-",)
_GEMINI_PREFIXES = ("gemini-",)


def get_connector(model_name: str, **kwargs) -> ModelConnector:
    """
    Return the appropriate async connector for a given model name string.

    Routing rules (applied in order):
      - Starts with 'gpt-', 'o1', 'o3', 'o4', 'text-' → OpenAI
      - Starts with 'claude-'                          → Anthropic
      - Starts with 'gemini-'                          → Google Gemini
      - Anything else                                  → Ollama (local)

    Extra kwargs (e.g. temperature, api_key) are forwarded to the connector.
    """
    if any(model_name.startswith(p) for p in _OPENAI_PREFIXES):
        return OpenAIConnector(model=model_name, **kwargs)
    if any(model_name.startswith(p) for p in _ANTHROPIC_PREFIXES):
        return AnthropicConnector(model=model_name, **kwargs)
    if any(model_name.startswith(p) for p in _GEMINI_PREFIXES):
        return GeminiConnector(model=model_name, **kwargs)
    # Default: assume Ollama local model
    return OllamaConnector(model=model_name, **kwargs)


__all__ = [
    "ModelConnector",
    "OpenAIConnector",
    "AnthropicConnector",
    "GeminiConnector",
    "OllamaConnector",
    "get_connector",
]
