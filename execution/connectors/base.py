"""
execution/connectors/base.py
-----------------------------
Abstract base class for all model connectors.

Every connector wraps one model family (OpenAI, Anthropic, Gemini, Ollama)
and exposes a single async `chat()` method. The rest of the pipeline only
ever talks to this interface — swapping target models is a one-line change.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class ModelConnector(ABC):
    """Async interface to a hosted or local LLM."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        """The canonical model identifier (e.g. 'gpt-4o', 'claude-opus-4-6')."""

    @abstractmethod
    async def chat(
        self,
        user_prompt: str,
        system_prompt: str | None = None,
        max_tokens: int = 2048,
    ) -> str:
        """
        Send a single-turn chat request and return the model's text reply.

        Args:
            user_prompt:   The user-turn message (the attack variant).
            system_prompt: Optional system instruction prepended before the
                           user turn. Useful for simulating a target system
                           that has a fixed persona or policy.
            max_tokens:    Upper bound on response length.

        Returns:
            The model's text response as a plain string.

        Raises:
            Exception: Propagates API errors so the pipeline can log them and
                       store them in the AttackResult.error field.
        """
