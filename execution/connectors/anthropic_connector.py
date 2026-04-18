"""
execution/connectors/anthropic_connector.py
--------------------------------------------
Async connector for Anthropic Claude models.

Reads ANTHROPIC_API_KEY from the environment (or .env via python-dotenv).
"""

from __future__ import annotations

import os

import anthropic as ant

from execution.connectors.base import ModelConnector


class AnthropicConnector(ModelConnector):
    def __init__(
        self,
        model: str = "claude-sonnet-4-6",
        api_key: str | None = None,
        temperature: float = 1.0,
    ) -> None:
        self._model = model
        self._temperature = temperature
        self._client = ant.AsyncAnthropic(api_key=api_key or os.getenv("ANTHROPIC_API_KEY"))

    @property
    def model_name(self) -> str:
        return self._model

    async def chat(
        self,
        user_prompt: str,
        system_prompt: str | None = None,
        max_tokens: int = 2048,
    ) -> str:
        kwargs: dict = {
            "model": self._model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        if system_prompt:
            kwargs["system"] = system_prompt
        # temperature is only supported on some Claude endpoints
        try:
            kwargs["temperature"] = self._temperature
            resp = await self._client.messages.create(**kwargs)
        except ant.BadRequestError:
            # Extended thinking models don't support temperature
            del kwargs["temperature"]
            resp = await self._client.messages.create(**kwargs)

        return resp.content[0].text if resp.content else ""
