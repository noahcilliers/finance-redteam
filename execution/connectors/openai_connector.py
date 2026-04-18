"""
execution/connectors/openai_connector.py
-----------------------------------------
Async connector for OpenAI models (GPT-4o, GPT-3.5-turbo, o-series, etc.).

Reads OPENAI_API_KEY from the environment (or .env via python-dotenv).
"""

from __future__ import annotations

import os

from openai import AsyncOpenAI

from execution.connectors.base import ModelConnector


class OpenAIConnector(ModelConnector):
    def __init__(
        self,
        model: str = "gpt-4o",
        api_key: str | None = None,
        temperature: float = 1.0,
    ) -> None:
        self._model = model
        self._temperature = temperature
        self._client = AsyncOpenAI(api_key=api_key or os.getenv("OPENAI_API_KEY"))

    @property
    def model_name(self) -> str:
        return self._model

    async def chat(
        self,
        user_prompt: str,
        system_prompt: str | None = None,
        max_tokens: int = 2048,
    ) -> str:
        messages: list[dict] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})

        resp = await self._client.chat.completions.create(
            model=self._model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=self._temperature,
        )
        return resp.choices[0].message.content or ""
