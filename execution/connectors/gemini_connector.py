"""
execution/connectors/gemini_connector.py
-----------------------------------------
Async connector for Google Gemini models.

Reads GOOGLE_API_KEY from the environment (or .env via python-dotenv).
Uses the google-genai SDK's async client (client.aio.*).
"""

from __future__ import annotations

import os

from execution.connectors.base import ModelConnector


class GeminiConnector(ModelConnector):
    def __init__(
        self,
        model: str = "gemini-2.5-flash",
        api_key: str | None = None,
        temperature: float = 1.0,
    ) -> None:
        self._model = model
        self._temperature = temperature
        self._api_key = api_key or os.getenv("GOOGLE_API_KEY")

    @property
    def model_name(self) -> str:
        return self._model

    async def chat(
        self,
        user_prompt: str,
        system_prompt: str | None = None,
        max_tokens: int = 2048,
    ) -> str:
        from google import genai
        from google.genai import types as gtypes

        client = genai.Client(api_key=self._api_key)

        config_kwargs: dict = {
            "max_output_tokens": max_tokens,
            "temperature": self._temperature,
        }
        if system_prompt:
            config_kwargs["system_instruction"] = system_prompt

        config = gtypes.GenerateContentConfig(**config_kwargs)

        resp = await client.aio.models.generate_content(
            model=self._model,
            contents=user_prompt,
            config=config,
        )
        return resp.text or ""
