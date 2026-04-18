"""
execution/connectors/ollama_connector.py
-----------------------------------------
Async connector for locally-running Ollama models (Llama, Mistral, etc.).

Uses the Ollama HTTP API directly via httpx. No API key required.
Configure OLLAMA_BASE_URL env var to override the default localhost address.
"""

from __future__ import annotations

import os

import httpx

from execution.connectors.base import ModelConnector

DEFAULT_BASE_URL = "http://localhost:11434"


class OllamaConnector(ModelConnector):
    def __init__(
        self,
        model: str = "llama2",
        base_url: str | None = None,
        temperature: float = 0.8,
        timeout: float = 120.0,
    ) -> None:
        self._model = model
        self._base_url = (base_url or os.getenv("OLLAMA_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self._temperature = temperature
        self._timeout = timeout

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

        payload: dict = {
            "model": self._model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self._temperature,
                "num_predict": max_tokens,
            },
        }

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{self._base_url}/api/chat",
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()

        return data.get("message", {}).get("content", "")
