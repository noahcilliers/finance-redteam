"""
execution/attacker.py
----------------------
AttackerClient — calls the attacker LLM with a mutation prompt and parses the
JSON array of variant strings it returns.

The attacker LLM is instructed (in MutationPromptBuilder._output_contract_block)
to respond with a bare JSON array of strings. In practice models sometimes wrap
this in a markdown code fence, add a preamble, or return malformed JSON. The
parser here handles all common cases with a graceful fallback chain.

Design:
  - AttackerClient is async and uses a RateLimiter for concurrency control.
  - parse_variants() is a staticmethod so it can be tested independently.
  - On JSON parse failure, the error is re-raised with the raw response snippet
    attached so the pipeline can log it and move on.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from execution.connectors.base import ModelConnector
from execution.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

# Regex to pull a JSON array out of a response that may have surrounding text.
_JSON_ARRAY_RE = re.compile(r"\[.*\]", re.DOTALL)
# Regex to pull array from a markdown code block.
_CODE_FENCE_RE = re.compile(r"```(?:json)?\s*(\[.*?\])\s*```", re.DOTALL)


class AttackerParseError(ValueError):
    """Raised when the attacker LLM response cannot be parsed as a JSON array."""


class AttackerClient:
    """
    Wraps a ModelConnector to call the attacker LLM and parse its output.

    Args:
        connector:    A ModelConnector pointed at the attacker model.
        rate_limiter: RateLimiter controlling concurrency/rate to the attacker.
        max_tokens:   Token budget for the attacker response.
    """

    def __init__(
        self,
        connector: ModelConnector,
        rate_limiter: RateLimiter | None = None,
        max_tokens: int = 4096,
    ) -> None:
        self.connector = connector
        self.rate_limiter = rate_limiter or RateLimiter(max_concurrent=3)
        self.max_tokens = max_tokens

    async def generate_variants(self, mutation_prompt: str) -> list[str]:
        """
        Send the mutation prompt to the attacker LLM and return parsed variants.

        Returns:
            List of variant prompt strings (may be fewer than variants_per_seed
            if the model produced fewer, or if some entries were blank).

        Raises:
            AttackerParseError: If the response cannot be parsed as a JSON array.
            Exception:          Propagates raw API errors.
        """
        logger.debug(
            "Calling attacker model '%s' (prompt len=%d chars)",
            self.connector.model_name,
            len(mutation_prompt),
        )

        async with self.rate_limiter:
            raw = await self.connector.chat(
                mutation_prompt,
                max_tokens=self.max_tokens,
            )

        logger.debug("Attacker raw response (%d chars): %.200s…", len(raw), raw)
        variants = self.parse_variants(raw)
        logger.info(
            "Attacker '%s' → %d variants parsed",
            self.connector.model_name,
            len(variants),
        )
        return variants

    @staticmethod
    def parse_variants(raw: str) -> list[str]:
        """
        Parse a JSON array of strings from the attacker LLM's raw text output.

        Fallback chain:
          1. Direct json.loads(raw) — ideal case.
          2. Extract from a ```json … ``` code fence.
          3. Extract the first [...] span from anywhere in the response.

        Raises:
            AttackerParseError: If all three attempts fail.
        """
        # --- attempt 1: bare JSON ---
        stripped = raw.strip()
        try:
            result = json.loads(stripped)
            if isinstance(result, list):
                return [str(v) for v in result if str(v).strip()]
        except json.JSONDecodeError:
            pass

        # --- attempt 2: markdown code fence ---
        fence_match = _CODE_FENCE_RE.search(raw)
        if fence_match:
            try:
                result = json.loads(fence_match.group(1))
                if isinstance(result, list):
                    return [str(v) for v in result if str(v).strip()]
            except json.JSONDecodeError:
                pass

        # --- attempt 3: first [...] span in the text ---
        array_match = _JSON_ARRAY_RE.search(raw)
        if array_match:
            try:
                result = json.loads(array_match.group(0))
                if isinstance(result, list):
                    return [str(v) for v in result if str(v).strip()]
            except json.JSONDecodeError:
                pass

        snippet = raw[:300].replace("\n", " ")
        raise AttackerParseError(
            f"Could not parse attacker response as a JSON array of strings. "
            f"First 300 chars: {snippet!r}"
        )
