"""
execution/pipeline_config.py
-----------------------------
PipelineConfig extends GenerationConfig with execution-specific settings:
concurrency caps, rate limits, target system prompt, output options, etc.

Usage:
    cfg = PipelineConfig.from_yaml("execution/pipeline_config.yaml")
    # cfg also inherits all generation config fields (seed_filters, mutations, …)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from generation.mutation_prompt_builder import GenerationConfig


@dataclass
class PipelineConfig(GenerationConfig):
    # ---- Execution controls ----------------------------------------
    # Max simultaneous in-flight calls to the attacker LLM.
    attacker_max_concurrent: int = 3
    # Attacker LLM calls per second (across all concurrent slots).
    attacker_rps: float = 2.0
    # Max simultaneous in-flight calls to the target model.
    target_max_concurrent: int = 5
    # Target model calls per second.
    target_rps: float = 5.0

    # ---- Target model options -------------------------------------
    # Optional system prompt injected into every target model call.
    # Simulates deploying the target inside a product with a fixed persona.
    target_system_prompt: str | None = None

    # ---- Run behaviour --------------------------------------------
    # dry_run=True builds and logs everything but skips actual API calls.
    dry_run: bool = False
    # If True, skip the attacker LLM step and send seed prompts directly
    # to the target. Useful for baseline testing.
    skip_attacker: bool = False

    # ---- Output ---------------------------------------------------
    # Directory where JSONL run logs are written.
    runs_dir: str = "runs"
    # Write a JSONL file for this run (in addition to SQLite).
    save_jsonl: bool = True

    @classmethod
    def from_yaml(cls, path: Path | str) -> "PipelineConfig":
        with Path(path).open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        # Accept all fields that appear in either the parent or this class.
        known = {
            *GenerationConfig.__dataclass_fields__.keys(),
            *cls.__dataclass_fields__.keys(),
        }
        return cls(**{k: v for k, v in data.items() if k in known})
