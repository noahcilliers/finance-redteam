"""
seed_loader.py
--------------
Loads static attack YAML files from `attacks/library/` and filters them
according to a `seed_filters` block from the generation config.

Every filter is optional. Filters combine with AND. List-valued filters
(e.g. `financial_subdomain`) match if ANY listed value matches the seed.

Returned seeds are plain dicts — the schema is whatever the YAML file
contains, augmented with `_source_path` pointing back to the file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


DEFAULT_LIBRARY_ROOT = Path(__file__).resolve().parent.parent / "attacks" / "library"


class SeedLoader:
    def __init__(self, library_root: Path | str = DEFAULT_LIBRARY_ROOT) -> None:
        self.library_root = Path(library_root)
        if not self.library_root.is_dir():
            raise FileNotFoundError(f"Attack library not found at {self.library_root}")

    def load_all(self) -> list[dict[str, Any]]:
        """Load every YAML file under the library, no filtering."""
        seeds: list[dict[str, Any]] = []
        for path in sorted(self.library_root.rglob("*.yaml")):
            with path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                continue  # skip malformed files rather than crashing the run
            data["_source_path"] = str(path.relative_to(self.library_root))
            seeds.append(data)
        return seeds

    def load(self, seed_filters: dict[str, Any] | None) -> list[dict[str, Any]]:
        """Load all seeds then apply the config's filter block."""
        all_seeds = self.load_all()
        if not seed_filters:
            return all_seeds
        return [s for s in all_seeds if self._matches(s, seed_filters)]

    # ---- filter logic ------------------------------------------------

    @staticmethod
    def _matches(seed: dict[str, Any], f: dict[str, Any]) -> bool:
        # exact-match override: if attack_ids is set, nothing else matters
        ids = f.get("attack_ids") or []
        if ids:
            return seed.get("id") in ids

        # list filters (OR within the list, AND across filters)
        def in_list(field: str, key: str) -> bool:
            allowed = f.get(key) or []
            if not allowed:
                return True
            return seed.get(field) in allowed

        if not in_list("financial_subdomain", "financial_subdomain"):
            return False
        if not in_list("attack_type", "attack_type"):
            return False

        seed_tags = set(seed.get("tags") or [])

        tags_any = set(f.get("tags_any") or [])
        if tags_any and seed_tags.isdisjoint(tags_any):
            return False

        tags_all = set(f.get("tags_all") or [])
        if tags_all and not tags_all.issubset(seed_tags):
            return False

        tags_none = set(f.get("tags_none") or [])
        if tags_none and not seed_tags.isdisjoint(tags_none):
            return False

        sev = seed.get("severity_potential")
        if sev is not None:
            if "min_severity" in f and sev < f["min_severity"]:
                return False
            if "max_severity" in f and sev > f["max_severity"]:
                return False

        return True
