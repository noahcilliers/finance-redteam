"""Subprocess launcher + scope preview for the Run Attacks page.

This module is the only place the dashboard shells out to the actual pipeline.
It stays UI-agnostic: every function here is callable from a plain Python
REPL, which keeps it testable and keeps Streamlit-specific concerns (session
state, widgets) inside ``pages/run.py``.
"""

from __future__ import annotations

import json
import os
import shlex
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

# --- Project paths ----------------------------------------------------------

_HERE = Path(__file__).resolve().parent
PROJECT_ROOT = _HERE.parent.parent  # dashboard/utils/ -> dashboard/ -> project root
EXECUTION_MODULE = "execution.deepteam_run"
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "execution" / "pipeline_config.yaml"
RUNS_DIR = PROJECT_ROOT / "runs"
LAUNCHER_CONFIG_DIR = RUNS_DIR / "dashboard_configs"
LAUNCHER_LOG_DIR = RUNS_DIR / "dashboard_logs"


def project_root() -> Path:
    return PROJECT_ROOT


# Make the project importable so we can re-use its own seed loader.
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# --- Seed catalog -----------------------------------------------------------


@dataclass(frozen=True)
class SeedRecord:
    """Flat view of a YAML seed — just the fields the UI needs for filtering."""

    id: str
    attack_type: Optional[str]
    attack_technique: Optional[str]
    financial_subdomain: Optional[str]
    owasp_category: Optional[str]
    mitre_technique: Optional[str]
    severity_potential: Optional[int]
    tags: tuple[str, ...]
    source_path: str


def _coerce_tags(raw) -> tuple[str, ...]:
    if not raw:
        return ()
    if isinstance(raw, str):
        return (raw,)
    return tuple(str(t) for t in raw)


def load_seed_catalog() -> list[SeedRecord]:
    """Load every YAML seed under attacks/library/. Never raises on one bad file."""
    library_root = PROJECT_ROOT / "attacks" / "library"
    records: list[SeedRecord] = []
    if not library_root.is_dir():
        return records
    for path in sorted(library_root.rglob("*.yaml")):
        try:
            with path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        records.append(
            SeedRecord(
                id=str(data.get("id") or path.stem),
                attack_type=data.get("attack_type"),
                attack_technique=data.get("attack_technique"),
                financial_subdomain=data.get("financial_subdomain"),
                owasp_category=data.get("owasp_category"),
                mitre_technique=data.get("mitre_technique"),
                severity_potential=data.get("severity_potential"),
                tags=_coerce_tags(data.get("tags")),
                source_path=str(path.relative_to(library_root)),
            )
        )
    return records


# --- Scope preview ----------------------------------------------------------


@dataclass
class ScopeFilters:
    """Filter selections from the UI form. All fields optional."""

    subdomains: list[Optional[str]] = field(default_factory=list)
    attack_types: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    tags_any: list[str] = field(default_factory=list)
    tags_none: list[str] = field(default_factory=list)
    min_severity: Optional[int] = None
    max_severity: Optional[int] = None

    def matches(self, seed: SeedRecord) -> bool:
        if self.subdomains:
            if seed.financial_subdomain not in self.subdomains:
                return False
        if self.attack_types and (seed.attack_type not in self.attack_types):
            return False
        if self.techniques and (seed.attack_technique not in self.techniques):
            return False
        seed_tags = set(seed.tags)
        if self.tags_any and seed_tags.isdisjoint(self.tags_any):
            return False
        if self.tags_none and not seed_tags.isdisjoint(self.tags_none):
            return False
        if self.min_severity is not None and (
            seed.severity_potential is None or seed.severity_potential < self.min_severity
        ):
            return False
        if self.max_severity is not None and (
            seed.severity_potential is None or seed.severity_potential > self.max_severity
        ):
            return False
        return True


@dataclass
class ScopePreview:
    matching_seeds: int
    total_attacks: int           # actual test-case count (mode-dependent)
    est_runtime_seconds: float   # scope / rps, ignoring concurrency starvation
    matched_ids: list[str]
    attacks_note: str = ""       # human-readable breakdown shown under the count

    def humanised_runtime(self) -> str:
        s = max(0.0, self.est_runtime_seconds)
        if s < 90:
            return f"~{int(s)}s"
        if s < 60 * 60:
            return f"~{s / 60:.1f} min"
        return f"~{s / 3600:.1f} hr"


def _estimate_lf_attacks_per_seed(
    seed: SeedRecord,
    *,
    include_llm_enhancers: bool = True,
) -> int:
    """
    Estimate how many test cases library-faithful mode generates for one seed.

    Mirrors deepteam_bridge.dispatch_enhancers without importing DeepTeam, so
    the scope preview stays lightweight. 1 raw + N applicable enhancers.
    """
    technique = (seed.attack_technique or "").strip()
    tags = set(seed.tags)
    count = 1  # raw seed prompt is always included

    # Deterministic encoders — always-on unless the seed is already in that encoding
    if technique != "base64":
        count += 1   # Base64
    if technique != "leetspeak":
        count += 1   # Leetspeak
    count += 1       # ROT13 (always safe to add)

    if not include_llm_enhancers:
        return count

    # LLM-based enhancers — only applied when technique matches
    if technique in {"direct_injection", "system_prompt_extraction"}:
        count += 2   # PromptInjection + SystemOverride
    elif technique == "indirect_injection":
        count += 1   # PromptInjection only

    roleplay_techniques = {
        "dan_roleplay", "persona_roleplay", "alternate_reality_roleplay",
        "character_capture", "hypothetical_framing",
    }
    if technique in roleplay_techniques or "roleplay" in tags:
        count += 1   # Roleplay

    authority_techniques = {
        "refusal_bypass", "jurisdiction_claim", "validation_framing", "language_probe",
    }
    if technique in authority_techniques:
        count += 1   # AuthorityEscalation

    # Multilingual is skipped for seeds that are already non-English
    if technique != "language_switch":
        count += 1   # Multilingual

    return count


def preview_scope(
    seeds: list[SeedRecord],
    filters: ScopeFilters,
    variants_per_seed: int,
    target_rps: float,
    *,
    mode: str = "library-faithful",
    include_llm_enhancers: bool = True,
) -> ScopePreview:
    matched = [s for s in seeds if filters.matches(s)]
    rps = max(target_rps, 0.01)
    # Per-attack wall time includes judge + target round trips; the observed
    # mean in the existing runs log is ~90s per attack. Use that as a floor,
    # but never shorter than the rate-limit interval.
    per_attack_seconds = max(90.0, 1.0 / rps)

    if mode == "library-faithful":
        # In library-faithful mode the attack count is determined by how many
        # enhancers each seed triggers, NOT by variants_per_seed (that slider
        # is simulator-mode only). Compute per-seed to get the real total.
        per_seed_counts = [
            _estimate_lf_attacks_per_seed(s, include_llm_enhancers=include_llm_enhancers)
            for s in matched
        ]
        total_attacks = sum(per_seed_counts)
        if matched:
            avg = total_attacks / len(matched)
            attacks_note = (
                f"library-faithful: ~{avg:.1f} test cases/seed "
                f"(raw + deterministic encoders"
                + (" + LLM enhancers" if include_llm_enhancers else "")
                + ")"
            )
        else:
            attacks_note = "library-faithful mode"
    else:
        total_attacks = len(matched) * max(1, variants_per_seed)
        attacks_note = (
            f"simulator: {len(matched)} seeds × {int(variants_per_seed)} variants"
        )

    return ScopePreview(
        matching_seeds=len(matched),
        total_attacks=total_attacks,
        est_runtime_seconds=total_attacks * per_attack_seconds,
        matched_ids=[s.id for s in matched],
        attacks_note=attacks_note,
    )


# --- Config YAML builder ----------------------------------------------------


def load_base_config() -> dict[str, Any]:
    """Load the checked-in base pipeline_config.yaml as a dict."""
    if not DEFAULT_CONFIG_PATH.is_file():
        return {}
    with DEFAULT_CONFIG_PATH.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data


def build_config_dict(form: dict[str, Any]) -> dict[str, Any]:
    """Merge user form selections onto the base config.

    The form dict uses simple keys; we only overwrite fields the user touched.
    Anything not in the form is inherited from pipeline_config.yaml, so niche
    fields (feedback_loop, custom_instructions, etc.) still flow through.
    """
    cfg = load_base_config()
    seed_filters = dict(cfg.get("seed_filters") or {})

    if "subdomains" in form:
        # Only non-None values — SeedLoader's financial_subdomain filter
        # is skipped when the list is empty, which gives "all including None".
        subs = [s for s in form["subdomains"] if s is not None]
        if subs:
            seed_filters["financial_subdomain"] = subs
        else:
            seed_filters.pop("financial_subdomain", None)

    if "attack_types" in form and form["attack_types"]:
        seed_filters["attack_type"] = list(form["attack_types"])
    elif "attack_types" in form:
        seed_filters.pop("attack_type", None)

    if "tags_any" in form and form["tags_any"]:
        seed_filters["tags_any"] = list(form["tags_any"])
    elif "tags_any" in form:
        seed_filters.pop("tags_any", None)

    if "tags_none" in form:
        if form["tags_none"]:
            seed_filters["tags_none"] = list(form["tags_none"])
        else:
            seed_filters.pop("tags_none", None)

    if "min_severity" in form and form["min_severity"] is not None:
        seed_filters["min_severity"] = int(form["min_severity"])
    if "max_severity" in form and form["max_severity"] is not None:
        seed_filters["max_severity"] = int(form["max_severity"])

    cfg["seed_filters"] = seed_filters

    for yaml_key, form_key in {
        "variants_per_seed": "variants_per_seed",
        "attacker_model": "attacker_model",
        "target_model": "target_model",
        "target_max_concurrent": "target_max_concurrent",
        "target_rps": "target_rps",
        "dry_run": "dry_run",
        "skip_attacker": "skip_attacker",
    }.items():
        if form_key in form and form[form_key] is not None:
            cfg[yaml_key] = form[form_key]

    if form.get("target_system_prompt"):
        cfg["target_system_prompt"] = form["target_system_prompt"]

    return cfg


def write_config_file(cfg: dict[str, Any]) -> Path:
    """Write cfg to runs/dashboard_configs/<timestamp>.yaml and return the path."""
    LAUNCHER_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    path = LAUNCHER_CONFIG_DIR / f"run_{ts}.yaml"
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, sort_keys=False)
    return path


def build_cli_args(
    config_path: Path,
    form: dict[str, Any],
) -> list[str]:
    """Produce the argv list for ``python -m execution.deepteam_run``.

    We always pass --config; other flags only appear when the user overrode
    the corresponding dashboard control, so the YAML remains the source of
    truth for anything the form doesn't expose.
    """
    args = [sys.executable, "-u", "-m", EXECUTION_MODULE, "--config", str(config_path)]

    if form.get("target_model"):
        args += ["--target", str(form["target_model"])]

    mode = form.get("mode") or "library-faithful"
    args += ["--mode", mode]

    if form.get("simulator_model"):
        args += ["--simulator", str(form["simulator_model"])]
    if form.get("evaluator_model"):
        args += ["--evaluator", str(form["evaluator_model"])]

    if form.get("variants_per_seed") is not None:
        args += ["--attacks-per-type", str(int(form["variants_per_seed"]))]

    if form.get("target_max_concurrent") is not None:
        args += ["--max-concurrent", str(int(form["target_max_concurrent"]))]

    if form.get("target_rps") is not None:
        rpm = max(1, int(round(float(form["target_rps"]) * 60)))
        args += ["--rpm", str(rpm)]

    if form.get("no_llm_enhancers"):
        args += ["--no-llm-enhancers"]
    if form.get("no_enhancers"):
        args += ["--no-enhancers"]

    if form.get("verbose"):
        args += ["-v"]
    return args


# --- Subprocess launch / monitor / stop -------------------------------------


@dataclass
class ActiveRun:
    pid: int
    started_at: float
    config_path: str
    log_path: str
    argv: list[str]

    def pretty_argv(self) -> str:
        return " ".join(shlex.quote(a) for a in self.argv)

    def wall_seconds(self) -> float:
        return max(0.0, time.time() - self.started_at)


def launch_run(argv: list[str]) -> tuple[subprocess.Popen, ActiveRun]:
    """Spawn the runner, redirecting combined stdout+stderr to a log file.

    The subprocess is started in a new session so a Streamlit server crash
    (or the user closing the browser) doesn't take the run down with it.
    """
    LAUNCHER_LOG_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    log_path = LAUNCHER_LOG_DIR / f"launcher_{ts}.log"
    log_file = log_path.open("w", encoding="utf-8", buffering=1)  # line-buffered
    log_file.write(f"# Launched {ts} UTC\n# argv: {' '.join(shlex.quote(a) for a in argv)}\n\n")
    log_file.flush()

    # Isolate from the parent process group so terminate() doesn't bubble
    # Streamlit's SIGTERM up, and so the run survives a server crash.
    popen_kwargs: dict[str, Any] = dict(
        cwd=str(PROJECT_ROOT),
        stdout=log_file,
        stderr=subprocess.STDOUT,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    if hasattr(os, "setsid"):
        popen_kwargs["preexec_fn"] = os.setsid  # POSIX
    else:
        popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

    proc = subprocess.Popen(argv, **popen_kwargs)

    config_path = ""
    if "--config" in argv:
        i = argv.index("--config")
        if i + 1 < len(argv):
            config_path = argv[i + 1]

    active = ActiveRun(
        pid=proc.pid,
        started_at=time.time(),
        config_path=config_path,
        log_path=str(log_path),
        argv=list(argv),
    )
    return proc, active


def process_alive(proc: Optional[subprocess.Popen]) -> bool:
    if proc is None:
        return False
    return proc.poll() is None


def stop_run(proc: subprocess.Popen, grace_seconds: float = 5.0) -> str:
    """Send SIGTERM, wait briefly, then SIGKILL. Returns final status string."""
    if proc.poll() is not None:
        return f"already exited (rc={proc.returncode})"
    try:
        if hasattr(os, "killpg") and hasattr(os, "getpgid"):
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.terminate()
    except (ProcessLookupError, PermissionError) as e:
        return f"terminate failed: {e}"

    try:
        proc.wait(timeout=grace_seconds)
        return f"terminated (rc={proc.returncode})"
    except subprocess.TimeoutExpired:
        try:
            if hasattr(os, "killpg") and hasattr(os, "getpgid"):
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
            proc.wait(timeout=grace_seconds)
            return f"killed (rc={proc.returncode})"
        except Exception as e:
            return f"kill failed: {e}"


# --- Log tailing ------------------------------------------------------------


def read_log_tail(log_path: str | Path, max_lines: int = 200) -> str:
    """Read the last ``max_lines`` lines of the log file. Best-effort, no errors."""
    p = Path(log_path)
    if not p.is_file():
        return ""
    try:
        # For typical launcher logs (<10 MB) this is plenty fast. We read the
        # whole file instead of fancy seeking so UTF-8 decoding doesn't split
        # in the middle of a multi-byte character.
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return f"(could not read log: {e})"
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text
    return "\n".join(lines[-max_lines:])


# --- Recent runs inventory --------------------------------------------------


@dataclass
class RecentRun:
    jsonl_path: str
    started_at: float
    attack_count: int
    target_models: list[str]


def list_recent_runs(limit: int = 5) -> list[RecentRun]:
    """Scan runs/ for deepteam_run_*.jsonl files. Returns newest first.

    Reads just enough of each JSONL to produce a summary — attack_count comes
    from a line count, target_models from the first record's ``target_model``
    field. Non-blocking, safe on malformed files.
    """
    if not RUNS_DIR.is_dir():
        return []
    paths = sorted(
        (p for p in RUNS_DIR.glob("deepteam_run_*.jsonl") if p.is_file()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )[:limit]

    out: list[RecentRun] = []
    for p in paths:
        target_models: list[str] = []
        count = 0
        try:
            with p.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    count += 1
                    if count <= 5:  # sample first 5 records for model info
                        try:
                            rec = json.loads(line)
                            tm = rec.get("target_model") or rec.get("target") or ""
                            if tm and tm not in target_models:
                                target_models.append(tm)
                        except json.JSONDecodeError:
                            pass
        except Exception:
            continue
        out.append(
            RecentRun(
                jsonl_path=str(p),
                started_at=p.stat().st_mtime,
                attack_count=count,
                target_models=target_models,
            )
        )
    return out


# --- API-key status ---------------------------------------------------------


@dataclass
class KeyStatus:
    openai: bool
    anthropic: bool
    google: bool
    dotenv_found: bool


def api_key_status() -> KeyStatus:
    """Check whether the project's .env + current environment have the needed keys.

    We look at three locations, in order: the live process env (what Streamlit
    itself sees), then .env at the project root. A key is considered present
    if it's defined and non-empty in *either* place.
    """
    dotenv_path = PROJECT_ROOT / ".env"
    dotenv_values: dict[str, str] = {}
    if dotenv_path.is_file():
        try:
            for line in dotenv_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                dotenv_values[k.strip()] = v.strip().strip("'\"")
        except Exception:
            pass

    def has(name: str) -> bool:
        return bool(os.environ.get(name) or dotenv_values.get(name))

    return KeyStatus(
        openai=has("OPENAI_API_KEY"),
        anthropic=has("ANTHROPIC_API_KEY"),
        google=has("GOOGLE_API_KEY"),
        dotenv_found=dotenv_path.is_file(),
    )


# --- Known model lists ------------------------------------------------------

KNOWN_TARGET_MODELS: tuple[str, ...] = (
    "claude-sonnet-4-6",
    "claude-opus-4-6",
    "claude-haiku-4-5",
    "gpt-4o",
    "gpt-4o-mini",
    "gemini-2.0-flash",
)

KNOWN_ATTACKER_MODELS: tuple[str, ...] = (
    "gpt-4o",
    "gpt-4o-mini",
    "claude-sonnet-4-6",
    "claude-haiku-4-5",
)

KNOWN_EVALUATOR_MODELS: tuple[str, ...] = (
    "gpt-4o-mini",
    "gpt-4o",
    "claude-haiku-4-5",
    "claude-sonnet-4-6",
)
