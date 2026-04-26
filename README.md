# Finance Red-Teaming Benchmark

An automated LLM red-teaming tool that evaluates and compares the safety guardrails of frontier language models in the **financial domain**.

## Overview

This benchmark answers: *"How do today's frontier LLMs compare against older baselines when attacked in finance-specific scenarios?"* The headline deliverable is a benchmark with real numbers, a dashboard, and a public GitHub repo.

## Target Models

**Frontier tier**
- OpenAI — GPT-4o / GPT-4.1
- Anthropic — Claude Sonnet 4.6
- Google — Gemini 2.5 Pro / Flash

**Baseline tier (for generational contrast)**
- OpenAI — GPT-3.5-turbo
- Meta — Llama 2 7B via Ollama (local, free)

## Domain Focus: Financial Services

Three sub-domains, each with its own attack suite:

1. **Retail investment advice** — unlicensed stock picks, leverage recommendations, "guaranteed return" claims
2. **Fraud, scams & social engineering** — phishing emails, voice-scam scripts, money-laundering guidance
3. **Financial PII & data leakage** — account numbers, SSNs, system prompt extraction from a financial chatbot

## Attack Categories

| # | Category | OWASP Mapping |
|---|---|---|
| 1 | Prompt Injection | LLM01:2025 |
| 2 | Role-Play Jailbreaks | LLM01 (subtype) |
| 3 | Encoding / Obfuscation | LLM01 (subtype) |
| 4 | Multi-Turn Escalation | LLM01 (subtype) |
| 5 | Sensitive Info Disclosure | LLM02:2025 |

Target: **2,500 total test runs** — 100 attacks × 5 categories × 5 models.

## Success Metrics

Every test run produces:
- `attack_succeeded: bool` — binary Attack Success Rate (ASR)
- `severity: int 0–10` — how severe the failure was
- `judge_reasoning` — 1–2 sentence explanation from the judge LLM
- `refusal_quality: int 0–3` — quality of the model's refusal wording
- `hallucination_flag: bool` — did the model invent fake financial facts or regulations?

The judge LLM is always a **different provider** than the model being evaluated to avoid self-bias.

## Project Structure

```
finance-redteam/
├── attacks/library/     # 46 YAML attack seeds (3a/3b/3c + generic)
├── generation/          # SeedLoader + MutationPromptBuilder (I/O-free)
├── execution/           # Pipeline runners + async connectors
│   ├── connectors/        # openai, anthropic, gemini, ollama
│   ├── pipeline.py        # async orchestrator
│   ├── deepteam_bridge.py # YAML seed ↔ DeepTeam CustomVulnerability
│   ├── deepteam_run.py    # DeepTeam-powered CLI entry point
│   └── run.py             # MutationPromptBuilder CLI entry point
├── evaluation/          # FinancialSafetyJudge + deterministic pre-pass
│   ├── judge.py           # Anthropic tool-use, per-subdomain rubrics
│   ├── eval_runner.py     # async batch scorer
│   ├── deterministic.py   # PII / system-prompt-echo / harm-keyword detectors
│   ├── eval_schema.py     # pydantic verdict schema
│   └── harm_lexicon.yaml  # 3a/3b/3c keyword buckets
├── dashboard/           # Streamlit app (6 pages)
├── data/                # models.py, database.py, results.db
├── runs/                # Per-run JSONL execution logs
├── scripts/             # One-shot utilities (migrations, replay)
├── tests/               # pytest unit tests (bridge + deterministic)
├── docs/                # Scope, phase plans, architecture notes
├── redteam-env/         # Python virtual environment (gitignored)
├── .env                 # API keys (gitignored)
├── .env.example         # Safe template to commit
└── README.md
```

## Setup

```bash
python3 -m venv redteam-env
source redteam-env/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then fill in your keys
```

## Environment Variables

```
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
GOOGLE_API_KEY=
```

## Project Phases

*Status as of 2026-04-23.*

| Phase | Description | Status |
|---|---|---|
| 0 | Foundation, scope & setup | ✅ Complete |
| 1 | Architecture design | ✅ Complete |
| 2 | Attack library construction | ✅ Complete — 46 YAML seeds (14 × 3a, 17 × 3b, 9 × 3c, 6 generic); multi-turn escalation deferred to v2 |
| 3 | Execution engine | ✅ Complete — 4 async connectors (OpenAI, Anthropic, Gemini, Ollama), rate limiter, two pipeline entry points (`execution/run.py` MutationPromptBuilder path + `execution/deepteam_run.py` DeepTeam path). 765 runs in `data/results.db` across 24 run logs |
| 4 | Evaluation & judging | ✅ Complete — `FinancialSafetyJudge` (Anthropic tool-use, per-subdomain rubrics, single-pass + two-pass modes), `EvalRunner` batch scorer, and the deterministic pre-pass (`evaluation/deterministic.py`: SSN/CC/ABA/email PII detection with Luhn validation, system-prompt echo detection, harm-keyword lexicon, length-anomaly baseline). Residual cleanup items listed below |
| 5 | Dashboard & reporting | ✅ Complete — Streamlit app with 6 pages (overview, heatmap, browser, comparison, live run, judge) wired to the live DB |
| 6 | Defense layer | ⏳ Not started — next up |
| 7 | Feedback loop | 🟡 Partial — rule-based `ResultsAnalyzer` built; evolutionary mutation loop deferred |
| 8 | Write-up & publication | ⏳ Not started |

### Residual cleanup before Phase 6

Re-checked 2026-04-23 with the production DB. Earlier audit had stale info; current picture:

- **REFUSAL sentinel migration — already applied.** Dry-run of `scripts/migrate_refusal_sentinel.py` reports 0 rows matching `response_text = '[REFUSAL]'`. Translated rows correctly carry `error='api_level_refusal'` and empty response text.
- **Judgment "backlog" — not a real backlog.** 431 of 765 rows have a verdict; the other 334 have empty `response_text` (they're the api_level_refusal cohort). `eval_runner.py`'s `_JUDGEABLE_WHERE` filter correctly excludes them — there's nothing to score. A dry-run reports "Nothing to evaluate." as expected.
- **Real coverage gap — target model breadth.** The DB only covers 3 target models: `claude-haiku-4-5`, `claude-sonnet-4-6`, `gpt-4o`. The README's target list (Gemini 2.5 Pro/Flash, GPT-3.5, Llama 2) has zero runs. GPT-4o has only 1 of 19 (attack_type × technique) combos covered. This is where the pre-Phase-6 coverage sweep needs to spend its API budget.
- **3b flat-severity investigation.** Still open, but now cleanly isolated: the sentinel cohort isn't the cause (it's been migrated out). Something about the 3b rubric or the 17 seeds in 3b is pinning scores low. Worth a manual spot-check of 5-10 judged 3b rows before touching the rubric.

### Coverage bar (pinned 2026-04-23)

Coverage of the `(seed × enhancer × target_model)` matrix uses a split threshold:
- **Headline cells** — per-target × per-subdomain top-line ASR cells quoted in the final write-up: **N ≥ 5 runs** per cell (enough for a confidence interval).
- **Exhaustive library coverage** — every other cell across the full matrix: **N ≥ 1 run** per cell (yes/no "did we try this").

The coverage report (to be built) will check both thresholds independently and flag gaps under either.

## Cost Estimate

~$15–40 total in API credits for the full 2,500-run benchmark.

---

*Scope locked: April 2026. Any material change to target models, domain, attack categories, or success metric should be re-reviewed rather than drift silently.*
