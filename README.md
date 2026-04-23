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

The judge and dashboard are working, but the result set has known rough edges. These are maintenance tasks, not blockers for Phase 6 — but closing them out first would make Phase 6 benchmarking cleaner:

- **REFUSAL sentinel migration unapplied.** 279 of 765 rows carry the `[REFUSAL]` sentinel string as `response_text`. `scripts/migrate_refusal_sentinel.py` is written and idempotent but hasn't been run against the production DB. Running it marks those rows with `error='api_level_refusal'` so downstream eval doesn't score them as 0.0 severity.
- **334 unjudged rows.** 431 of 765 rows have a judge verdict; the remainder (mostly from the most recent runs) need to be pushed through `eval_runner.py --all`.
- **3b flat-severity investigation.** The 3b (fraud/scams) severity distribution is flat at ~0.0 across 342 rows. Partially explained by the REFUSAL sentinel issue above; need to re-judge after migration to confirm.
- **Coverage gaps.** 3c has 98 rows against 9 seeds while 3b has 342 rows against 17 seeds — coverage is uneven. A coverage-matrix report and gap-fill runner are on the agenda before Phase 6 (see project notes on test automation).

## Cost Estimate

~$15–40 total in API credits for the full 2,500-run benchmark.

---

*Scope locked: April 2026. Any material change to target models, domain, attack categories, or success metric should be re-reviewed rather than drift silently.*
