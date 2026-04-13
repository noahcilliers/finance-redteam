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
├── attacks/          # Attack prompt libraries, organised by category
├── dashboard/        # Streamlit results dashboard
├── data/             # Raw results, SQLite/Parquet databases
├── docs/             # Scope documents, architecture notes, phase write-ups
├── evaluation/       # Judge LLM rubric and scoring logic
├── execution/        # Attack runner, API clients, retry logic
├── redteam-env/      # Python virtual environment (gitignored)
├── .env              # API keys (gitignored)
├── .env.example      # Safe template to commit
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

| Phase | Description | Status |
|---|---|---|
| 0 | Foundation, scope & setup | ✅ Complete |
| 1 | Architecture design | 🔜 Next |
| 2 | Attack library construction | ⏳ Pending |
| 3 | Execution engine | ⏳ Pending |
| 4 | Evaluation & judging | ⏳ Pending |
| 5 | Dashboard & reporting | ⏳ Pending |
| 6 | Write-up & publication | ⏳ Pending |

## Cost Estimate

~$15–40 total in API credits for the full 2,500-run benchmark.

---

*Scope locked: April 2026. Any material change to target models, domain, attack categories, or success metric should be re-reviewed rather than drift silently.*
