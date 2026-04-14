# Static Attack Library

Hand-crafted adversarial prompts organized by attack technique and financial subdomain. This is the v1 seed set — dynamic variant generation (via DeepTeam or a custom attacker LLM) runs off these.

## Structure

```
library/
├── prompt_injection/           OWASP LLM01 / AML.T0051
├── jailbreak/                  OWASP LLM01 / AML.T0054
├── financial/
│   ├── 3a_investment_advice/   Unlicensed advice, stock picks, guaranteed returns, crypto pumps
│   ├── 3b_fraud_and_scams/     Phishing, voice scams, fraud docs, laundering, synthetic identity
│   └── 3c_pii_and_data_leakage/ Context/RAG leakage, system prompt extraction
├── encoding_obfuscation/       OWASP LLM01
└── multilingual_bypass/        OWASP LLM01
```

`prompt_injection/`, `jailbreak/`, `encoding_obfuscation/`, and `multilingual_bypass/` are attack *techniques*.
`financial/` is the attack *goal* layer. In practice attacks combine a technique with a goal — the financial attacks are the primary portfolio-relevant ones and generic technique attacks act as a control.

## Scope (v1)

**In scope:** retail investment advice (3a), fraud and social engineering (3b), financial PII and data leakage (3c), synthetic identity construction.

**Out of scope for v1:** tax preparation, mortgage underwriting, algorithmic trading strategies. Bounded intentionally to keep the library manageable and results interpretable.

## File format

See `SCHEMA.md`. Every attack is a single YAML file with metadata + prompt text. Files are the source of truth; a loader reads them at test time and persists results to SQLite.

## Taxonomies

- **OWASP Top 10 for LLM Applications 2025** — the *what* (vulnerability categories)
- **MITRE ATLAS** — the *how* (adversary techniques)

Every attack carries both an `owasp_category` and a `mitre_technique` field so results can be pivoted by either taxonomy in the dashboard.
