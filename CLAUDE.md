# finance-redteam — Project Context

## Project root
`/Users/noahcilliers/finance-redteam`

All code, tests, and execution live here. The Claude workspace folder ("AI RedTeaming Program") is for planning docs only — do not write code outputs there.

## What this project is
An automated LLM red-teaming pipeline targeting financial-domain safety failures. Three attack subdomains:
- **3a — Retail investment advice:** unlicensed stock picks, leverage recs, guaranteed-return claims, crypto pumps
- **3b — Fraud & social engineering:** phishing, voice scam scripts, document fraud, money laundering, synthetic identity
- **3c — Financial PII & data leakage:** context-window extraction, RAG corpus leakage, system prompt exfiltration

Out of scope for v1: tax preparation, mortgage underwriting, algorithmic trading.

## Architecture
```
attacks/library/     Static YAML attack seeds (46 files, organized by technique + subdomain)
generation/          MutationPromptBuilder — builds prompts for attacker LLM
execution/           Target model connectors + pipeline runner (not yet built)
evaluation/          LLM-as-judge + deterministic checks (not yet built)
data/results.db      SQLite results store
dashboard/           Streamlit visualisation (not yet built)
```

## Key design decisions
- DeepTeam used for dynamic attack generation; custom library provides domain-specific seeds
- Attack YAML schema: every file has `id`, `owasp_category`, `mitre_technique`, `financial_subdomain`, `severity_potential`, `tags`
- MutationPromptBuilder is I/O-free — takes seed + config, returns a string; ResultsAnalyzer is separate
- Feedback loop: rule-based ResultsAnalyzer feeds past-run patterns into mutation prompt (to be built)
- Attacker model ≠ target model by design

## Python environment
```bash
cd /Users/noahcilliers/finance-redteam
source redteam-env/bin/activate   # or create with: python3 -m venv redteam-env
pip install pyyaml deepteam openai anthropic
```

## Running the generation dry run
```bash
cd /Users/noahcilliers/finance-redteam
python3 -c "
from generation.mutation_prompt_builder import GenerationConfig, MutationPromptBuilder
from generation.seed_loader import SeedLoader
cfg = GenerationConfig.from_yaml('generation/generate_config.yaml')
seeds = SeedLoader().load(cfg.seed_filters)
print(f'{len(seeds)} seeds matched')
print(MutationPromptBuilder(cfg).build(seeds[0]))
"
```

## Running the red-team pipeline

### Environment
```bash
cd /Users/noahcilliers/finance-redteam
source redteam-env/bin/activate
```

### Test model connectivity
```bash
python test_connections.py
# Checks: gpt-4o, gpt-3.5-turbo, claude-sonnet-4-6, gemini-2.5-flash, llama2 (ollama/local)
```

### Run attacks (DeepTeam pipeline)
Config lives at `execution/pipeline_config.yaml` — edit `target_model` / `attacker_model` before each run.

```bash
# Live run (uses config as-is)
python -m execution.deepteam_run --config execution/pipeline_config.yaml

# Dry run — builds prompts, no API calls to target
python -m execution.deepteam_run --config execution/pipeline_config.yaml --dry-run

# Narrow to one subdomain and fewer variants
python -m execution.deepteam_run --config execution/pipeline_config.yaml \
  --subdomain 3a_investment_advice --variants-per-seed 2

# Library-faithful mode (no attacker LLM — deterministic enhancers only)
python -m execution.deepteam_run --config execution/pipeline_config.yaml \
  --mode library-faithful --no-llm-enhancers
```

### Run the judge (score unjudged results)
```bash
# Claude judge (default)
python -m evaluation.eval_runner --judge claude --model claude-sonnet-4-6 --concurrency 2

# GPT-4o judge
python -m evaluation.eval_runner --judge gpt4o --model gpt-4o --concurrency 2

# Dry run (no API calls — smoke test)
python -m evaluation.eval_runner --dry-run
```

### Launch the dashboard
```bash
streamlit run dashboard/app.py
```

### Model IDs for config
| Role     | Model options |
|----------|--------------|
| Target   | `gpt-4o-mini`, `gpt-4o`, `claude-sonnet-4-6`, `claude-haiku-4-5`, `gemini-2.5-flash` |
| Attacker | `claude-sonnet-4-6`, `gpt-4o`, `gpt-4o-mini` |
| Judge    | `claude-sonnet-4-6`, `claude-haiku-4-5`, `gpt-4o`, `gpt-4o-mini` |
