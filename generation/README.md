# generation/

Builds prompts for the attacker LLM. Takes seeds from the static library,
stacks the mutation techniques you configured, optionally layers in
patterns learned from past runs, and emits a single ready-to-send prompt
per seed.

## Files

| File | Purpose |
|---|---|
| `generate_config.example.yaml` | Template for per-run configuration. Copy to `generate_config.yaml` before each run. |
| `seed_loader.py` | Loads YAML files from `attacks/library/` and applies the config's filter block. |
| `mutation_prompt_builder.py` | Core class. Assembles the mutation prompt from seed + config + feedback context. |

## What you can control from the config

All of these are fields in `generate_config.yaml`:

- **which seeds to mutate** — `seed_filters` (by subdomain, attack type, tags, severity range, or exact ID list)
- **which mutations to apply** — `mutations` (stackable: rephrase, jailbreak_wrap, tone_shift, encoding_wrap, language_switch)
- **how many variants per seed** — `variants_per_seed`
- **your own instructions** — `custom_instructions` (appended verbatim to every mutation prompt)
- **which attacker LLM to use** — `attacker_model`
- **feedback loop on/off** — `feedback_loop.enabled`

## Quick dry run (no LLM calls — just see the prompts)

```python
from generation.mutation_prompt_builder import GenerationConfig, MutationPromptBuilder
from generation.seed_loader import SeedLoader

cfg    = GenerationConfig.from_yaml("generation/generate_config.example.yaml")
seeds  = SeedLoader().load(cfg.seed_filters)
builder = MutationPromptBuilder(cfg)

print(f"Loaded {len(seeds)} seeds matching the config filters.")
print(builder.build(seeds[0]))   # print the first mutation prompt
```

## Adding a new mutation technique

Add a function that takes a `GenerationConfig` and returns a string block,
then register it in `MUTATION_TEMPLATES` in `mutation_prompt_builder.py`.
Users can immediately reference the new name in their `mutations:` list.

## Feedback loop (Phase 7)

When `feedback_loop.enabled: true`, a `ResultsAnalyzer` (built separately
and passed in by the caller) produces a string summary of what has worked
and what has failed against the target model in recent runs. The builder
splices that summary into the mutation prompt so the attacker LLM can
learn from past results.

`ResultsAnalyzer` is intentionally NOT part of this module — the builder
is I/O-free and takes the pre-rendered context as a string argument. That
keeps the builder unit-testable and lets you swap rule-based vs. LLM-based
pattern extraction without touching the prompt assembly code.
