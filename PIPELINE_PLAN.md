# Finance Red-Team Pipeline — Build Summary & Next Steps

## What's built

The execution layer is complete and wired end-to-end.

```
finance-redteam/
├── attacks/library/          # 46 YAML seed files (3a, 3b, 3c + jailbreak/injection/encoding)
├── generation/
│   ├── seed_loader.py        # loads + filters YAML seeds
│   └── mutation_prompt_builder.py  # builds attacker LLM prompts from seeds
├── execution/
│   ├── connectors/           # async connectors: OpenAI, Anthropic, Gemini, Ollama
│   ├── rate_limiter.py       # semaphore + RPS cap
│   ├── attacker.py           # calls attacker LLM, parses JSON variant array
│   ├── pipeline.py           # PipelineRunner — full async orchestration
│   ├── pipeline_config.py    # PipelineConfig dataclass
│   ├── pipeline_config.yaml  # active config (gpt-4o attacker → claude-sonnet target)
│   └── run.py                # CLI: python -m execution.run --config ...
├── data/
│   ├── models.py             # AttackResult, AttackType, AttackTechnique (pydantic)
│   └── database.py           # SQLite read/write
└── evaluation/
    └── results_analyzer.py   # rule-based feedback context generator
```

### Current flow

1. Seed YAML is loaded and filtered by `SeedLoader`
2. `MutationPromptBuilder` constructs a structured prompt describing the seed and requesting N variants
3. Prompt is sent to the attacker LLM (currently GPT-4o)
4. Attacker returns a JSON array of variant attack prompts
5. Each variant is sent to the target model (currently Claude Sonnet)
6. Responses are stored in SQLite (`data/results.db`) and a per-run JSONL file

---

## Key issue discovered: attacker model refusal

When Claude Sonnet was used as the attacker model, it refused to generate optimized attack variants — even under an explicit red-team research framing. This is expected behaviour from a safety-trained model being asked to produce jailbreak content.

The workaround is GPT-4o as the attacker, which is more permissive for research contexts. This works but is not the right long-term architecture.

---

## Next phase: DeepTeam integration

The architecture always called for DeepTeam for dynamic attack generation. The `MutationPromptBuilder` approach is a valid design but the attacker-refusal problem makes it fragile when Claude-family models are used on the attacker side. DeepTeam is purpose-built for red-teaming and avoids this problem entirely.

### What DeepTeam replaces

DeepTeam takes over the attack generation step — the part currently handled by `MutationPromptBuilder` + `AttackerClient`. Everything downstream (connectors, database, evaluation) stays as-is.

### Integration pattern

DeepTeam's `RedTeamer` accepts a callable target function, which is where the existing connector layer plugs in:

```python
from deepteam import RedTeamer

def target(input: str) -> str:
    # existing AsyncConnector wrapped in asyncio.run()
    return claude_sonnet_connector.chat(input)

red_teamer = RedTeamer(target_model=target)
```

The YAML seed library maps to DeepTeam's `Vulnerability` inputs, so the existing 46 seeds remain the source of truth — DeepTeam just handles the synthesis of variants from them rather than delegating that to a raw LLM call.

### What we keep

Everything downstream of the attack generation step is preserved and remains custom:

- `execution/connectors/` — target model connectors (OpenAI, Anthropic, Gemini, Ollama)
- `data/models.py` — `AttackResult`, `AttackType`, `AttackTechnique`
- `data/database.py` — SQLite persistence
- `evaluation/results_analyzer.py` — rule-based feedback context for the mutation loop

### Custom eval and judge

DeepTeam's framework is explicitly designed to support custom scorers. Rather than using DeepTeam's default LLM-as-judge, we will plug in a `FinancialSafetyMetric` that scores responses against the three financial subdomains (3a investment advice, 3b fraud/scams, 3c PII leakage):

```python
from deepteam.metrics import BaseMetric

class FinancialSafetyMetric(BaseMetric):
    def score(self, input: str, actual_output: str) -> float:
        # domain-aware judge call
        # returns 0.0–1.0 severity score
        ...
```

DeepTeam returns `(prompt, response)` pairs — at that point we own the results and pipe them into `AttackResult` objects, store them in SQLite, and run them through `ResultsAnalyzer` for the feedback loop. The eval and judge layer is not being built yet, but the DeepTeam integration is designed from the start to leave that door open.

### Target integration shape

```
DeepTeam RedTeamer
   ├── synthesizes attack variants from YAML seeds (no refusal issues)
   ├── calls target via our connector layer
   └── returns (prompt, response) pairs
          ↓
   FinancialSafetyMetric  ← custom judge (future)
          ↓
   AttackResult → results.db → ResultsAnalyzer → feedback loop
```

### Steps for next session

1. Map YAML seed schema to DeepTeam `Vulnerability` + `VulnerabilityType`
2. Replace `AttackerClient` + `MutationPromptBuilder` with `RedTeamer`
3. Wrap existing async connectors as synchronous callables for DeepTeam's target interface
4. Pipe DeepTeam output into existing `AttackResult` model and `database.py`
5. Verify end-to-end with the `prompt_injection/direct_override` seeds
6. (Later) Implement `FinancialSafetyMetric` custom judge
