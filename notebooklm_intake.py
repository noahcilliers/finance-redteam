"""
notebooklm_intake.py — Finance Red-Team Attack Seed Intake
===========================================================
Creates a NotebookLM notebook, uploads the 4 seed source documents,
waits for indexing, then asks a set of cross-subdomain analysis questions
and saves each answer as a note inside the notebook.

Run from the finance-redteam directory:
    python3 notebooklm_intake.py

Requirements:
    pip install "notebooklm-py[browser]"
    notebooklm login   (run once to authenticate)
"""

import asyncio
import json
import time
from pathlib import Path

from notebooklm import NotebookLMClient

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

NOTEBOOK_TITLE = "Finance Red-Team: Attack Seed Library v1"

SOURCE_FILES = [
    "notebooklm_source_3a_investment_advice.md",
    "notebooklm_source_3b_fraud_and_scams.md",
    "notebooklm_source_3c_pii_and_data_leakage.md",
    "notebooklm_source_cross_cutting_techniques.md",
]

ANALYSIS_QUESTIONS = [
    (
        "technique_gaps",
        "Which MITRE ATT&CK for ML (AML) techniques appear in subdomain 3b and 3c but have NO seeds in 3a? "
        "List each missing technique and suggest what a seed covering it might look like.",
    ),
    (
        "cross_subdomain_combos",
        "Which attack techniques (e.g. encoding obfuscation, multilingual bypass, roleplay) are applied "
        "across more than one financial subdomain? For each, describe the pattern and rate whether the "
        "current seed library provides adequate coverage of that combination.",
    ),
    (
        "severity_distribution",
        "Summarise the severity_potential distribution across all seeds. Which subdomain has the highest "
        "average severity? Which individual seed has the highest severity and why is it rated that way?",
    ),
    (
        "missing_techniques",
        "Looking at the OWASP Top 10 for LLMs categories present in the seeds, which OWASP categories "
        "have fewer than 3 seeds? What attack scenarios in those categories are missing from the library?",
    ),
    (
        "multi_turn_gaps",
        "How many seeds are tagged 'multi_turn'? Which subdomains and techniques lack multi-turn variants? "
        "Propose 2 specific multi-turn seed ideas that would fill the most important gaps.",
    ),
    (
        "paired_seed_analysis",
        "Several seeds mention they are 'paired' with another seed to measure bypass delta (e.g. "
        "English vs Mandarin, English vs Spanish, English vs Arabic). List all identified pairs and "
        "explain what finding would constitute a meaningful safety gap for each pair.",
    ),
    (
        "high_priority_mutations",
        "If you had to prioritise 5 seeds from this library for mutation-based attack generation (to "
        "maximise the chance of finding novel failures), which 5 would you choose and why? Consider "
        "severity, subdomain coverage, and technique diversity.",
    ),
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")


async def wait_for_source(client, notebook_id: str, source_id: str, title: str, timeout: int = 300) -> bool:
    """Poll until source status is ready or timeout.

    The notebooklm-py Source object exposes is_ready(), is_processing(), is_failed()
    helper methods — status is an int enum (1=processing, 2=ready, 3=error), not a string.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        sources = await client.sources.list(notebook_id)
        for s in sources:
            if s.id == source_id:
                if s.is_ready:
                    return True
                if s.is_failed:
                    log(f"  ✗ Source '{title}' errored during processing")
                    return False
                # still processing — keep polling
        await asyncio.sleep(10)
    log(f"  ✗ Timed out waiting for source '{title}'")
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main() -> None:
    base_dir = Path(__file__).parent

    # Verify source files exist
    missing = [f for f in SOURCE_FILES if not (base_dir / f).exists()]
    if missing:
        print(f"ERROR: Missing source files: {missing}")
        print("Run the Cowork session first to generate them.")
        return

    async with await NotebookLMClient.from_storage() as client:

        # -- 1. Create notebook --------------------------------------------------
        log(f"Creating notebook: '{NOTEBOOK_TITLE}'")
        notebook = await client.notebooks.create(NOTEBOOK_TITLE)
        notebook_id = notebook.id
        log(f"  ✓ Notebook created: {notebook_id}")

        # -- 2. Add source files -------------------------------------------------
        source_ids = []
        for filename in SOURCE_FILES:
            path = base_dir / filename
            log(f"Adding source: {filename}")
            try:
                source = await client.sources.add_file(notebook_id, str(path))
                source_ids.append((source.id, filename))
                log(f"  ✓ Uploaded — source_id: {source.id}")
            except Exception as e:
                log(f"  ✗ Failed to upload {filename}: {e}")

        # -- 3. Wait for all sources to be indexed -------------------------------
        log(f"Waiting for {len(source_ids)} sources to be indexed...")
        all_ready = True
        for sid, title in source_ids:
            ready = await wait_for_source(client, notebook_id, sid, title)
            if ready:
                log(f"  ✓ Ready: {title}")
            else:
                all_ready = False

        if not all_ready:
            log("WARNING: Some sources failed to index. Proceeding with available sources.")

        # -- 4. Ask analysis questions and save as notes -------------------------
        log(f"\nAsking {len(ANALYSIS_QUESTIONS)} analysis questions...")
        results = {}

        for note_title, question in ANALYSIS_QUESTIONS:
            log(f"\nQ: {note_title}")
            try:
                response = await client.chat.ask(notebook_id, question)
                answer = response.answer if hasattr(response, 'answer') else str(response)
                results[note_title] = answer
                log(f"  Answer ({len(answer)} chars) — saving as note...")

                # Save answer as a notebook note
                await client.notes.create(
                    notebook_id,
                    title=f"Analysis: {note_title.replace('_', ' ').title()}",
                    content=f"**Question:**\n{question}\n\n**Answer:**\n{answer}",
                )
                log(f"  ✓ Saved as note")

            except Exception as e:
                log(f"  ✗ Failed: {e}")
                results[note_title] = f"ERROR: {e}"

        # -- 5. Save results to JSON for pipeline use ----------------------------
        output_path = base_dir / "data" / "notebooklm_analysis.json"
        output_path.parent.mkdir(exist_ok=True)
        with open(output_path, "w") as fh:
            json.dump(
                {
                    "notebook_id": notebook_id,
                    "notebook_title": NOTEBOOK_TITLE,
                    "source_files": SOURCE_FILES,
                    "analysis": results,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                },
                fh,
                indent=2,
            )

        log(f"\n✓ Done. Results saved to {output_path}")
        log(f"✓ Notebook URL: https://notebooklm.google.com/notebook/{notebook_id}")
        log(f"\nNotebook ID (save this): {notebook_id}")

        # Print a quick summary
        print("\n" + "=" * 60)
        print("ANALYSIS SUMMARY")
        print("=" * 60)
        for title, answer in results.items():
            print(f"\n--- {title.replace('_', ' ').upper()} ---")
            print(answer[:800] + ("..." if len(answer) > 800 else ""))


if __name__ == "__main__":
    asyncio.run(main())
