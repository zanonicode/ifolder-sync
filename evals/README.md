# Invariant Guardian — evaluation harness

The Guardian (`scripts/ai_guardian/`) is an LLM reviewer, so we treat **the reviewer
itself as the system-under-test**: does it catch diffs that weaken ifolder-sync's
data-loss invariants (recall) without crying wolf on benign diffs (false positives)?

- **SUT**: Vertex Gemini 2.5 Flash (keyless WIF) — the same model the Guardian runs.
- **Judge**: Anthropic Sonnet via `ANTHROPIC_API_KEY` — a *different* model family
  (anti-self-grading; DESIGN Decision 4/8).
- **Corpus** (`fixtures/<id>/`): each fixture is a real `diff.patch` against `ifolder_sync/`
  plus `expected.json`. *Positives* weaken one invariant (expect that invariant `FAIL`);
  *negatives* are benign (expect no `FAIL`). Seeded small; grow it over time.

## Gates (CI: `.github/workflows/ai-eval.yml`)

1. **Fixture integrity** — `git apply --check` on every `diff.patch`. A patch that no longer
   applies (the code moved) fails loudly instead of silently rotting against stale context.
2. **Run-twice consistency** — the eval runs twice; any fixture whose FAIL-set differs
   between runs is a non-deterministic flip → fail (temperature=0 discipline).
3. **Recall ≥ 0.85 / false-positive ≤ 0.10** — `assert_consistent.py` compares each
   fixture's model verdict to its `expected.json`.

This gates the **reviewer's quality**, never a merge — no AI job is ever a required check.
The job is fork-safe (`pull_request`, same-repo only) and skips cleanly if the Vertex repo
vars or the `ANTHROPIC_API_KEY` secret are absent.

## Run locally

```bash
pip install -e ".[ai]"
npm install -g promptfoo@0.121.15
gcloud auth application-default login           # local ADC (CI uses keyless WIF)

# regenerate the system prompt from the live invariants (no drift):
python -c 'from scripts.ai_guardian.prompt import build_system_prompt, fence_diff, load_invariants; open("evals/prompts/guardian-system.txt","w").write(build_system_prompt(load_invariants())+"\n\n"+fence_diff("{{diff}}")+"\n")'

cd evals
export GOOGLE_CLOUD_PROJECT=<project-id> GOOGLE_CLOUD_LOCATION=us-central1 ANTHROPIC_API_KEY=sk-ant-...
promptfoo eval -c promptfooconfig.yaml -o /tmp/run1.json
promptfoo eval -c promptfooconfig.yaml -o /tmp/run2.json
python assert_consistent.py /tmp/run1.json /tmp/run2.json --fixtures fixtures

# offline logic check of the gate (no network/keys):
python assert_consistent.py --selftest
```

## Add a fixture

Generate the patch **mechanically** so it always applies cleanly:

```bash
# 1. edit ifolder_sync/... to (weaken | not weaken) an invariant, then capture + revert:
git diff -- ifolder_sync > evals/fixtures/<id>/diff.patch
git checkout -- ifolder_sync          # the patch IS the fixture, not a real change

# 2. write evals/fixtures/<id>/expected.json:
#    {"id": "<id>", "kind": "positive|negative", "expect_fail": ["INVARIANT_ID", ...]}

# 3. add a matching test block to promptfooconfig.yaml (vars.fixture + vars.diff + asserts)
```

`prompts/guardian-system.txt` is generated from `invariants.yaml` (gitignored); CI
regenerates it on every run so it never drifts from the contract the Guardian enforces.
