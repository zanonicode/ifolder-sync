"""Invariant Guardian: an advisory Vertex-Gemini reviewer.

Flags PR diffs that weaken the repo's data-loss invariants. Comment-only;
never blocks. Same-repo PRs only; keyless via Workload Identity Federation.
"""
