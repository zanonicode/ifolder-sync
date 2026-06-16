"""Invariant Guardian entrypoint: diff -> verdict -> idempotent PR comment.

Wires the Guardian together: load the public safety contract
(`invariants.yaml`), build the system prompt, scope the PR diff to
`ifolder_sync/`, ask the review model for a structured `Verdict`, render it as
markdown, and UPSERT a single advisory comment on the pull request (found by a
stable HTML marker, edited if present, created otherwise).

This reviewer is ADVISORY by construction (DESIGN_03 Decisions 2/6): it only
comments and ALWAYS exits 0. Any failure — missing env, transport error, an
unparseable verdict, a GitHub API hiccup — degrades to a best-effort
"AI review unavailable this run" comment and still returns 0, so a Guardian
outage can never block a merge.

Run (in CI, after `google-github-actions/auth@v3` writes ADC):
    GOOGLE_CLOUD_PROJECT=<id> GOOGLE_CLOUD_LOCATION=us-central1 \
    PR_NUMBER=<n> GITHUB_REPOSITORY=<owner/repo> GITHUB_TOKEN=<token> \
    python -m scripts.ai_guardian.review
"""

from __future__ import annotations

import os
import sys
from typing import Protocol

from scripts.ai_guardian.diff import changed_diff
from scripts.ai_guardian.llm import Verdict, build_model
from scripts.ai_guardian.prompt import build_system_prompt, fence_diff, load_invariants

COMMENT_MARKER = "<!-- ifolder-ai-guardian -->"

_UNAVAILABLE = "AI review unavailable this run."


class _Comment(Protocol):
    body: str

    def edit(self, body: str) -> object: ...


class _PullRequest(Protocol):
    def get_issue_comments(self) -> object: ...

    def create_issue_comment(self, body: str) -> object: ...


def _status_emoji(status: str) -> str:
    return {"PASS": "✅", "FAIL": "🚨", "NOT_TOUCHED": "➖"}.get(status, "❓")


def _render_markdown(verdict: Verdict) -> str:
    failures = [f for f in verdict.findings if f.status == "FAIL"]
    headline = (
        f"⚠️ {len(failures)} invariant concern(s) flagged"
        if failures
        else "✅ No invariant weakening detected"
    )

    lines = [
        COMMENT_MARKER,
        "## Invariant Guardian (advisory)",
        "",
        headline,
        "",
        f"{verdict.summary.strip()}" if verdict.summary.strip() else "_(no summary)_",
        "",
    ]

    if verdict.findings:
        lines += [
            "| Invariant | Status | Location | Evidence |",
            "| --- | --- | --- | --- |",
        ]
        for f in verdict.findings:
            location = f"`{f.path}`"
            if f.line is not None:
                location += f":{f.line}"
            evidence = f.evidence.strip().replace("\n", " ").replace("|", "\\|")
            lines.append(
                f"| `{f.invariant_id}` | {_status_emoji(f.status)} {f.status} "
                f"| {location} | {evidence} |"
            )
    else:
        lines.append("_The model returned no findings._")

    lines += [
        "",
        "---",
        "_Advisory only — never a merge gate. Re-runs update this comment in place._",
    ]
    return "\n".join(lines)


def _render_message(message: str) -> str:
    return "\n".join(
        [
            COMMENT_MARKER,
            "## Invariant Guardian (advisory)",
            "",
            message,
            "",
            "---",
            "_Advisory only — never a merge gate._",
        ]
    )


def _upsert_comment(pr: _PullRequest, body: str) -> None:
    """Find the Guardian comment by marker and edit it; otherwise create one.

    Iterating issue comments can raise on a bot-authored comment with some
    PyGithub versions, so the find step is best-effort: on any error we fall
    through to creating a fresh comment rather than aborting the upsert.
    """
    existing: _Comment | None = None
    try:
        for comment in pr.get_issue_comments():  # type: ignore[attr-defined]
            if COMMENT_MARKER in (comment.body or ""):
                existing = comment
                break
    except Exception:  # noqa: BLE001  (degrade to create; never abort the upsert)
        existing = None

    if existing is not None:
        existing.edit(body)
    else:
        pr.create_issue_comment(body)


def _get_pull_request() -> _PullRequest:
    """Resolve the PR object from env via PyGithub (lazy-imported)."""
    from github import Auth, Github

    token = os.environ["GITHUB_TOKEN"]
    repo_name = os.environ["GITHUB_REPOSITORY"]
    pr_number = int(os.environ["PR_NUMBER"])

    gh = Github(auth=Auth.Token(token))
    return gh.get_repo(repo_name).get_pull(pr_number)


def main() -> int:
    try:
        invariants = load_invariants()
        system = build_system_prompt(invariants)

        diff = changed_diff()
        if diff is None:
            # Nothing in scope to review (a docs-only PR, or a diff over the cap). Stay
            # silent: an advisory bot must not comment on every out-of-scope PR.
            print("guardian: no in-scope diff (empty or over MAX_DIFF_BYTES); skipping.")
            return 0

        model = build_model()
        verdict = model.review(system, fence_diff(diff))
        body = _render_markdown(verdict)

        _upsert_comment(_get_pull_request(), body)
        print(f"guardian: posted verdict with {len(verdict.findings)} finding(s).")
        return 0
    except Exception as exc:  # noqa: BLE001  (advisory: any failure -> unavailable comment, exit 0)
        print(f"guardian: review failed ({exc!r}); posting unavailable notice.", file=sys.stderr)
        try:
            _upsert_comment(_get_pull_request(), _render_message(_UNAVAILABLE))
        except Exception as post_exc:  # noqa: BLE001  (even the notice is best-effort)
            print(f"guardian: could not post unavailable notice ({post_exc!r}).", file=sys.stderr)
        return 0


if __name__ == "__main__":
    sys.exit(main())
