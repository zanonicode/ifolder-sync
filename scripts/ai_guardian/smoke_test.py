"""One-call Vertex AI reachability check for the Invariant Guardian (Phase 2).

Confirms that `gemini-2.5-flash` is reachable on Vertex AI through the keyless WIF
credentials before any Guardian/eval wiring is trusted (DESIGN_03 R3, Decision 5).
Application Default Credentials come from the environment — in CI these are written by
`google-github-actions/auth@v3` (GOOGLE_APPLICATION_CREDENTIALS); locally, from
`gcloud auth application-default login` or an impersonated session.

Run:
    GOOGLE_CLOUD_PROJECT=<project-id> python scripts/ai_guardian/smoke_test.py

Exits 0 on a successful generation, 1 on any failure with a clear message.
"""

from __future__ import annotations

import os
import sys

MODEL = "gemini-2.5-flash"
PROMPT = "reply with the single word: OK"


def main() -> int:
    # Never set GEMINI_API_KEY in this process: the SDK prefers the Gemini Developer API
    # over Vertex when any API-key env var is present, even with vertexai=True, which would
    # silently bypass the WIF path this check is meant to validate (DESIGN_03 Decision 5).
    if os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"):
        print(
            "FAIL: GEMINI_API_KEY/GOOGLE_API_KEY is set; it would override Vertex ADC. "
            "Unset it so this smoke test exercises the keyless WIF path.",
            file=sys.stderr,
        )
        return 1

    project = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project:
        print(
            "FAIL: GOOGLE_CLOUD_PROJECT is not set; cannot target a Vertex AI project.",
            file=sys.stderr,
        )
        return 1
    location = os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1")

    try:
        from google import genai
        from google.genai import types
    except ImportError as exc:
        print(
            f"FAIL: google-genai is not installed ({exc}); install the 'ai' extra: "
            'pip install -e ".[ai]"',
            file=sys.stderr,
        )
        return 1

    try:
        client = genai.Client(vertexai=True, project=project, location=location)
        resp = client.models.generate_content(
            model=MODEL,
            contents=PROMPT,
            config=types.GenerateContentConfig(temperature=0),
        )
    except Exception as exc:  # noqa: BLE001  (any auth/transport/quota error is a failed check)
        print(
            f"FAIL: Vertex call to {MODEL} in {project}/{location} raised {exc!r}",
            file=sys.stderr,
        )
        return 1

    # A blocked or empty candidate yields resp.text is None; treat it as unreachable.
    if resp is None or resp.text is None:
        print(
            f"FAIL: {MODEL} returned no text (response or response.text was None; "
            "likely a safety block or empty candidate).",
            file=sys.stderr,
        )
        return 1

    print(f"OK: {MODEL} reachable in {project}/{location}")
    print(f"model text: {resp.text.strip()!r}")

    usage = resp.usage_metadata
    if usage is None:
        print("warning: response carried no usage_metadata; cannot report token usage.")
    else:
        print(
            "token usage: "
            f"input={usage.prompt_token_count} "
            f"output={usage.candidates_token_count} "
            f"total={usage.total_token_count}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
