"""ReviewModel boundary + the Vertex Gemini implementation of the Invariant Guardian.

This mirrors the engine's `SyncClient` Protocol (ifolder_sync/syncer.py): the reviewer
binds to the `ReviewModel` interface, not the concrete `VertexGeminiModel`, so the glue
(diff -> verdict -> PR comment in review.py) and the unit tests bind to a verifiable
contract and a fake stands in for the real backend with no network. It is also the
P3/LiteLLM seam (DESIGN Decision 4): a second backend drops in behind `build_model`
unchanged.

Import discipline: `google-genai` is lazy-imported INSIDE `VertexGeminiModel` methods, so
importing this module needs only `pydantic`. The unit-test job installs no `google-genai`
(only the base + pydantic), so `Finding`, `Verdict`, `ReviewModel`, and `build_model`'s
error path must all be importable and testable without the SDK present.
"""

from __future__ import annotations

from typing import Protocol, cast, runtime_checkable

from pydantic import BaseModel


class Finding(BaseModel):
    """One invariant verdict. `status` is a machine enum ONLY ("PASS" | "FAIL" |
    "NOT_TOUCHED"); only that enum (plus the cited path:line) is ever read back from the
    untrusted model output — never free-form instructions."""

    invariant_id: str
    status: str
    path: str
    line: int | None = None
    evidence: str


class Verdict(BaseModel):
    """The full structured review: one `Finding` per invariant the model addressed, plus a
    short human summary. Used directly as the google-genai `response_schema`."""

    findings: list[Finding]
    summary: str


@runtime_checkable
class ReviewModel(Protocol):
    """The exact reviewer surface the Guardian glue depends on, declared at the consumer.

    review.py binds to this Protocol, not to `VertexGeminiModel`, so the production backend
    is swappable in one place (`build_model`, the P3 seam) and the unit tests substitute a
    fake with no network — the same discipline as the engine's `FakeICloud`. mypy checks
    structural conformance against both the real model and the test fake.
    """

    def review(self, system: str, data: str) -> Verdict: ...


class VertexGeminiModel:
    """Gemini-on-Vertex reviewer (keyless WIF). ADC is supplied by
    google-github-actions/auth@v3 via GOOGLE_APPLICATION_CREDENTIALS; no API key is read.

    `google-genai` is imported lazily inside the methods so this module imports with only
    pydantic available.
    """

    def __init__(self, model: str = "gemini-2.5-flash") -> None:
        import os

        from google import genai

        # Explicit Vertex args (avoids relying on GOOGLE_GENAI_USE_VERTEXAI). The SDK
        # prefers the Gemini Developer API over Vertex if any API-key env var is present,
        # so this job must NEVER set GEMINI_API_KEY (DESIGN Decision 5).
        self._client = genai.Client(
            vertexai=True,
            project=os.environ["GOOGLE_CLOUD_PROJECT"],
            location=os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1"),
        )
        self._model = model

    def review(self, system: str, data: str) -> Verdict:
        from google.genai import types

        resp = self._client.models.generate_content(
            model=self._model,
            contents=data,
            config=types.GenerateContentConfig(
                system_instruction=system,
                response_mime_type="application/json",
                response_schema=Verdict,  # the Pydantic CLASS, not an instance
                temperature=0,  # determinism discipline
                # google-genai accepts these category/threshold strings at runtime; its
                # type stubs declare enums, so the two args carry arg-type ignores
                # (DESIGN_03 Decision 5: string literals, not enums).
                safety_settings=[
                    types.SafetySetting(
                        category=cat,  # type: ignore[arg-type]
                        threshold="BLOCK_ONLY_HIGH",  # type: ignore[arg-type]
                    )
                    for cat in (
                        "HARM_CATEGORY_DANGEROUS_CONTENT",
                        "HARM_CATEGORY_HATE_SPEECH",
                    )
                ],
            ),
        )
        # `parsed` is None on schema-violating output: fail safe (advisory), never raise.
        if resp.parsed is None:
            return Verdict(findings=[], summary="model returned no parseable verdict")
        # `response_schema=Verdict` guarantees the parsed object IS a Verdict; the SDK's
        # broad `parsed` type (BaseModel | dict | Enum) is narrowed here for mypy.
        return cast(Verdict, resp.parsed)


def build_model(provider: str = "vertex") -> ReviewModel:
    """Factory / P3 seam. "vertex" -> the keyless Vertex Gemini reviewer; any other value
    raises (the LiteLLM/Anthropic backend lands here unchanged when an R1 trigger fires)."""
    if provider == "vertex":
        return VertexGeminiModel()
    raise ValueError(f"unknown provider {provider!r}")
