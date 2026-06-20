"""Shared structured-state vocabulary for ifolder-sync's read-only observers.

The engine's decide phase classifies each path into a `SyncRow`; `doctor`
(`Syncer.plan()`) returns a `Plan` of them, and the live dashboard (feature 04) streams
`SyncEvent`s into an in-memory surface that flushes the same `SyncRow` shape to
`status.json`. Defining the vocabulary once, here, keeps the two consumers from drifting.
This module is pure data and (de)serialization — no engine logic, no IO.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any, Literal, Optional

if TYPE_CHECKING:
    # Annotation-only import. `Op` is a str-Enum in syncer.py, which imports THIS module
    # back (Syncer._classify_plan builds SyncRows), so a runtime `from .syncer import Op`
    # here would be a circular import. `from __future__ import annotations` defers the
    # annotation, so the type stays precise for mypy while runtime imports stay acyclic.
    # Op is a str subclass, so a SyncRow.op carries its wire value ("upload") and
    # serializes as that string.
    from .syncer import Op

# status.json / doctor --json envelope version. A breaking change to the row or envelope
# shape bumps this, so a stale reader fails loudly instead of silently misparsing.
SCHEMA = 1

# Every state a path can be reported in. The first block is live apply states (the
# dashboard, feature 04); the second is decide-only states (doctor, feature 05).
State = Literal[
    "uploading",
    "downloading",
    "deleting-local",
    "deleting-remote",
    "done",
    "conflict",
    "deferred-settle",
    "pending-unreadable",
    "error",
    "collision",
    "kind-conflict",
    "oversize",
    "orphan-baseline",
    "planned-upload",
    "planned-download",
    "planned-delete",
    "would-conflict",
    "drift",
]

Kind = Literal["file", "dir"]
Level = Literal["info", "attention", "error"]


@dataclass(frozen=True)
class SyncEvent:
    """One per-path transition emitted by the engine (feature 04). Frozen: an event is an
    immutable fact handed to the observer surface, never mutated in place."""

    ts: float
    pass_id: int
    relpath: str
    op: "Op"
    state: State
    kind: Kind
    bytes: Optional[int] = None
    passes_stuck: Optional[int] = None
    reason: Optional[str] = None
    level: Level = "info"


@dataclass
class SyncRow:
    """The current view of one path: what the engine would do (or is doing) with it, plus
    why and for how long. The shared serialization unit of both `doctor --json` and the
    dashboard's `status.json` (the envelope-parity contract)."""

    relpath: str
    state: State
    # The engine Op that produced this row (doctor decide rows). None for rows folded from a
    # persisted registry (the dashboard's settle/unreadable attention rows have no decided op).
    op: Optional["Op"] = None
    kind: Kind = "file"
    passes_stuck: Optional[int] = None
    reason: Optional[str] = None
    bytes: Optional[int] = None
    last_seen_pass: int = 0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Op is a str-Enum; str() pins it to the wire value ("upload") regardless of the
        # Enum __str__ quirk across Python versions, so a reader gets a plain string (or None).
        d["op"] = str(self.op) if self.op is not None else None
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SyncRow":
        """Rebuild from a serialized dict, ignoring unknown keys so a newer producer's
        extra fields never crash an older reader (the schema version gates real breaks)."""
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class Plan:
    """The result of a decide-only pass (`Syncer.plan()`): the classified rows plus
    pass-level banners. Read-only — `doctor` renders it; it is never applied."""

    rows: list[SyncRow] = field(default_factory=list)
    suppressed_deletes: int = 0
    # Paths the decide phase could not reconcile this pass (live case-collisions +
    # kind-conflicts): surfaced as a count so `doctor` can warn without re-deriving them.
    errors: int = 0

    @property
    def orphans(self) -> list[SyncRow]:
        """Baseline rows absent from BOTH sides — the headline inconsistency class (the
        2026-06-20 ghost). Internally these are the engine's DROP_BASELINE decisions."""
        return [r for r in self.rows if r.state == "orphan-baseline"]

    @property
    def is_clean(self) -> bool:
        return not self.rows and not self.suppressed_deletes and not self.errors


def make_envelope(rows: list[SyncRow], **extra: Any) -> dict[str, Any]:
    """Wrap rows in the versioned envelope shared by `doctor --json` and `status.json`.
    `extra` carries consumer-specific fields (doctor: suppressed_deletes/decide_errors;
    dashboard: pid/last_sync/...). The `schema` + `rows` shape is the parity contract."""
    env: dict[str, Any] = {"schema": SCHEMA, "rows": [r.to_dict() for r in rows]}
    env.update(extra)
    return env
