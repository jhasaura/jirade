"""dum.yaml editor — apply governance grants to databricks_user_management.

The Permission Advisor decides `table → allowed_divisions`. The *applied* form
of that access lives in
`infra/deployments/databricks_user_management/dum.yaml`, where each
`group-division-*` block lists `catalog.schema.table: read` grants that
terraform turns into Unity Catalog grants for that division's Okta group.

This module writes those grants into dum.yaml for **high-confidence** decisions
only (deterministic mv-inherit + high-confidence LLM). Everything else is left
for a human. Edits are made with ruamel round-trip so the file's comments and
YAML anchors survive and the diff is minimal (added lines only).
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from typing import Any

from ruamel.yaml import YAML

from .permission_advisor import CORE_DIVISION, AdvisorDecision

# Path to the applied-access source of truth in algolia/data.
DUM_PATH = "infra/deployments/databricks_user_management/dum.yaml"

# Only these top-level blocks are per-division grant targets. The broad shared
# anchor blocks (many divisions under one `groups:`) are deliberately NOT
# touched — adding a table there would grant it far too widely.
DIVISION_BLOCK_PREFIX = "group-division-"

# The shared "core" block. It is NOT a group-division-* block (its Okta group is
# the all-employees group), so it's identified by this exact key and mapped to
# the Core division. domain=Core tables are granted here.
CORE_BLOCK_KEY = "group-analytics-core-tables"

# How a division name appears inside a block's `groups:` list.
_DIVISION_LABEL_PREFIXES = ("Okta Push - Division - ", "Push - Division - ")

READ_PRIVILEGE = "read"


@dataclass
class DivisionDrift:
    """Alignment between governance divisions and dum.yaml division blocks."""

    # Divisions the governance model can emit that have NO group-division-*
    # block in dum.yaml — grants to them can never be applied (the real problem).
    missing_in_dum: list[str] = field(default_factory=list)
    # dum.yaml division blocks no capability references — informational only.
    unused_dum_blocks: list[str] = field(default_factory=list)

    @property
    def has_drift(self) -> bool:
        """Drift that matters: governance names that can't resolve to a block."""
        return bool(self.missing_in_dum)


@dataclass
class DumApplyResult:
    """What apply_grants did (and chose not to do)."""

    applied: list[tuple[str, str, str]] = field(default_factory=list)          # (division, block, table)
    already_present: list[tuple[str, str, str]] = field(default_factory=list)  # (division, block, table)
    unmatched_divisions: list[tuple[str, str]] = field(default_factory=list)   # (division, table)
    skipped_low_confidence: list[str] = field(default_factory=list)            # table ids not written

    @property
    def changed(self) -> bool:
        return bool(self.applied)


def _yaml() -> YAML:
    y = YAML()
    y.preserve_quotes = True
    y.width = 4096  # never line-wrap our long table identifiers
    # Match dum.yaml's block style (dash indented under the key) so a round-trip
    # touches only the lines we add. ruamel does NOT auto-detect this — without it
    # the default (sequence=2, offset=0) re-indents every list and the whole file
    # shows as changed.
    y.indent(mapping=2, sequence=4, offset=2)
    return y


def load_dum(text: str) -> Any:
    """Round-trip-load dum.yaml (preserving comments/anchors)."""
    return _yaml().load(text)


def dump_dum(dum: Any) -> str:
    """Serialize a round-tripped dum document back to text."""
    buf = io.StringIO()
    _yaml().dump(dum, buf)
    return buf.getvalue()


def resolve_division_groups(dum: Any) -> dict[str, str]:
    """Map division display-name → `group-division-*` block key.

    Built by reading each per-division block's `groups:` label(s) and stripping
    the known "… Division - " prefix. Broad shared/anchor blocks are ignored.
    """
    out: dict[str, str] = {}
    for key, block in (dum or {}).items():
        if not (isinstance(key, str) and key.startswith(DIVISION_BLOCK_PREFIX)):
            continue
        if not isinstance(block, dict):
            continue
        for label in block.get("groups") or []:
            name = _division_name(str(label))
            if name and name not in out:
                out[name] = key

    # The core block is identified by its key, not a per-division Okta label:
    # its `groups:` is the all-employees group (core tables = readable by all),
    # so it never resolves via the "… Division - " label above. Register it
    # explicitly so domain=Core grants route to it.
    if isinstance((dum or {}).get(CORE_BLOCK_KEY), dict):
        out.setdefault(CORE_DIVISION, CORE_BLOCK_KEY)
    return out


def _division_name(label: str) -> str:
    for prefix in _DIVISION_LABEL_PREFIXES:
        if label.startswith(prefix):
            return label[len(prefix):].strip()
    return ""


def build_grant_index(dum: Any) -> dict[str, set[str]]:
    """Map each granted securable → the set of divisions that can read it.

    Inverts the grant blocks resolved by `resolve_division_groups` — the
    per-division RBAC blocks (`group-division-*`) plus the shared core block —
    into `table_id → {divisions}`. This is the source of truth for "has this
    table already been permissioned, and to whom?" The broad shared/anchor
    blocks (all-employees, hex-users, …) are deliberately ignored, since access
    granted there is the legacy wide model, not a per-division decision.
    """
    block_to_divisions: dict[str, list[str]] = {}
    for division, block_key in resolve_division_groups(dum).items():
        block_to_divisions.setdefault(block_key, []).append(division)

    index: dict[str, set[str]] = {}
    for block_key, divisions in block_to_divisions.items():
        block = dum.get(block_key)
        if not isinstance(block, dict):
            continue
        for entry in (block.get("tables") or []):
            table_id = _entry_key(entry)
            index.setdefault(table_id, set()).update(divisions)
    return index


def build_core_tables(dum: Any) -> set[str]:
    """Return the securables granted under the core block (CORE_BLOCK_KEY).

    These are the shared/universal tables (dbt domain=Core). mv inheritance skips
    refs in this set so a metric view doesn't pick up a core dimension's grants.
    """
    core_block_key = resolve_division_groups(dum).get(CORE_DIVISION)
    if not core_block_key:
        return set()
    block = dum.get(core_block_key)
    if not isinstance(block, dict):
        return set()
    return {_entry_key(entry) for entry in (block.get("tables") or [])}


def detect_division_drift(proposed_divisions: list[str], dum: Any) -> DivisionDrift:
    """Compare the divisions the classifier proposed against dum.yaml's blocks.

    Args:
        proposed_divisions: every division the advisor emitted this run (union of
            all decisions' allowed_divisions).
        dum: a loaded dum.yaml document.

    Returns:
        DivisionDrift — `missing_in_dum` is the actionable set (proposed, but
        there's no group-division-* block to grant them, so they'd be silently
        skipped at apply time — advisory-only until a block exists).
    """
    dum_divisions = set(resolve_division_groups(dum))
    proposed = set(proposed_divisions)
    return DivisionDrift(
        missing_in_dum=sorted(proposed - dum_divisions),
        unused_dum_blocks=sorted(dum_divisions - proposed),
    )


def render_drift_note(drift: DivisionDrift) -> str:
    """Markdown warning for the PR comment — empty when there's no actionable drift."""
    if not drift.has_drift:
        return ""
    return (
        "#### ⚠ Not yet grantable\n"
        "The classifier proposed these divisions, but they have **no "
        "`group-division-*` block** in `dum.yaml`, so grants to them can't be "
        "applied yet (they're advisory-only until a block exists):\n"
        + ", ".join(f"`{d}`" for d in drift.missing_in_dum)
        + "\n\n_Add a per-division RBAC block in `dum.yaml`, or reconcile the "
        "division label in the capability→divisions map._"
    )


def is_high_confidence(decision: AdvisorDecision) -> bool:
    """Whether a decision is trustworthy enough to write to dum.yaml.

    domain=Core is always high (deterministic). mv-inheritance and LLM proposals
    qualify only when their confidence is 'high' — mv-inheritance is downgraded to
    'low' when the core block is absent (universal dims can't be excluded), so it
    stays advisory rather than auto-committing incidental grants. already-granted
    (existing) and llm_failed never qualify.
    """
    if decision.status == "core_domain":
        return True
    if decision.status in ("inherits_from_ref", "llm_proposed") and (
        decision.confidence or ""
    ).lower() == "high":
        return True
    return False


def table_identifier(decision: AdvisorDecision) -> str:
    """The Unity Catalog identifier a grant targets: catalog.schema.table."""
    ev = decision.evidence
    return f"{ev.catalog}.{ev.schema}.{ev.table_name}"


def apply_grants(dum: Any, decisions: list[AdvisorDecision]) -> DumApplyResult:
    """Mutate `dum` in place, adding read grants for high-confidence decisions.

    For each high-confidence decision, add `catalog.schema.table: read` under
    every resolvable allowed-division block. Low-confidence / failed decisions
    are recorded in skipped_low_confidence and left untouched. Divisions with no
    matching block are recorded in unmatched_divisions (never invented).
    """
    resolver = resolve_division_groups(dum)
    result = DumApplyResult()

    for d in decisions:
        table_id = table_identifier(d)
        if not is_high_confidence(d):
            # Only note ones that actually proposed access but weren't confident.
            if d.status in ("llm_proposed", "llm_failed"):
                result.skipped_low_confidence.append(table_id)
            continue
        for division in d.allowed_divisions:
            block_key = resolver.get(division)
            if block_key is None:
                result.unmatched_divisions.append((division, table_id))
                continue
            if _add_table_grant(dum[block_key], table_id):
                result.applied.append((division, block_key, table_id))
            else:
                result.already_present.append((division, block_key, table_id))

    return result


def _add_table_grant(block: Any, table_id: str) -> bool:
    """Insert `- table_id: read` into a block's `tables:` list, sorted.

    Returns True if a grant was added, False if it was already present. Creates
    the `tables:` key if the block doesn't have one.
    """
    tables = block.get("tables")
    if tables is None:
        tables = []
        block["tables"] = tables

    for entry in tables:
        if _entry_key(entry) == table_id:
            return False

    idx = len(tables)
    for i, entry in enumerate(tables):
        if _entry_key(entry) > table_id:
            idx = i
            break
    tables.insert(idx, {table_id: READ_PRIVILEGE})
    return True


def _entry_key(entry: Any) -> str:
    """The single securable identifier a `- ident: read` entry grants on."""
    if isinstance(entry, dict) and entry:
        return str(next(iter(entry.keys())))
    return str(entry)


def render_dum_summary(result: DumApplyResult, dum_path: str, will_commit: bool) -> str:
    """Markdown block describing what apply_grants did — embedded in the PR
    comment so it's covered by the idempotency hash. Empty when nothing to say.
    """
    if not (
        result.applied
        or result.unmatched_divisions
        or result.skipped_low_confidence
    ):
        return ""

    lines = ["#### 🔐 Access grants (`dum.yaml`)"]
    if result.applied:
        verb = "Committed to" if will_commit else "Would grant in"
        lines.append(f"{verb} `{dum_path}` (high-confidence, matching RBAC block):")
        by_table: dict[str, list[str]] = {}
        for division, _block, table in result.applied:
            by_table.setdefault(table, []).append(division)
        for table, divs in sorted(by_table.items()):
            lines.append(f"- `{table}` → {', '.join(sorted(divs))}")
        if not will_commit:
            lines.append("")
            lines.append("_Dry-run — not committed. Re-run with `apply_dum_edit=true` to write._")

    if result.unmatched_divisions:
        unmatched = sorted({d for d, _t in result.unmatched_divisions})
        lines.append("")
        lines.append(
            "_No `group-division-*` block for: "
            + ", ".join(f"`{d}`" for d in unmatched)
            + " — add a block or fix the division name._"
        )

    if result.skipped_low_confidence:
        skipped = sorted(set(result.skipped_low_confidence))
        lines.append("")
        lines.append(
            "_Not granted (low confidence / needs review): "
            + ", ".join(f"`{t}`" for t in skipped)
            + "._"
        )

    return "\n".join(lines)
