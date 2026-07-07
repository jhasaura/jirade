"""Tests for the dum.yaml editor (round-trip, division resolver, grant apply)."""

from pathlib import Path

from jirade.tools.permission_advisor import AdvisorDecision, TableEvidence
from jirade.tools.dum_editor import (
    apply_grants,
    detect_division_drift,
    dump_dum,
    is_high_confidence,
    load_dum,
    render_drift_note,
    resolve_division_groups,
    table_identifier,
)

FIXTURES = Path(__file__).parent / "fixtures"
DUM_TEXT = (FIXTURES / "dum.yaml").read_text()


def _decision(table, catalog, schema, divisions, status="llm_proposed", confidence="high"):
    return AdvisorDecision(
        evidence=TableEvidence(table_name=table, catalog=catalog, schema=schema, path="x.sql"),
        status=status,
        allowed_divisions=divisions,
        confidence=confidence,
    )


# ── round-trip fidelity ───────────────────────────────────────────────────────
class TestRoundTrip:
    def test_preserves_comments_and_anchors(self):
        out = dump_dum(load_dum(DUM_TEXT))
        assert "# databricks_user_management config" in out
        assert "# Divisions" in out
        assert "&okta_all_divisions" in out  # anchor survives
        assert "*okta_all_divisions" in out  # alias survives

    def test_unedited_dump_is_stable(self):
        once = dump_dum(load_dum(DUM_TEXT))
        twice = dump_dum(load_dum(once))
        assert once == twice

    def test_unedited_round_trip_is_byte_identical(self):
        # A no-edit round-trip must NOT reformat the file (e.g. re-indent block
        # sequences) — otherwise a grant commit shows the whole file as changed.
        assert dump_dum(load_dum(DUM_TEXT)) == DUM_TEXT

    def test_adding_one_grant_changes_only_one_line(self):
        from jirade.tools.permission_advisor import AdvisorDecision, TableEvidence
        from jirade.tools.dum_editor import apply_grants
        dum = load_dum(DUM_TEXT)
        apply_grants(dum, [AdvisorDecision(
            evidence=TableEvidence(
                table_name="dim_brand_new", catalog="analytics", schema="dimensional", path="x.sql",
            ),
            status="core_domain", allowed_divisions=["Core"], confidence="high",
        )])
        added = [l for l in dump_dum(dum).splitlines() if l not in DUM_TEXT.splitlines()]
        assert added == ["    - analytics.dimensional.dim_brand_new: read"]


# ── division resolver ─────────────────────────────────────────────────────────
class TestResolveDivisionGroups:
    def test_maps_division_names_to_blocks(self):
        r = resolve_division_groups(load_dum(DUM_TEXT))
        assert r["Sales Leadership"] == "group-division-sales-leadership"
        assert r["Finance"] == "group-division-finance"
        assert r["Data Analysis"] == "group-division-data-analysis"

    def test_ignores_broad_shared_blocks(self):
        r = resolve_division_groups(load_dum(DUM_TEXT))
        # The wide group-all-employees / group-audit-mirror blocks are never
        # grant targets, even though they list division labels.
        assert "group-all-employees" not in r.values()
        assert "group-audit-mirror" not in r.values()

    def test_core_block_matched_by_key_not_label(self):
        # The core block's groups label is the all-employees Okta group, and its
        # key is not group-division-* — it must still resolve, by CORE_BLOCK_KEY.
        r = resolve_division_groups(load_dum(DUM_TEXT))
        assert r["Core"] == "group-analytics-core-tables"


# ── build_core_tables ─────────────────────────────────────────────────────────
class TestBuildCoreTables:
    def test_returns_group_division_core_tables(self):
        from jirade.tools.dum_editor import build_core_tables
        core = build_core_tables(load_dum(DUM_TEXT))
        assert core == {"analytics.dimensional.dim_calendar"}

    def test_empty_when_no_core_block(self):
        from jirade.tools.dum_editor import build_core_tables
        dum = load_dum(
            "group-division-finance:\n  groups:\n    - \"Okta Push - Division - Finance\"\n"
        )
        assert build_core_tables(dum) == set()


# ── confidence gating ─────────────────────────────────────────────────────────
class TestIsHighConfidence:
    def test_inherit_is_high(self):
        assert is_high_confidence(_decision("x", "mart", "sales", [], status="inherits_from_ref")) is True

    def test_core_domain_is_high(self):
        assert is_high_confidence(_decision("x", "mart", "sales", [], status="core_domain")) is True

    def test_llm_high_is_high(self):
        assert is_high_confidence(_decision("x", "mart", "sales", [], confidence="high")) is True

    def test_llm_medium_and_low_are_not(self):
        assert is_high_confidence(_decision("x", "mart", "sales", [], confidence="medium")) is False
        assert is_high_confidence(_decision("x", "mart", "sales", [], confidence="low")) is False

    def test_failed_and_already_classified_are_not(self):
        assert is_high_confidence(_decision("x", "mart", "sales", [], status="llm_failed")) is False
        assert is_high_confidence(
            _decision("x", "mart", "sales", [], status="already_classified")
        ) is False


# ── table_identifier ──────────────────────────────────────────────────────────
def test_table_identifier():
    d = _decision("fact_new_signal", "mart", "sales", [])
    assert table_identifier(d) == "mart.sales.fact_new_signal"


# ── detect_division_drift ─────────────────────────────────────────────────────
class TestDetectDivisionDrift:
    def test_flags_governance_divisions_absent_from_dum(self):
        dum = load_dum(DUM_TEXT)  # blocks: Sales Leadership, Finance, Data Analysis
        gov = ["Sales Leadership", "Finance", "Revenue Operations", "Accounting"]
        drift = detect_division_drift(gov, dum)
        assert drift.missing_in_dum == ["Accounting", "Revenue Operations"]
        assert drift.has_drift is True

    def test_no_drift_when_all_present(self):
        dum = load_dum(DUM_TEXT)
        drift = detect_division_drift(["Sales Leadership", "Finance"], dum)
        assert drift.missing_in_dum == []
        assert drift.has_drift is False

    def test_reports_unused_dum_blocks(self):
        dum = load_dum(DUM_TEXT)
        # Governance references only Finance → the other two dum blocks are unused.
        drift = detect_division_drift(["Finance"], dum)
        assert "Data Analysis" in drift.unused_dum_blocks
        assert "Sales Leadership" in drift.unused_dum_blocks
        assert drift.has_drift is False  # unused-only is informational, not drift

    def test_render_note_empty_when_no_drift(self):
        assert render_drift_note(detect_division_drift(["Finance"], load_dum(DUM_TEXT))) == ""

    def test_render_note_lists_missing(self):
        note = render_drift_note(
            detect_division_drift(["Revenue Operations"], load_dum(DUM_TEXT))
        )
        assert "Not yet grantable" in note
        assert "`Revenue Operations`" in note


# ── apply_grants ──────────────────────────────────────────────────────────────
class TestApplyGrants:
    def test_writes_high_confidence_grants_to_matched_blocks(self):
        dum = load_dum(DUM_TEXT)
        d = _decision(
            "fact_new_signal", "mart", "sales",
            ["Sales Leadership", "Finance", "Nonexistent Division"],
            confidence="high",
        )
        res = apply_grants(dum, [d])

        assert ("Sales Leadership", "group-division-sales-leadership", "mart.sales.fact_new_signal") in res.applied
        assert ("Finance", "group-division-finance", "mart.sales.fact_new_signal") in res.applied
        assert ("Nonexistent Division", "mart.sales.fact_new_signal") in res.unmatched_divisions

    def test_inserts_sorted(self):
        dum = load_dum(DUM_TEXT)
        apply_grants(dum, [_decision("fact_new_signal", "mart", "sales", ["Sales Leadership"])])
        keys = [next(iter(e.keys())) for e in dum["group-division-sales-leadership"]["tables"]]
        assert keys == [
            "analytics.dimensional.dim_account",
            "mart.sales.fact_new_signal",
            "mart.sales.rpt_opportunity",
        ]

    def test_creates_tables_key_when_absent(self):
        dum = load_dum(DUM_TEXT)
        apply_grants(dum, [_decision("fact_new_signal", "mart", "sales", ["Finance"])])
        out = dump_dum(dum)
        # Finance had no tables: key — it must now exist with the grant.
        assert "group-division-finance:" in out
        finance_block = dum["group-division-finance"]["tables"]
        assert any("mart.sales.fact_new_signal" in e for e in finance_block)

    def test_does_not_touch_broad_block(self):
        dum = load_dum(DUM_TEXT)
        before = [next(iter(e.keys())) for e in dum["group-all-employees"]["tables"]]
        apply_grants(dum, [_decision("fact_new_signal", "mart", "sales", ["Sales Leadership"])])
        after = [next(iter(e.keys())) for e in dum["group-all-employees"]["tables"]]
        assert before == after == ["analytics.dimensional.dim_date"]

    def test_already_present_is_noop(self):
        dum = load_dum(DUM_TEXT)
        # dim_date already granted to Data Analysis in the fixture.
        d = _decision("dim_date", "analytics", "dimensional", ["Data Analysis"])
        res = apply_grants(dum, [d])
        assert ("Data Analysis", "group-division-data-analysis", "analytics.dimensional.dim_date") in res.already_present
        assert res.applied == []
        keys = [next(iter(e.keys())) for e in dum["group-division-data-analysis"]["tables"]]
        assert keys.count("analytics.dimensional.dim_date") == 1  # not duplicated

    def test_low_confidence_is_skipped_not_written(self):
        dum = load_dum(DUM_TEXT)
        d = _decision("fact_maybe", "mart", "sales", ["Sales Leadership"], confidence="low")
        res = apply_grants(dum, [d])
        assert "mart.sales.fact_maybe" in res.skipped_low_confidence
        assert res.applied == []
        keys = [next(iter(e.keys())) for e in dum["group-division-sales-leadership"]["tables"]]
        assert "mart.sales.fact_maybe" not in keys

    def test_edited_dump_reloads_and_keeps_comments(self):
        dum = load_dum(DUM_TEXT)
        apply_grants(dum, [_decision("fact_new_signal", "mart", "sales", ["Sales Leadership", "Finance"])])
        out = dump_dum(dum)
        assert "# Divisions" in out
        assert "&okta_all_divisions" in out
        # Re-loads cleanly and the grant is there.
        reloaded = load_dum(out)
        keys = [next(iter(e.keys())) for e in reloaded["group-division-finance"]["tables"]]
        assert "mart.sales.fact_new_signal" in keys
