#!/usr/bin/env python3
"""Behavioral acceptance scenarios for the boot evidence transaction.

This mirrors the Rust rules in ``src/evidence.rs`` and the four participating
scanners so the incident scenarios can be exercised without a Linux target:

* complete evidence spanning the boot window -> CLEAN,
* legal journal rotation while audit was switched off -> no source may claim
  clean and the boot verdict is INCONCLUSIVE,
* empty journal records -> INCONCLUSIVE (the original bug),
* permission errors / disabled / redirected sources -> INCONCLUSIVE,
* legitimate audit restart, rate limiting, dmesg restriction and an idle
  ftrace tracer keep their context instead of being silently dropped.

The assertions double as the per-source window-coverage acceptance checks.
"""

from __future__ import annotations

from dataclasses import dataclass, field

MIN_COVERED_SPAN_SECS = 60
RECORD_SOURCES = ("audit", "journal")


@dataclass
class SourceEvidence:
    window: tuple[int, int] | None = None
    record_count: int = 0
    origins: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def is_complete(self) -> bool:
        return (
            self.window is not None
            and self.record_count > 0
            and not self.errors
            and not self.limitations
        )

    def span_secs(self) -> int:
        if self.window is None:
            return 0
        start, end = self.window
        return max(0, end - start)


def verdict_for(source: str, evidence: SourceEvidence | None) -> str:
    if evidence is None:
        return "MISSING"
    if not evidence.is_complete():
        return "INCONCLUSIVE"
    if source in RECORD_SOURCES and evidence.span_secs() < MIN_COVERED_SPAN_SECS:
        return "INCONCLUSIVE"
    if evidence.window is not None:
        return "CLEAN"
    return "INCONCLUSIVE"


def boot_verdict(transaction: dict[str, SourceEvidence | None]) -> str:
    if all(
        verdict_for(source, evidence) == "CLEAN"
        for source, evidence in transaction.items()
    ):
        return "CLEAN"
    return "INCONCLUSIVE"


SOURCES = ("audit", "journal", "printk", "ftrace")


def clean_baseline() -> dict[str, SourceEvidence | None]:
    return {
        "audit": SourceEvidence(
            window=(0, 3600), record_count=400, origins=["/proc/net/audit"]
        ),
        "journal": SourceEvidence(
            window=(0, 3600),
            record_count=9000,
            origins=["journalctl -b", "cursor=s=1;i=1"],
        ),
        "printk": SourceEvidence(
            window=(0, 0), record_count=3, origins=["/proc/sys/kernel/printk"]
        ),
        "ftrace": SourceEvidence(
            window=(0, 0), record_count=2, origins=["/sys/kernel/tracing"]
        ),
    }


def assert_verdict(name: str, transaction: dict[str, SourceEvidence | None], expected: dict[str, str]):
    for source in SOURCES:
        actual = verdict_for(source, transaction[source])
        assert actual == expected[source], (
            f"{name}: source {source} expected {expected[source]} got {actual}"
        )


def test_clean_baseline_publishes_clean() -> None:
    tx = clean_baseline()
    assert_verdict(
        "clean_baseline",
        tx,
        {source: "CLEAN" for source in SOURCES},
    )
    assert boot_verdict(tx) == "CLEAN"


def test_incident_rotation_and_audit_off_never_clean() -> None:
    """The exact incident: legal journal rotation + audit off + empty view."""
    tx = clean_baseline()

    # audit was switched off inside the window: explicit limitation.
    tx["audit"] = SourceEvidence(
        window=(0, 1800),
        record_count=120,
        origins=["/proc/sys/kernel/audit_enabled"],
        limitations=["audit_enabled=0", "audit_disable_markers=1"],
    )

    # journal rotated legally; the remaining view starts late and the cursor
    # only anchors the post-rotation tail.
    tx["journal"] = SourceEvidence(
        window=(1500, 3600),
        record_count=300,
        origins=[
            "journalctl -b",
            "cursor=s=2;i=9",
            "files=/var/log/journal/.../system@abc.journal",
        ],
        limitations=["journal_rotations=1", "boot_head_uncovered=1500s"],
    )

    assert_verdict(
        "incident",
        tx,
        {
            "audit": "INCONCLUSIVE",
            "journal": "INCONCLUSIVE",
            "printk": "CLEAN",
            "ftrace": "CLEAN",
        },
    )
    assert boot_verdict(tx) == "INCONCLUSIVE"


def test_ghostscan_empty_record_incident_word_for_word() -> None:
    """Regression test for the original ghostscan false-clean bug.

    The host rotated its journal legally while audit was switched off inside
    the same window.  A scanner that only sees an empty record set must not
    mark the whole boot clean, and every affected source keeps its window,
    cursor and limitation attached to the transaction.
    """
    tx: dict[str, SourceEvidence | None] = {
        "audit": SourceEvidence(
            window=None,
            record_count=1,
            origins=["/proc/sys/kernel/audit_enabled"],
            limitations=["audit_enabled=0", "audit_epoch_visibility=empty"],
        ),
        "journal": SourceEvidence(
            window=None,
            record_count=0,
            origins=["journalctl -b", "cursor=s=9;i=1"],
            limitations=[
                "journal_records=0",
                "journal_rotations=1",
                "journal_cursor=unavailable",
            ],
            errors=[],
        ),
        "printk": SourceEvidence(
            window=(0, 0),
            record_count=3,
            origins=["/proc/sys/kernel/printk"],
            limitations=["dmesg_restrict=1"],
        ),
        "ftrace": SourceEvidence(
            window=None,
            record_count=0,
            origins=["/sys/kernel/tracing"],
            errors=["failed to locate tracefs"],
            limitations=["tracefs=unavailable"],
        ),
    }

    expected = {
        "audit": "INCONCLUSIVE",
        "journal": "INCONCLUSIVE",
        "printk": "INCONCLUSIVE",
        "ftrace": "INCONCLUSIVE",
    }
    assert_verdict("ghostscan_incident", tx, expected)
    assert boot_verdict(tx) == "INCONCLUSIVE"

    # The evidence that explains the verdict must survive the transaction.
    journal = tx["journal"]
    assert journal is not None
    assert any("journal_rotations=1" == item for item in journal.limitations)
    assert any(item.startswith("cursor=") for item in journal.origins)
    audit = tx["audit"]
    assert audit is not None
    assert "audit_enabled=0" in audit.limitations


def test_empty_records_cannot_be_clean() -> None:
    tx = clean_baseline()
    tx["journal"] = SourceEvidence(
        window=None,
        record_count=0,
        origins=["journalctl -b"],
        limitations=["journal_records=0"],
    )
    assert verdict_for("journal", tx["journal"]) == "INCONCLUSIVE"
    assert boot_verdict(tx) == "INCONCLUSIVE"


def test_permission_error_downgrades_even_with_records() -> None:
    tx = clean_baseline()
    tx["audit"] = SourceEvidence(
        window=(0, 3600),
        record_count=50,
        origins=["/proc/net/audit"],
        errors=["permission denied reading /proc/net/audit"],
        limitations=["proc_audit_access=denied"],
    )
    assert verdict_for("audit", tx["audit"]) == "INCONCLUSIVE"


def test_legitimate_restart_and_rate_limit_keep_context() -> None:
    tx = clean_baseline()
    tx["audit"] = SourceEvidence(
        window=(0, 3600),
        record_count=400,
        origins=["journalctl -b KERNEL_AUDIT"],
        # Restart + rate limiting are operational context: preserved, and the
        # window seam keeps the source from claiming a clean observation.
        limitations=["audit_epochs=2", "audit_restarts=2", "audit_rate_limited=1"],
    )
    evidence = tx["audit"]
    assert evidence is not None
    assert "audit_epochs=2" in evidence.limitations
    assert "audit_rate_limited=1" in evidence.limitations
    assert verdict_for("audit", evidence) == "INCONCLUSIVE"


def test_restricted_dmesg_is_limitation_not_finding_but_not_clean() -> None:
    tx = clean_baseline()
    tx["printk"] = SourceEvidence(
        window=(0, 120),
        record_count=3,
        origins=["/proc/sys/kernel/dmesg_restrict"],
        # Restricted dmesg is expected hardening, but it still bounds what the
        # scan could observe, so no public clean claim is possible alone.
        limitations=["dmesg_restrict=1"],
    )
    assert verdict_for("printk", tx["printk"]) == "INCONCLUSIVE"


def test_idle_ftrace_stays_clean_when_fully_readable() -> None:
    tx = clean_baseline()
    # current_tracer=nop and empty filter: no limitation, no error.
    tx["ftrace"] = SourceEvidence(
        window=(0, 120),
        record_count=2,
        origins=["/sys/kernel/tracing/current_tracer"],
    )
    assert verdict_for("ftrace", tx["ftrace"]) == "CLEAN"


def test_redirected_ftrace_is_inconclusive() -> None:
    tx = clean_baseline()
    tx["ftrace"] = SourceEvidence(
        window=(0, 120),
        record_count=2,
        origins=["/sys/kernel/tracing/current_tracer"],
        limitations=["ftrace_tracer=function", "ftrace_sensitive_filter=true"],
    )
    assert verdict_for("ftrace", tx["ftrace"]) == "INCONCLUSIVE"


def test_missing_tracefs_is_missing_observation() -> None:
    tx = clean_baseline()
    tx["ftrace"] = SourceEvidence(
        window=None,
        record_count=0,
        origins=["/sys/kernel/tracing"],
        errors=["failed to locate tracefs"],
        limitations=["tracefs=unavailable"],
    )
    assert verdict_for("ftrace", tx["ftrace"]) == "INCONCLUSIVE"


def test_narrow_window_cannot_claim_coverage() -> None:
    evidence = SourceEvidence(window=(0, 5), record_count=1)
    assert verdict_for("audit", evidence) == "INCONCLUSIVE"


def test_missing_source_is_reported() -> None:
    assert verdict_for("ftrace", None) == "MISSING"


def main() -> int:
    tests = [
        obj
        for name, obj in sorted(globals().items())
        if name.startswith("test_") and callable(obj)
    ]
    for test in tests:
        test()
        print(f"ok   - {test.__name__}")
    print(f"\nall {len(tests)} behavioral scenarios passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
