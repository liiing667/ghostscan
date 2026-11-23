#!/usr/bin/env python3
"""Behavioral acceptance scenarios for the shared scan summary transaction.

This mirrors the Rust rules in ``src/scan_summary.rs`` and the dispatch in
``src/main.rs`` so the incident scenarios can be exercised without a Linux
target or a Rust toolchain:

* every collector clean                 -> CLEAN, exit 0 (empty scan stays
  clean and no-hit collectors are not failures),
* two risky collectors + one permission
  error                                 -> RISK+INCOMPLETE, exit 3 (the
  reported bug can never end clean),
* one permission error, no findings     -> INCOMPLETE, exit 2,
* findings only                        -> RISK, exit 1,
* an aborted (panicking) collector      -> INCOMPLETE, never skipped,
* a report write failure still keeps the verdict/exit code derived from the
  same transaction, so no clean or mixed round is left behind.

Run: python3 tests/acceptance/simulate_scan_rounds.py
"""

from __future__ import annotations

from dataclasses import dataclass, field

CLEAN = "CLEAN"
RISK = "RISK"
INCOMPLETE = "INCOMPLETE"
RISK_INCOMPLETE = "RISK+INCOMPLETE"


@dataclass
class CollectorRecord:
    name: str
    status: str  # "finding" | "clean" | "failed"
    detail: str = ""


@dataclass
class ScanSummary:
    """Python mirror of src/scan_summary.rs::ScanSummary."""

    records: list[CollectorRecord] = field(default_factory=list)

    def record(self, name: str, outcome: tuple[str, str]) -> None:
        kind, detail = outcome
        if kind == "finding":
            status = "finding"
        elif kind == "clean":
            status = "clean"
        else:
            status = "failed"
        self.records.append(CollectorRecord(name, status, detail))

    def record_aborted(self, name: str, reason: str) -> None:
        self.records.append(CollectorRecord(name, "failed", reason))

    def total(self) -> int:
        return len(self.records)

    def finding_count(self) -> int:
        return sum(r.status == "finding" for r in self.records)

    def failure_count(self) -> int:
        return sum(r.status == "failed" for r in self.records)

    def covered(self) -> int:
        return self.total() - self.failure_count()

    def verdict(self) -> str:
        has_findings = self.finding_count() > 0
        has_failures = self.failure_count() > 0
        if not has_findings and not has_failures:
            return CLEAN
        if has_findings and not has_failures:
            return RISK
        if not has_findings and has_failures:
            return INCOMPLETE
        return RISK_INCOMPLETE

    def exit_code(self) -> int:
        return {CLEAN: 0, RISK: 1, INCOMPLETE: 2, RISK_INCOMPLETE: 3}[
            self.verdict()
        ]

    def render(self) -> str:
        lines = [
            "[Summary]",
            (
                f"collectors={self.total()} covered={self.covered()} "
                f"findings={self.finding_count()} failures={self.failure_count()}"
            ),
        ]
        findings = [r for r in self.records if r.status == "finding"]
        if findings:
            lines.append("findings:")
            lines.extend(f"- {r.name}: {r.detail}" for r in findings)
        failures = [r for r in self.records if r.status == "failed"]
        if failures:
            lines.append("failures:")
            lines.extend(f"- {r.name}: {r.detail}" for r in failures)
        lines.append(f"verdict: {self.verdict()}")
        return "\n".join(lines) + "\n"


def write_report(summary: ScanSummary, sink: list[str] | None) -> tuple[bool, str]:
    """Render before write, matching main.rs::write_all.

    A ``None`` sink simulates a broken report channel: the buffer is still
    built and the exit code still comes from the same summary.
    """
    report = summary.render()
    if sink is None:
        return False, report
    sink.append(report)
    return True, report


def check(name: str, got: object, expected: object) -> None:
    if got != expected:
        raise AssertionError(f"{name}: expected {expected!r}, got {got!r}")
    print(f"ok   - {name}")


def main() -> int:
    # Scenario 1: the reported incident - two risky collectors plus one
    # permission failure. The old binary printed the first risk and still
    # exited clean; the transaction must end RISK+INCOMPLETE with code 3.
    incident = ScanSummary()
    incident.record("Hidden LKM", ("finding", "module=rootkit.ko"))
    incident.record("Unknown kprobes", ("finding", "target=sys_connect"))
    incident.record(
        "Host PID namespace shared",
        ("failed", "permission denied reading host pid ns"),
    )
    for quiet in range(47):
        incident.record(f"quiet-{quiet}", ("clean", ""))
    check("incident coverage counts only completed collectors",
          incident.covered(), 49)
    check("incident finding count", incident.finding_count(), 2)
    check("incident failure count", incident.failure_count(), 1)
    check("incident never ends clean", incident.verdict(), RISK_INCOMPLETE)
    check("incident exit code", incident.exit_code(), 3)
    report = incident.render()
    assert "verdict: CLEAN" not in report
    assert "verdict: RISK+INCOMPLETE" in report
    print("ok   - incident report contains no clean claim")

    # Scenario 2: empty scan / no-hit collectors stay clean and exit 0.
    empty = ScanSummary()
    for idx in range(50):
        empty.record(f"collector-{idx}", ("clean", ""))
    check("empty scan is fully covered", empty.covered(), 50)
    check("empty scan verdict", empty.verdict(), CLEAN)
    check("empty scan exit code", empty.exit_code(), 0)

    # Scenario 3: permission error alone is INCOMPLETE, code 2 - never clean.
    denied = ScanSummary()
    denied.record("Seccomp user-notify responders",
                  ("failed", "pid=42 fd: permission denied"))
    denied.record("Audit disabled or dropping", ("clean", ""))
    check("denied collector loses coverage", denied.covered(), 1)
    check("denied round verdict", denied.verdict(), INCOMPLETE)
    check("denied round exit code", denied.exit_code(), 2)
    assert "CLEAN" not in denied.render()
    print("ok   - permission failure report never claims clean")

    # Scenario 4: findings only are RISK, code 1.
    risky = ScanSummary()
    risky.record("sudoers dangerous entries",
                 ("finding", "entry='NOPASSWD: ALL'"))
    check("risky round verdict", risky.verdict(), RISK)
    check("risky round exit code", risky.exit_code(), 1)

    # Scenario 5: an aborted collector is a failure, not a skipped collector.
    aborted = ScanSummary()
    aborted.record_aborted("Ftrace redirection", "collector aborted: boom")
    check("aborted collector counts as failure", aborted.failure_count(), 1)
    check("aborted round is incomplete", aborted.verdict(), INCOMPLETE)
    check("aborted round exit code", aborted.exit_code(), 2)

    # Scenario 6: a broken report channel still leaves a coherent round - the
    # rendered verdict and the exit code come from the same summary.
    ok, rendered = write_report(incident, sink=None)
    check("broken write is reported", ok, False)
    check("rendered verdict still non-clean",
          "verdict: RISK+INCOMPLETE" in rendered, True)
    check("exit code unaffected by write failure", incident.exit_code(), 3)
    sink: list[str] = []
    ok, _ = write_report(empty, sink)
    check("healthy write succeeds", ok, True)
    check("healthy report claims clean", "verdict: CLEAN" in sink[0], True)

    print("\nall behavioral scenarios passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
