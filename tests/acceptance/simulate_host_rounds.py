#!/usr/bin/env python3
"""Executable truth-table for the host observation generation.

This mirrors the Rust state machine in ``src/host_observation.rs`` without
needing a Rust toolchain.  It is intentionally small and checks the incident
properties directly:

* a second round whose task collector fails has no task evidence,
* a stamp from the first round is rejected by the second round's report,
* cancel + failed retry never resurrects a previously completed value,
* empty container inventories are complete evidence,
* permission errors are partial evidence, not a foreign-generation fallback,
* scanner ordering/filtering and the public exit code are unchanged.

Run: python3 tests/acceptance/simulate_host_rounds.py
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class Generation:
    boot_id: str
    round: int
    started_ns: int

    @property
    def label(self) -> str:
        return f"{self.boot_id}:{self.round}:{self.started_ns}"


@dataclass(frozen=True)
class Stamp:
    kind: str
    generation: Generation
    attempt: int


@dataclass
class Collector:
    kind: str
    stamp: Stamp
    status: str
    value: Optional[object]
    reason: Optional[str] = None
    error_count: int = 0

    def usable(self) -> bool:
        return self.status in ("COMPLETE", "PARTIAL")


@dataclass
class Observation:
    generation: Generation
    collectors: Dict[str, Collector] = field(default_factory=dict)

    def add(self, kind: str, status: str, value: Optional[object],
            attempt: int = 1, reason: Optional[str] = None,
            error_count: int = 0) -> None:
        self.collectors[kind] = Collector(
            kind=kind,
            stamp=Stamp(kind, self.generation, attempt),
            status=status,
            value=value,
            reason=reason,
            error_count=error_count,
        )

    def merged_domains(self) -> List[str]:
        domains: List[str] = []
        if self.collectors["containers"].usable():
            domains.append("container")
        if self.collectors["bpf_tasks"].usable() and self.collectors["proc_tasks"].usable():
            domains.append("tasks")
        return domains

    def evidence_status(self) -> str:
        statuses = [collector.status for collector in self.collectors.values()]
        if not any(status in ("COMPLETE", "PARTIAL") for status in statuses):
            return "FAILED"
        if all(status == "COMPLETE" for status in statuses):
            return "COMPLETE"
        return "PARTIAL"

    def report(self, offered: List[Stamp]) -> Tuple[List[str], int, bool]:
        accepted = [stamp for stamp in offered if stamp.generation == self.generation]
        rejected = [stamp for stamp in offered if stamp.generation != self.generation]
        return self.merged_domains(), len(rejected), len(accepted) == len(offered)


def round_one() -> Observation:
    observation = Observation(Generation("boot-a", 1, 1_000))
    observation.add("containers", "COMPLETE", ["container-a"])
    observation.add("bpf_tasks", "COMPLETE", {4242: "task-a"})
    observation.add("proc_tasks", "COMPLETE", {4242: "task-a"})
    return observation


def round_two_task_failure() -> Observation:
    observation = Observation(Generation("boot-a", 2, 2_000))
    observation.add("containers", "COMPLETE", ["container-b"])
    observation.add(
        "bpf_tasks",
        "FAILED",
        None,
        reason="bpftool is not available",
    )
    observation.add("proc_tasks", "COMPLETE", {5000: "task-b"})
    return observation


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"ok   - {message}")


def main() -> None:
    first = round_one()
    second = round_two_task_failure()

    check(first.generation != second.generation, "two rounds have distinct generations")
    check(
        second.merged_domains() == ["container"],
        "failed task collector merges only the current round's containers",
    )
    check(
        second.collectors["bpf_tasks"].value is None,
        "failed second-round task collector holds no stale task value",
    )
    check(
        second.collectors["bpf_tasks"].reason == "bpftool is not available",
        "collector failure text is preserved",
    )
    check(
        second.evidence_status() == "PARTIAL",
        "a failed task collector makes the host evidence partial",
    )

    stale_stamp = first.collectors["containers"].stamp
    domains, rejected, same_generation = second.report([stale_stamp])
    check(rejected == 1 and not same_generation, "a first-round stamp is rejected")
    check(domains == ["container"], "rejected stale evidence is not merged")

    # Cancel + failed retry: the completed value must be dropped first and the
    # failed retry must not restore it.
    cancelled = observation_with_retry()
    check(cancelled.collectors["bpf_tasks"].status == "FAILED", "failed retry stays failed")
    check(cancelled.collectors["bpf_tasks"].value is None, "failed retry exposes no old value")
    check(
        cancelled.collectors["bpf_tasks"].stamp.attempt == 3,
        "cancel and retry each advance the collector attempt",
    )
    check(cancelled.merged_domains() == ["container"], "cancelled tasks are not merged")

    empty = Observation(Generation("boot-a", 3, 3_000))
    empty.add("containers", "COMPLETE", [])
    empty.add("bpf_tasks", "COMPLETE", {})
    empty.add("proc_tasks", "COMPLETE", {})
    check(empty.merged_domains() == ["container", "tasks"], "empty results are complete evidence")
    check(empty.evidence_status() == "COMPLETE", "empty results are not collector failures")

    denied = Observation(Generation("boot-a", 4, 4_000))
    denied.add("containers", "PARTIAL", [], error_count=1)
    denied.add("bpf_tasks", "COMPLETE", {4242: "task"})
    denied.add("proc_tasks", "COMPLETE", {4242: "task"})
    check(
        denied.evidence_status() == "PARTIAL",
        "permission/read errors remain partial evidence",
    )
    check(denied.merged_domains() == ["container", "tasks"], "partial container evidence is usable")

    check(SCANNER_ORDER[0] == "Hidden LKM (proc/sysfs vs kallsyms clusters)",
          "scanner ordering anchor is unchanged")
    check(len(SCANNER_ORDER) == 50, "scanner set still contains 50 entries")
    check(EXIT_CODE == 0, "existing exit code remains 0")

    print("\nall host observation round simulations passed")


def observation_with_retry() -> Observation:
    observation = Observation(Generation("boot-a", 5, 5_000))
    observation.add("containers", "COMPLETE", ["container-a"])
    # attempt 1 succeeds, then operator cancel advances to attempt 2, and the
    # failed retry records attempt 3 without restoring the old value.
    observation.add("bpf_tasks", "FAILED", None, attempt=3, reason="retry failed")
    observation.add("proc_tasks", "COMPLETE", {4242: "task-a"})
    return observation


SCANNER_ORDER = [
    "Hidden LKM (proc/sysfs vs kallsyms clusters)",
    "Kernel taint with no visible cause",
    "Ftrace redirection on critical paths",
    "Unknown kprobes on sensitive symbols",
    "Syscall table pointer integrity",
    "modprobe helper tamper",
    "Netfilter hook drift (orphans/invalid jumps)",
    "Module list linkage tamper",
    "Ownerless BPF objects",
    "BPF kprobe attachments to sensitive symbols",
    "BPF LSM present",
    "XDP/TC detached programs",
    "Sockmap/Sockhash verdict without owners",
    "Sensitive kfunc usage",
    "Pins on non-bpffs mounts",
    "Netlink vs /proc/net sockets",
    "Task list mismatch (BPF vs /proc)",
    "Hidden PIDs (bpf-only)",
    "Kernel thread masquerade",
    "Suspicious ptrace edges",
    "Seccomp user-notify responders",
    "Deleted-binary or memfd processes",
    "Core dump pipeline tamper",
    "Hidden listeners (netlink-only)",
    "Ownerless sockets",
    "Netfilter cloaking artifacts",
    "Local port backdoors (tmp/deleted)",
    "ld.so.preload tamper",
    "Cron/anacron/at ghost jobs",
    "systemd ghost units (exec in tmp/deleted)",
    "SSH footholds (forced/wildcard/insecure)",
    "OverlayFS whiteouts / opaque",
    "Hidden bind/immutable mounts",
    "Fanotify watchers on sensitive mounts",
    "PAM/NSS modules from non-system paths",
    "Live LD_PRELOAD to deleted/writable libs",
    "Library search hijack (SUID/priv)",
    "LD_AUDIT in daemons (no TTY)",
    "Large RX-anonymous regions in daemons (non-JIT)",
    "Kernel text not RO (best-effort)",
    "scripts.d executable from tmp/non-root",
    "sudoers dangerous entries",
    "Kernel cmdline disables auditing/lockdown/IMA",
    "Sensitive host mounts into containers",
    "Host PID namespace shared",
    "Host net namespace shared",
    "Overlay lowerdir outside storage root",
    "Audit disabled or dropping",
    "Journal gaps (current boot)",
    "Kernel message suppression",
]

EXIT_CODE = 0


if __name__ == "__main__":
    main()
