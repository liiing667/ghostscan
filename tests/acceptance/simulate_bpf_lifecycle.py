#!/usr/bin/env python3
"""Executable truth table for the shared BPF lifecycle transaction.

This mirrors the Rust rules in ``src/bpf_lifecycle.rs`` and the public BPF
scanners so the incident scenarios can be exercised without a Linux/libbpf
target:

* a program detached and re-pinned between collectors cannot be combined with
  the old kprobe link,
* program id reuse with a different tag is a cross-generation conflict,
* an identity fence discards the whole generation and a retry starts clean,
* legal bpffs pins and anonymous programs remain visible,
* kprobe and kretprobe attachments stay distinct,
* permission errors are explicit and never become a clean/OK result.

Run: python3 tests/acceptance/simulate_bpf_lifecycle.py
"""

from __future__ import annotations

from dataclasses import dataclass, field

MAX_ATTEMPTS = 4


@dataclass(frozen=True)
class Stamp:
    boot_id: str
    generation: int
    attempt: int = 1
    started_unix_ns: int = 0
    pid: int = 1

    def same_generation(self, other: "Stamp") -> bool:
        return self.boot_id == other.boot_id and self.generation == other.generation


@dataclass
class Program:
    id: int
    name: str
    tag: str
    type: str
    attach_type: str
    owner_pids: list[int] = field(default_factory=list)
    pinned: list[str] = field(default_factory=list)
    stamp: Stamp | None = None


@dataclass
class Map:
    id: int
    name: str
    type: str
    owner_pids: list[int] = field(default_factory=list)
    pinned: list[str] = field(default_factory=list)
    verdict_prog_id: int | None = None
    verdict_prog_tag: str | None = None
    stamp: Stamp | None = None


@dataclass
class Link:
    id: int
    prog_id: int | None
    prog_tag: str | None
    type: str
    attach_type: str
    target: str
    pinned: list[str] = field(default_factory=list)
    stamp: Stamp | None = None


@dataclass
class Pin:
    path: str
    object_kind: str
    object_id: int
    object_tag: str | None
    mount_fstype: str
    stamp: Stamp | None = None

    @property
    def on_bpffs(self) -> bool:
        return self.mount_fstype == "bpf"


@dataclass
class Snapshot:
    stamp: Stamp
    programs: list[Program] = field(default_factory=list)
    maps: list[Map] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    pins: list[Pin] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    cross_generation: int = 0

    def program(self, prog_id: int) -> Program | None:
        return next((program for program in self.programs if program.id == prog_id), None)

    def ownerless_programs(self) -> list[Program]:
        return [
            program
            for program in self.programs
            if not program.owner_pids and not program.pinned
        ]

    def validate(self) -> None:
        by_id: dict[int, set[str]] = {}
        for program in self.programs:
            by_id.setdefault(program.id, set()).add(program.tag)
        for prog_id, tags in by_id.items():
            if len(tags) > 1:
                self.conflicts.append(
                    f"program id={prog_id} reused with different tags: {sorted(tags)}"
                )
                self.cross_generation += 1

        for link in self.links:
            if link.prog_id is None:
                continue
            program = self.program(link.prog_id)
            if program is None:
                self.conflicts.append(
                    f"link id={link.id} references missing program id={link.prog_id}"
                )
                self.cross_generation += 1
            elif (
                link.prog_tag
                and link.prog_tag != "unknown"
                and link.prog_tag != program.tag
            ):
                self.conflicts.append(
                    f"link id={link.id} tag={link.prog_tag} != program tag={program.tag}"
                )
                self.cross_generation += 1

        for map_record in self.maps:
            if map_record.verdict_prog_id is None:
                continue
            program = self.program(map_record.verdict_prog_id)
            if program is None:
                self.conflicts.append(
                    f"map id={map_record.id} references missing verdict program"
                )
                self.cross_generation += 1
            elif (
                map_record.verdict_prog_tag
                and map_record.verdict_prog_tag != "unknown"
                and map_record.verdict_prog_tag != program.tag
            ):
                self.conflicts.append(
                    f"map id={map_record.id} verdict tag mismatch"
                )
                self.cross_generation += 1

    def status(self) -> str:
        if self.conflicts:
            return "UNSTABLE"
        if self.errors:
            return "PARTIAL"
        return "COMPLETE"


def identity_fence(first: dict[int, str], second: dict[int, str], kind: str) -> list[str]:
    conflicts = []
    for object_id in sorted(set(first) | set(second)):
        if first.get(object_id) != second.get(object_id):
            conflicts.append(f"{kind} id={object_id} changed identity between collectors")
    return conflicts


def collect_generation(
    stamp: Stamp,
    first: tuple[list[Program], list[Map], list[Link], list[Pin]],
    fence: tuple[list[Program], list[Map], list[Link]] | None,
) -> Snapshot:
    programs, maps, links, pins = first
    snapshot = Snapshot(stamp=stamp, programs=programs, maps=maps, links=links, pins=pins)
    if fence is not None:
        fence_programs, fence_maps, fence_links = fence
        snapshot.conflicts.extend(
            identity_fence(
                {
                    program.id: f"{program.name}:{program.tag}:{program.pinned}:{program.owner_pids}"
                    for program in programs
                },
                {
                    program.id: f"{program.name}:{program.tag}:{program.pinned}:{program.owner_pids}"
                    for program in fence_programs
                },
                "program",
            )
        )
        snapshot.conflicts.extend(
            identity_fence(
                {record.id: f"{record.name}:{record.type}" for record in maps},
                {record.id: f"{record.name}:{record.type}" for record in fence_maps},
                "map",
            )
        )
        snapshot.conflicts.extend(
            identity_fence(
                {
                    link.id: f"{link.prog_id}:{link.type}:{link.attach_type}"
                    for link in links
                },
                {
                    link.id: f"{link.prog_id}:{link.type}:{link.attach_type}"
                    for link in fence_links
                },
                "link",
            )
        )
        snapshot.cross_generation += len(snapshot.conflicts)
    snapshot.validate()
    return snapshot


def collect_transaction(rounds: list[tuple]) -> Snapshot:
    """Each round is (stamp, first_tuple, fence_tuple-or-None)."""
    last = None
    for index, (stamp, first, fence) in enumerate(rounds[:MAX_ATTEMPTS], start=1):
        snapshot = collect_generation(stamp, first, fence)
        if not snapshot.conflicts:
            return snapshot
        last = snapshot
    if last is None:
        raise AssertionError("no rounds supplied")
    last.conflicts.append(f"no stable BPF generation after {MAX_ATTEMPTS} attempts")
    last.cross_generation += 1
    return last


def stamp(generation: int, boot_id: str = "boot-a") -> Stamp:
    return Stamp(boot_id=boot_id, generation=generation)


def test_detach_and_repin_between_collectors_is_not_merged() -> None:
    old_program = Program(7, "probe", "old-tag", "tracing", "kprobe")
    new_program = Program(7, "probe", "new-tag", "tracing", "kprobe")
    old_link = Link(11, 7, "old-tag", "kprobe", "kprobe", "vfs_read")
    new_link = Link(12, 7, "new-tag", "kprobe", "kprobe", "vfs_read")

    incident = collect_generation(
        stamp(1),
        ([old_program], [], [old_link], []),
        ([new_program], [], [new_link]),
    )
    assert incident.conflicts, "program id reuse must invalidate the generation"
    assert incident.status() == "UNSTABLE"

    # Retry starts a fresh generation and only publishes the matching pair.
    retry = collect_generation(
        stamp(2),
        ([new_program], [], [new_link], []),
        ([new_program], [], [new_link]),
    )
    assert retry.status() == "COMPLETE"
    assert retry.links[0].prog_tag == retry.program(7).tag  # type: ignore[union-attr]


def test_pin_move_between_collectors_discards_generation() -> None:
    before = Program(3, "probe", "tag-a", "tracing", "kprobe")
    after = Program(3, "probe", "tag-a", "tracing", "kprobe", pinned=["/sys/fs/bpf/x"])
    snapshot = collect_generation(
        stamp(1),
        ([before], [], [], []),
        ([after], [], []),
    )
    assert snapshot.conflicts
    assert any("changed identity" in conflict for conflict in snapshot.conflicts)


def test_legal_bpffs_pin_and_anonymous_program_are_preserved() -> None:
    program = Program(5, "anonymous", "tag-a", "tracing", "kprobe")
    documented = Program(
        6,
        "pinned",
        "tag-b",
        "tracing",
        "kprobe",
        pinned=["/sys/fs/bpf/pinned"],
    )
    pin = Pin(
        "/sys/fs/bpf/pinned",
        "prog",
        6,
        "tag-b",
        "bpf",
    )
    snapshot = collect_generation(
        stamp(1),
        ([program, documented], [], [], [pin]),
        ([program, documented], [], []),
    )
    assert [record.id for record in snapshot.ownerless_programs()] == [5]
    assert all(record.on_bpffs for record in snapshot.pins)


def test_distinct_attach_types_keep_their_kind() -> None:
    program = Program(8, "probe", "tag-a", "tracing", "kprobe")
    kprobe = Link(1, 8, "tag-a", "kprobe", "kprobe", "vfs_read")
    kretprobe = Link(2, 8, "tag-a", "kretprobe", "kretprobe", "vfs_write")
    snapshot = collect_generation(
        stamp(1),
        ([program], [], [kprobe, kretprobe], []),
        ([program], [], [kprobe, kretprobe]),
    )
    kinds = {link.attach_type for link in snapshot.links}
    assert kinds == {"kprobe", "kretprobe"}


def test_permission_error_is_explicit() -> None:
    snapshot = collect_generation(
        stamp(1),
        ([], [], [], []),
        None,
    )
    snapshot.errors.append("permission denied reading BPF programs")
    assert snapshot.status() == "PARTIAL"
    assert snapshot.status() != "COMPLETE"


def main() -> int:
    tests = [
        obj
        for name, obj in sorted(globals().items())
        if name.startswith("test_") and callable(obj)
    ]
    for test in tests:
        test()
        print(f"ok   - {test.__name__}")
    print(f"\nall {len(tests)} BPF lifecycle scenarios passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
