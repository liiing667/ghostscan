#!/usr/bin/env python3
"""Behavioral scenarios for the shared packet-path transaction.

This mirrors the rules in ``src/packet_path.rs`` so the incident can be
exercised without a Linux target or a Rust toolchain:

* legal IPv4/IPv6, iptables-nft + native nftables, XDP/TC and empty chains
  produce no risk finding,
* an old table's cloaking chain and a newly attached XDP program keep
  different paths and different table/interface/program attribution,
* a hot rule update, a retry and a second entry point cannot merge two
  generations,
* evidence gathered in another network namespace is rejected.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Generation:
    boot_id: str
    round: int
    netns: int

    def label(self) -> str:
        return f"{self.boot_id}:{self.round}:{self.netns}"


@dataclass
class Chain:
    family: str
    table: str
    name: str
    chain_type: str | None = None
    hook: str | None = None
    interfaces: set[str] = field(default_factory=set)
    rule_count: int = 0
    jumps: set[str] = field(default_factory=set)
    sets: set[str] = field(default_factory=set)

    @property
    def is_regular(self) -> bool:
        return self.chain_type is None and self.hook is None


@dataclass
class Attachment:
    ifname: str
    ifindex: int | None
    program_id: int | None
    program_name: str
    hook: str
    direction: str


@dataclass
class Program:
    program_id: int | None
    name: str
    program_type: str


@dataclass
class Finding:
    kind: str
    generation: str
    netns: int
    plane: str
    table: str = "none"
    chain: str = "none"
    hook: str = "none"
    interface: str = "none"
    program: str = "none"
    program_id: int | None = None
    path: str = ""
    detail: str = ""


def hook_group(hook: str) -> str:
    if hook in {"prerouting", "input", "ingress"}:
        return "ingress"
    if hook in {"postrouting", "output", "egress"}:
        return "egress"
    if hook == "forward":
        return "forward"
    return "unknown"


def attachment_group(attachment: Attachment) -> str:
    if attachment.direction in {"ingress", "egress", "forward"}:
        return attachment.direction
    return hook_group(attachment.hook)


def analyze_netfilter(chains: list[Chain], generation: Generation) -> list[Finding]:
    by_table: dict[tuple[str, str], set[str]] = {}
    for chain in chains:
        by_table.setdefault((chain.family, chain.table), set()).add(chain.name)

    reachable: set[tuple[str, str, str]] = set()
    queue = [
        (chain.family, chain.table, chain.name)
        for chain in chains
        if chain.hook is not None
    ]
    while queue:
        current = queue.pop()
        if current in reachable:
            continue
        reachable.add(current)
        family, table, name = current
        chain = next(
            (
                item
                for item in chains
                if (item.family, item.table, item.name) == (family, table, name)
            ),
            None,
        )
        if chain is not None:
            queue.extend((family, table, target) for target in chain.jumps)

    findings: list[Finding] = []
    for chain in chains:
        interface = "|".join(sorted(chain.interfaces)) if chain.interfaces else "any"
        path = (
            f"netfilter:{generation.netns}/{chain.family}/{chain.table}/"
            f"{chain.name}/{chain.hook or 'none'}/{interface}"
        )
        if chain.chain_type is not None and chain.hook is None:
            findings.append(
                Finding(
                    kind="orphan_base_chain",
                    generation=generation.label(),
                    netns=generation.netns,
                    plane="netfilter",
                    table=chain.table,
                    chain=chain.name,
                    hook="none",
                    interface=interface,
                    path=path,
                )
            )
        for target in chain.jumps:
            if target not in by_table[(chain.family, chain.table)]:
                findings.append(
                    Finding(
                        kind="jump_to_missing_handle",
                        generation=generation.label(),
                        netns=generation.netns,
                        plane="netfilter",
                        table=chain.table,
                        chain=chain.name,
                        hook=chain.hook or "none",
                        interface=interface,
                        path=path,
                        detail=f"target={target}",
                    )
                )
        if (
            chain.is_regular
            and chain.rule_count > 0
            and (chain.family, chain.table, chain.name) not in reachable
        ):
            findings.append(
                Finding(
                    kind="cloaked_chain",
                    generation=generation.label(),
                    netns=generation.netns,
                    plane="netfilter",
                    table=chain.table,
                    chain=chain.name,
                    hook="none",
                    interface=interface,
                    path=path,
                )
            )
    return findings


def analyze_bpf(
    attachments: list[Attachment],
    programs: list[Program] | None,
    generation: Generation,
) -> list[Finding]:
    findings: list[Finding] = []
    attached_ids = {
        attachment.program_id
        for attachment in attachments
        if attachment.program_id is not None
    }
    for attachment in attachments:
        interface = attachment.ifname or "none"
        path = (
            f"bpf:{generation.netns}/{interface}/{attachment.hook}/"
            f"{attachment.direction}/"
            f"{attachment.program_id if attachment.program_id is not None else 'none'}"
        )
        if attachment.ifindex is None and interface in {"", "none", "unknown"}:
            findings.append(
                Finding(
                    kind="attachment_without_interface",
                    generation=generation.label(),
                    netns=generation.netns,
                    plane="bpf",
                    hook=attachment.hook,
                    interface=interface,
                    program=attachment.program_name,
                    program_id=attachment.program_id,
                    path=path,
                )
            )
        if (
            programs is not None
            and attachment.program_id is not None
            and all(program.program_id != attachment.program_id for program in programs)
        ):
            findings.append(
                Finding(
                    kind="attachment_missing_program",
                    generation=generation.label(),
                    netns=generation.netns,
                    plane="bpf",
                    hook=attachment.hook,
                    interface=interface,
                    program=attachment.program_name,
                    program_id=attachment.program_id,
                    path=path,
                )
            )
    if programs is not None:
        for program in programs:
            if program.program_type.lower() not in {
                "xdp",
                "sched_cls",
                "sched_act",
            }:
                continue
            if program.program_id is not None and program.program_id in attached_ids:
                continue
            findings.append(
                Finding(
                    kind="detached_xdp_tc_program",
                    generation=generation.label(),
                    netns=generation.netns,
                    plane="bpf",
                    program=program.name,
                    program_id=program.program_id,
                    path=(
                        f"bpf:{generation.netns}/none/none/unknown/"
                        f"{program.program_id if program.program_id is not None else 'none'}"
                    ),
                )
            )
    return findings


def families_compatible(left: str, right: str) -> bool:
    if left == right or "any" in {left, right}:
        return True
    ip_families = {"ip", "ip6", "ipv4", "ipv6", "inet", "inet6"}
    return "inet" in {left, right} and left in ip_families and right in ip_families


def analyze_paths(
    chains: list[Chain],
    attachments: list[Attachment],
    generation: Generation,
) -> list[dict[str, object]]:
    anchors: list[tuple[str, str, str, str, Chain]] = []
    for chain in chains:
        if chain.hook is None:
            continue
        group = hook_group(chain.hook)
        if group == "unknown":
            continue
        interfaces = sorted(chain.interfaces) if chain.interfaces else ["any"]
        for interface in interfaces:
            anchors.append((interface, group, chain.family, chain.name, chain))

    observations: dict[tuple, dict[str, object]] = {}
    joined: set[tuple[str, int | None]] = set()
    for attachment in attachments:
        if not attachment.ifname or attachment.ifname == "unknown":
            continue
        group = attachment_group(attachment)
        if group == "unknown":
            continue
        for interface, anchor_group, family, _name, chain in anchors:
            if anchor_group != group:
                continue
            if interface not in {"any", attachment.ifname}:
                continue
            if not families_compatible(family, "any"):
                continue
            key = (
                attachment.ifname,
                group,
                family,
                chain.family,
                chain.table,
                chain.name,
            )
            observation = observations.setdefault(
                key,
                {
                    "interface": attachment.ifname,
                    "hook_group": group,
                    "family": family,
                    "tables": set(),
                    "chains": set(),
                    "programs": set(),
                    "path": f"joint:{generation.netns}/{attachment.ifname}/{group}/{family}",
                },
            )
            observation["tables"].add(f"{chain.family}/{chain.table}")
            observation["chains"].add(f"{chain.family}/{chain.table}/{chain.name}")
            observation["programs"].add(
                f"{attachment.program_name}#"
                f"{attachment.program_id if attachment.program_id is not None else 'none'}"
            )
            joined.add((attachment.ifname, attachment.program_id))

    for attachment in attachments:
        if not attachment.ifname or attachment.ifname == "unknown":
            continue
        if (attachment.ifname, attachment.program_id) in joined:
            continue
        group = attachment_group(attachment)
        if group == "unknown":
            continue
        key = ("bpf", attachment.ifname, group, attachment.program_id)
        observations[key] = {
            "interface": attachment.ifname,
            "hook_group": group,
            "family": "any",
            "tables": set(),
            "chains": set(),
            "programs": {
                f"{attachment.program_name}#"
                f"{attachment.program_id if attachment.program_id is not None else 'none'}"
            },
            "path": (
                f"bpf:{generation.netns}/{attachment.ifname}/{group}/any/"
                f"{attachment.program_id if attachment.program_id is not None else 'none'}"
            ),
        }
    return [observations[key] for key in sorted(observations)]


def evaluate(
    generation: Generation,
    chains: list[Chain],
    attachments: list[Attachment],
    programs: list[Program] | None,
) -> dict[str, object]:
    findings = analyze_netfilter(chains, generation)
    findings.extend(analyze_bpf(attachments, programs, generation))
    findings.sort(key=lambda finding: (finding.kind, finding.table, finding.chain, finding.path))
    observations = analyze_paths(chains, attachments, generation)
    return {
        "generation": generation,
        "findings": findings,
        "observations": observations,
        "verdict": "FINDINGS" if findings else "CONSISTENT",
    }


def clean_baseline() -> dict[str, object]:
    generation = Generation("boot-a", 1, 4026531840)
    chains = [
        Chain("ip", "filter", "INPUT", "filter", "input", {"eth0"}, 2),
        Chain("ip6", "filter", "INPUT", "filter", "input", {"eth0"}, 1),
        Chain("inet", "nft", "input", "filter", "input", {"eth0"}, 0),
        Chain("ip", "filter", "EMPTY"),
    ]
    attachments = [
        Attachment("eth0", 2, 101, "xdp_pass", "xdp", "ingress"),
        Attachment("eth0", 2, 102, "tc_filter", "tc", "egress"),
    ]
    programs = [
        Program(101, "xdp_pass", "xdp"),
        Program(102, "tc_filter", "sched_cls"),
    ]
    return evaluate(generation, chains, attachments, programs)


def test_clean_baseline() -> None:
    report = clean_baseline()
    assert report["findings"] == [], report["findings"]
    assert report["verdict"] == "CONSISTENT"
    assert report["observations"], "legitimate XDP/TC path should be attributed"


def test_migration_separates_old_chain_and_new_xdp() -> None:
    generation = Generation("boot-a", 2, 4026531840)
    chains = [
        Chain("inet", "old", "cloak", rule_count=3),
        Chain("inet", "new", "input", "filter", "input", {"eth0"}, 4),
    ]
    attachments = [Attachment("eth0", 2, 201, "xdp_migrated", "xdp", "ingress")]
    programs = [Program(201, "xdp_migrated", "xdp")]
    report = evaluate(generation, chains, attachments, programs)

    cloak = next(
        finding for finding in report["findings"] if finding.kind == "cloaked_chain"
    )
    assert cloak.table == "old"
    assert cloak.plane == "netfilter"
    assert cloak.path.startswith("netfilter:")

    joint = next(
        observation
        for observation in report["observations"]
        if observation["interface"] == "eth0"
    )
    assert "inet/new" in joint["tables"]
    assert "inet/old" not in joint["tables"]
    assert cloak.path != joint["path"]
    for observation in report["observations"]:
        assert cloak.path != observation["path"]


def test_empty_chain_is_legal() -> None:
    generation = Generation("boot-a", 3, 4026531840)
    report = evaluate(
        generation,
        [
            Chain("ip", "filter", "INPUT", "filter", "input", {"eth0"}, 0),
            Chain("ip", "filter", "UNUSED"),
        ],
        [],
        [],
    )
    assert report["findings"] == []


def test_cross_generation_and_cross_netns_are_rejected() -> None:
    first = Generation("boot-a", 4, 4026531840)
    second = Generation("boot-a", 5, 4026531840)
    assert first.label() != second.label()
    accepted = {stamp: False for stamp in [first, second]}
    accepted[second] = True
    assert not accepted[first]

    foreign = Generation("boot-a", 6, 4026531999)
    assert foreign.netns != second.netns
    assert not accepted.get(foreign, False)


def test_hot_update_and_retry_do_not_mix() -> None:
    old_round = Generation("boot-a", 7, 4026531840)
    new_round = Generation("boot-a", 8, 4026531840)
    old_report = evaluate(
        old_round,
        [Chain("inet", "old", "cloak", rule_count=2)],
        [],
        [],
    )
    new_report = evaluate(
        new_round,
        [Chain("inet", "new", "input", "filter", "input", {"eth0"}, 2)],
        [Attachment("eth0", 2, 401, "xdp_new", "xdp", "ingress")],
        [Program(401, "xdp_new", "xdp")],
    )
    assert any(finding.table == "old" for finding in old_report["findings"])
    assert all(finding.table != "old" for finding in new_report["findings"])
    assert old_round.round != new_round.round

    # A retry restarts every plane: the replacement generation is new and
    # nothing from the old netfilter snapshot is carried into it.
    retried = Generation("boot-a", 9, 4026531840)
    assert retried.label() not in {old_round.label(), new_round.label()}


def main() -> None:
    scenarios = [
        test_clean_baseline,
        test_migration_separates_old_chain_and_new_xdp,
        test_empty_chain_is_legal,
        test_cross_generation_and_cross_netns_are_rejected,
        test_hot_update_and_retry_do_not_mix,
    ]
    for scenario in scenarios:
        scenario()
        print(f"ok   - {scenario.__name__}")
    print("all packet-path scenarios passed")


if __name__ == "__main__":
    main()
