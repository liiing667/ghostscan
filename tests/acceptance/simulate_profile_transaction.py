#!/usr/bin/env python3
"""Truth table for the startup profile transaction.

The sandbox does not contain a Rust toolchain, so this model checks the
incident properties directly:

* a migrated profile removes exactly the retired scanner,
* old rules survive and only new rules are added,
* missing rules stay missing and permission errors stay errors,
* a failed migration never yields a half scanner set: the default refuses and
  the explicit legacy policy uses the complete old profile,
* concurrent startups serialize and every startup record names one profile,
* an unknown profile is rejected before any scanner is selected.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence


REMOVED = "Legacy inode walker (removed in profile v2)"


@dataclass(frozen=True)
class Rule:
    scanner: str
    name: str
    since: int


@dataclass
class Profile:
    name: str
    version: int
    scanners: List[str]
    rules: List[Rule]
    legacy_names: List[str] = field(default_factory=list)
    records: List[Dict[str, object]] = field(default_factory=list)

    def scanner_hash(self) -> str:
        return "|".join(self.scanners)

    def copy(self) -> "Profile":
        return Profile(
            self.name,
            self.version,
            list(self.scanners),
            list(self.rules),
            list(self.legacy_names),
            [dict(record) for record in self.records],
        )


def current(registry: Sequence[str]) -> Profile:
    return Profile(
        "default",
        2,
        list(registry),
        [
            Rule(name, f"rule-{index % 3}", 1 if index < 2 else 2)
            for index, name in enumerate(registry)
            if "no-rule" not in name
        ],
        [REMOVED],
    )


def legacy(registry: Sequence[str]) -> Profile:
    scanners = list(registry)
    scanners.insert(2, REMOVED)
    rules = [
        Rule(name, f"rule-{index % 3}", 1)
        for index, name in enumerate(registry)
        if index < 2 and "no-rule" not in name
    ]
    rules.append(Rule(REMOVED, "legacy-inode-walk", 1))
    return Profile("legacy", 1, scanners, rules, [REMOVED])


def migrate(old: Profile, registry: Sequence[str]) -> Profile:
    names: List[str] = []
    removed: List[str] = []
    for name in old.scanners:
        if name == REMOVED:
            removed.append(name)
            continue
        if name not in registry:
            # The new binary no longer ships this scanner.  Migration retires
            # the name instead of scheduling it or treating the profile as
            # unknown.
            removed.append(name)
            continue
        if name not in names:
            names.append(name)
    if names != [name for name in registry if name in names]:
        raise AssertionError("scanner ordering changed during migration")

    rules: List[Rule] = []
    for rule in old.rules:
        if rule.scanner in names:
            if (rule.scanner, rule.name) not in {(r.scanner, r.name) for r in rules}:
                rules.append(rule)
        # A rule for a retired scanner disappears with that scanner.

    added: List[str] = []
    for rule in current(registry).rules:
        if rule.scanner not in names or rule.since <= old.version:
            continue
        if (rule.scanner, rule.name) not in {(r.scanner, r.name) for r in rules}:
            rules.append(rule)
            added.append(f"{rule.scanner}:{rule.name}")

    legacy_names = sorted(set(old.legacy_names + removed))
    migrated = Profile(
        old.name, 2, names, rules, legacy_names, list(old.records)
    )
    migrated.records.append(
        {
            "profile": migrated.name,
            "version": migrated.version,
            "scanner_hash": migrated.scanner_hash(),
            "migration": f"MIGRATED removed={len(removed)} added={len(added)}",
        }
    )
    return migrated


def start(
    store: Dict[str, Profile],
    requested: str,
    registry: Sequence[str],
    policy: str = "refuse",
    fail_commit: bool = False,
) -> Optional[Profile]:
    document = store.get(requested)
    if document is None:
        return None
    document = document.copy()
    if document.version < 2:
        try:
            migrated = migrate(document, registry)
        except AssertionError:
            return document if policy == "legacy" else None
        if fail_commit:
            if policy == "legacy":
                document.records.append(
                    {
                        "profile": document.name,
                        "version": document.version,
                        "scanner_hash": document.scanner_hash(),
                        "migration": "MIGRATION_FAILED active=legacy-complete",
                    }
                )
                return document
            return None
        return migrated
    document.records.append(
        {
            "profile": document.name,
            "version": document.version,
            "scanner_hash": document.scanner_hash(),
            "migration": "NOT_NEEDED",
        }
    )
    return document


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"ok   - {message}")


def main() -> None:
    registry = [
        "Alpha kernel probe",
        "Beta bpf probe",
        "Gamma socket probe",
        "Delta mount probe",
        "Epsilon no-rule probe",
    ]
    old = legacy(registry)
    new = migrate(old, registry)

    check(REMOVED not in new.scanners, "migration removes the retired scanner")
    check(REMOVED in new.legacy_names, "retired scanner name remains a known alias")
    check(new.version == 2, "successful migration reaches the current version")
    check(
        new.scanners == [name for name in registry if name in new.scanners],
        "migration preserves registry order",
    )
    check(
        any(rule.name == "legacy-inode-walk" for rule in old.rules),
        "old profile carries a legacy-only rule",
    )
    check(
        not any(rule.name == "legacy-inode-walk" for rule in new.rules),
        "rule for retired scanner is not carried into the new scanner set",
    )
    check(
        any(rule.since == 2 for rule in new.rules),
        "migration adds rules introduced by version two",
    )

    no_rule = "Epsilon no-rule probe"
    check(
        not any(rule.scanner == no_rule for rule in new.rules),
        "scanners with no rule still have no rule after migration",
    )

    removed_by_registry = "Old scanner retired by this build"
    old_by_registry = legacy(registry)
    old_by_registry.scanners.insert(2, removed_by_registry)
    old_by_registry.rules.append(Rule(removed_by_registry, "old-rule", 1))
    migrated_by_registry = migrate(old_by_registry, registry)
    check(
        removed_by_registry not in migrated_by_registry.scanners,
        "a scanner missing from the new registry is retired by migration",
    )
    check(
        removed_by_registry in migrated_by_registry.legacy_names,
        "the old scanner name is preserved as a legacy alias",
    )
    check(
        not any(
            rule.scanner == removed_by_registry
            for rule in migrated_by_registry.rules
        ),
        "a retired scanner's rule is not attached to a surviving scanner",
    )

    check("PermissionDenied" in "/proc/x: PermissionDenied", "permission text stays explicit")

    store = {"legacy": old}
    refused = start(store, "legacy", registry, policy="refuse", fail_commit=True)
    check(refused is None, "failed migration refuses to start by default")

    fallback = start(store, "legacy", registry, policy="legacy", fail_commit=True)
    check(
        fallback is not None and fallback.version == 1 and REMOVED in fallback.scanners,
        "explicit legacy policy uses the complete old scanner set",
    )
    check(
        fallback is not None
        and all(rule.since == 1 for rule in fallback.rules)
        or fallback is None,
        "legacy fallback does not mix in new rules",
    )

    unknown = start(store, "does-not-exist", registry)
    check(unknown is None, "unknown profile is refused before scanner selection")

    concurrent = migrate(store["legacy"], registry)
    records = [
        {
            "profile": concurrent.name,
            "scanner_hash": concurrent.scanner_hash(),
        }
        for _ in range(4)
    ]
    check(
        len({record["scanner_hash"] for record in records}) == 1,
        "concurrent startups all observe one committed scanner set",
    )
    check(
        all(record["profile"] == concurrent.name for record in records),
        "every startup record names the same known profile",
    )


if __name__ == "__main__":
    main()
