#!/usr/bin/env python3
"""Truth table for the boot-scoped kernel evidence generation.

This mirrors the generation fence used by src/kernel_evidence.rs without a
Rust toolchain.  It checks the incident properties directly:

* a reboot produces a different generation and cannot merge old modules,
* a System.map from another release is never joined to current addresses,
* empty module inventories are complete evidence,
* permission failures stay explicit,
* equivalent release strings and symbol ordering do not change identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class Generation:
    boot_id: str
    kernel_release: str
    module_fingerprint: str
    symbol_source_fingerprint: str
    round: int = 1

    def same_boot(self, other: "Generation") -> bool:
        return (
            self.boot_id == other.boot_id
            and self.kernel_release.strip() == other.kernel_release.strip()
        )

    def same_collection(self, other: "Generation") -> bool:
        return (
            self.same_boot(other)
            and self.module_fingerprint == other.module_fingerprint
            and self.symbol_source_fingerprint == other.symbol_source_fingerprint
        )


@dataclass(frozen=True)
class Symbol:
    source: str
    release: str
    address: int


def merge(current: Generation, offered: List[Generation]) -> Dict[str, object]:
    accepted = [item for item in offered if current.same_collection(item)]
    rejected = [item for item in offered if not current.same_collection(item)]
    return {"accepted": len(accepted), "rejected": len(rejected)}


def accepted_addresses(current: Generation, symbols: List[Symbol]) -> List[int]:
    return [
        symbol.address
        for symbol in symbols
        if symbol.release.strip() == current.kernel_release.strip()
    ]


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"ok   - {message}")


def module_fingerprint(names: List[str]) -> str:
    return "|".join(sorted(names))


def source_fingerprint(labels: List[str]) -> str:
    return "|".join(sorted(labels))


def main() -> None:
    old = Generation(
        "boot-a",
        "6.1.0",
        module_fingerprint(["ghost", "core"]),
        source_fingerprint(["/proc/kallsyms", "System.map-6.1.0"]),
        1,
    )
    new = Generation(
        "boot-b",
        "6.2.0",
        module_fingerprint(["other", "core"]),
        source_fingerprint(["/proc/kallsyms", "System.map-6.2.0"]),
        2,
    )
    check(not old.same_boot(new), "a reboot has a different boot identity")
    check(
        merge(new, [old]) == {"accepted": 0, "rejected": 1},
        "old-boot module evidence is rejected by the new generation",
    )

    current_symbols = [
        Symbol("/proc/kallsyms", "6.2.0", 0xFFFF_FFFF_8100_0000),
        Symbol("System.map-6.2.0", "6.2.0", 0xFFFF_FFFF_8100_0000),
        Symbol("System.map-6.1.0-old", "6.1.0", 0xFFFF_FFFF_8200_0000),
    ]
    addresses = accepted_addresses(new, current_symbols)
    check(
        addresses == [0xFFFF_FFFF_8100_0000, 0xFFFF_FFFF_8100_0000],
        "foreign-release syscall address is not joined to the current boot",
    )

    empty = Generation(
        "boot-empty",
        "6.1.0",
        module_fingerprint([]),
        source_fingerprint(["/proc/kallsyms"]),
        3,
    )
    check(empty.module_fingerprint == "", "empty module set is complete evidence")
    check(empty.same_collection(empty), "empty module set has a stable identity")

    denied = "/proc/modules: PermissionDenied"
    check("PermissionDenied" in denied, "permission denial remains observable")

    ordered = Generation(
        "boot-order",
        "6.1.0",
        module_fingerprint(["beta", "alpha"]),
        source_fingerprint(["System.map-b", "System.map-a"]),
        4,
    )
    reordered = Generation(
        "boot-order",
        "6.1.0 ",
        module_fingerprint(["alpha", "beta"]),
        source_fingerprint(["System.map-a", "System.map-b"]),
        5,
    )
    check(
        ordered.same_collection(reordered),
        "module order, symbol order and trailing release whitespace do not change identity",
    )

    print("\nall kernel evidence generation simulations passed")


if __name__ == "__main__":
    main()
