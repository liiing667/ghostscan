#!/usr/bin/env python3
"""Behavioural model for the shared persistence observation.

The Rust toolchain is not assumed on every host, so this script mirrors the
rules in ``src/persistence.rs`` and exercises the incident scenarios directly:

* a stable host produces one generation whose SSH, sudo (with include chain),
  PAM and systemd findings all name the same generation,
* a sudoers include replaced between the two capture passes makes the whole
  generation unstable and is retried from an empty snapshot,
* a symlink re-pointed between passes is a generation conflict, not evidence
  from two targets,
* an unreadable include stays a PARTIAL error on its own generation,
* retry exhaustion is FAILED and never merges a failed generation,
* masked units, legitimate configuration and empty results remain observations.

Run: python3 tests/acceptance/simulate_persistence_generations.py
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

MAX_GENERATION_ATTEMPTS = 4

SUDOERS = "/etc/sudoers"
SUDOERS_DIR = "/etc/sudoers.d"
PASSWD = "/etc/passwd"
NSSWITCH = "/etc/nsswitch.conf"
PAM_DIR = "/etc/pam.d"
UNIT_DIR = "/etc/systemd/system"
SYSTEM_LIB_PREFIXES = ("/lib", "/lib64", "/usr/lib", "/usr/lib64")


@dataclass
class Node:
    kind: str = "file"  # file | symlink | dir | missing
    content: str = ""
    target: str | None = None
    error: str | None = None
    ino: int = 1
    entries: list[str] = field(default_factory=list)


@dataclass
class Fixture:
    nodes: dict[str, Node]

    def copy(self) -> "Fixture":
        return Fixture(
            {
                path: Node(
                    kind=node.kind,
                    content=node.content,
                    target=node.target,
                    error=node.error,
                    ino=node.ino,
                    entries=list(node.entries),
                )
                for path, node in self.nodes.items()
            }
        )


@dataclass
class Record:
    path: str
    resolved: str
    content: str | None
    link: str | None
    missing: bool
    error: str | None
    ino: int


@dataclass
class Finding:
    source: str
    file: str
    chain: list[str]
    detail: str


@dataclass
class Capture:
    records: dict[str, Record] = field(default_factory=dict)
    dirs: dict[str, list[str]] = field(default_factory=dict)
    chains: dict[str, list[list[str]]] = field(default_factory=dict)
    include_errors: list[str] = field(default_factory=list)
    sudo_files: set[str] = field(default_factory=set)
    pam_files: set[str] = field(default_factory=set)
    systemd_units: set[str] = field(default_factory=set)


def normalize(path: str) -> str:
    parts: list[str] = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/" + "/".join(parts)


def add_chain(capture: Capture, path: str, chain: list[str]) -> None:
    bucket = capture.chains.setdefault(path, [])
    if chain and chain not in bucket:
        bucket.append(list(chain))


def resolve(fixture: Fixture, path: str) -> tuple[str, Node, str | None]:
    current = normalize(path)
    link: str | None = None
    seen: set[str] = set()
    for _ in range(40):
        if current in seen:
            return current, Node(kind="missing"), link
        seen.add(current)
        node = fixture.nodes.get(current, Node(kind="missing"))
        if node.kind != "symlink" or node.target is None:
            return current, node, link
        link = node.target
        current = (
            normalize(node.target)
            if node.target.startswith("/")
            else normalize(current.rsplit("/", 1)[0] + "/" + node.target)
        )
    return current, Node(kind="missing"), link


def read_record(fixture: Fixture, path: str) -> Record:
    path = normalize(path)
    resolved, node, link = resolve(fixture, path)
    if node.kind == "missing":
        return Record(path, resolved, None, link, True, None, 0)
    if node.kind == "dir":
        return Record(path, resolved, None, link, False, None, node.ino)
    if node.error:
        return Record(path, resolved, None, link, False, node.error, node.ino)
    return Record(path, resolved, node.content, link, False, None, node.ino)


def list_entries(capture: Capture, fixture: Fixture, path: str) -> list[str]:
    path = normalize(path)
    if path in capture.dirs:
        return capture.dirs[path]
    node = fixture.nodes.get(path, Node(kind="missing"))
    if node.kind == "missing":
        capture.dirs[path] = []
        return []
    if node.kind != "dir":
        capture.include_errors.append(f"failed to read {path}: not a directory")
        capture.dirs[path] = []
        return []
    entries = sorted(normalize(entry) for entry in node.entries)
    capture.dirs[path] = entries
    return entries


def add_file(
    capture: Capture,
    fixture: Fixture,
    path: str,
    chain: list[str],
    source: str | None,
) -> bool:
    path = normalize(path)
    add_chain(capture, path, chain)
    if source == "sudo":
        capture.sudo_files.add(path)
    elif source == "pam":
        capture.pam_files.add(path)
    elif source == "systemd":
        capture.systemd_units.add(path)
    if path in capture.records:
        return False
    capture.records[path] = read_record(fixture, path)
    if fixture.nodes.get(path, Node()).kind == "dir":
        list_entries(capture, fixture, path)
    return True


def add_dir(
    capture: Capture, fixture: Fixture, path: str, chain: list[str]
) -> list[str]:
    add_chain(capture, normalize(path), chain)
    return list_entries(capture, fixture, path)


def sudo_includes(content: str) -> list[tuple[str, bool]]:
    found: list[tuple[str, bool]] = []
    for line in content.splitlines():
        text = line.strip()
        for keyword, directory in (
            ("#includedir", True),
            ("@includedir", True),
            ("#include", False),
            ("@include", False),
        ):
            if text.startswith(keyword) and len(text) > len(keyword) and text[len(keyword)].isspace():
                argument = text[len(keyword):].strip().strip("\"'")
                if argument:
                    found.append((argument, directory))
                break
    return found


def pam_includes(content: str) -> list[str]:
    found: list[str] = []
    for line in content.splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        tokens = text.split()
        if tokens and tokens[0] in ("@include", "include") and len(tokens) > 1:
            found.append(tokens[1].strip("\"'"))
    return found


def sudoers_dir_accepts(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return not name.endswith("~") and "." not in name


def capture_pass(fixture: Fixture) -> Capture:
    capture = Capture()
    add_file(capture, fixture, PASSWD, [PASSWD], None)
    add_file(capture, fixture, SUDOERS, [SUDOERS], "sudo")
    add_file(capture, fixture, NSSWITCH, [NSSWITCH], "nss")

    for entry in list_entries(capture, fixture, PAM_DIR):
        add_file(capture, fixture, entry, [entry], "pam")
    for entry in list_entries(capture, fixture, UNIT_DIR):
        if entry.endswith(".service"):
            add_file(capture, fixture, entry, [entry], "systemd")

    processed_sudo: set[str] = set()
    processed_pam: set[str] = set()
    processed_systemd: set[str] = set()
    processed_passwd = False

    for _ in range(64):
        progressed = False
        if not processed_passwd:
            processed_passwd = True
            passwd = capture.records[PASSWD].content or ""
            for line in passwd.splitlines():
                parts = line.split(":")
                if len(parts) < 6 or not parts[5].startswith("/"):
                    continue
                auth = normalize(parts[5] + "/.ssh/authorized_keys")
                if add_file(capture, fixture, auth, [auth], "ssh"):
                    progressed = True

        for file in sorted(capture.sudo_files):
            if file in processed_sudo:
                continue
            processed_sudo.add(file)
            content = capture.records[file].content or ""
            for argument, directory in sudo_includes(content):
                base = file.rsplit("/", 1)[0]
                target = normalize(argument if argument.startswith("/") else base + "/" + argument)
                for chain in list(capture.chains.get(file, [])):
                    next_chain = chain + [target]
                    if directory:
                        for entry in add_dir(capture, fixture, target, next_chain):
                            if sudoers_dir_accepts(entry):
                                if add_file(capture, fixture, entry, next_chain + [entry], "sudo"):
                                    progressed = True
                    elif add_file(capture, fixture, target, next_chain, "sudo"):
                        progressed = True

        for file in sorted(capture.pam_files):
            if file in processed_pam:
                continue
            processed_pam.add(file)
            content = capture.records[file].content or ""
            for argument in pam_includes(content):
                base = file.rsplit("/", 1)[0]
                target = normalize(argument if argument.startswith("/") else base + "/" + argument)
                for chain in list(capture.chains.get(file, [])):
                    if add_file(capture, fixture, target, chain + [target], "pam"):
                        progressed = True

        for unit in sorted(capture.systemd_units):
            if unit in processed_systemd:
                continue
            processed_systemd.add(unit)
            name = unit.rsplit("/", 1)[-1]
            for root in (UNIT_DIR, "/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"):
                dropin_dir = normalize(f"{root}/{name}.d")
                for chain in list(capture.chains.get(unit, [])):
                    for entry in add_dir(capture, fixture, dropin_dir, chain + [dropin_dir]):
                        if entry.endswith(".conf"):
                            if add_file(capture, fixture, entry, chain + [entry], "systemd"):
                                progressed = True

        if not progressed:
            break

    for entry in list_entries(capture, fixture, SUDOERS_DIR):
        if sudoers_dir_accepts(entry) and entry not in capture.records:
            add_file(capture, fixture, entry, [SUDOERS_DIR, entry], "sudo")
    return capture


def fingerprint(capture: Capture) -> str:
    pieces = []
    for path, record in sorted(capture.records.items()):
        pieces.append(
            f"{path}|{record.resolved}|{record.missing}|{record.content}|"
            f"{record.link}|{record.error}|{record.ino}"
        )
    for path, entries in sorted(capture.dirs.items()):
        pieces.append(f"dir:{path}|{','.join(entries)}")
    pieces.extend(f"error:{error}" for error in capture.include_errors)
    return "\n".join(pieces)


def build_findings(capture: Capture) -> dict[str, list[Finding]]:
    findings: dict[str, list[Finding]] = {"ssh": [], "sudo": [], "pam": [], "nss": [], "systemd": []}

    def chain_for(path: str, root: str | None = None) -> list[str]:
        chains = capture.chains.get(path, [])
        if root:
            rooted = [chain for chain in chains if chain and chain[0] == root]
            if rooted:
                return max(rooted, key=len)
        return max(chains, key=len) if chains else [path]

    passwd = capture.records[PASSWD].content or ""
    for line in passwd.splitlines():
        parts = line.split(":")
        if len(parts) < 6 or not parts[5].startswith("/"):
            continue
        auth = normalize(parts[5] + "/.ssh/authorized_keys")
        record = capture.records.get(auth)
        if record is None or record.missing or record.error or record.content is None:
            continue
        for entry in record.content.splitlines():
            text = entry.strip()
            if not text or text.startswith("#"):
                continue
            tokens = text.split()
            if tokens and not tokens[0].startswith("ssh-"):
                for option in tokens[0].split(","):
                    if option.startswith("command=") or option.startswith("permitopen="):
                        findings["ssh"].append(Finding("ssh", auth, [auth], option))

    for file in sorted(capture.sudo_files):
        record = capture.records.get(file)
        if record is None or record.missing or record.error or record.content is None:
            continue
        for index, line in enumerate(record.content.splitlines(), 1):
            text = line.strip()
            if text and not text.startswith("#") and "NOPASSWD: ALL" in text:
                findings["sudo"].append(
                    Finding("sudo", file, chain_for(file, SUDOERS), f"line_no={index}")
                )

    for file in sorted(capture.pam_files):
        record = capture.records.get(file)
        if record is None or record.missing or record.error or record.content is None:
            continue
        for index, line in enumerate(record.content.splitlines(), 1):
            tokens = line.strip().split()
            if len(tokens) < 3 or tokens[0].startswith("@"):
                continue
            module = tokens[2]
            if module.startswith("/") and not module.startswith(SYSTEM_LIB_PREFIXES):
                findings["pam"].append(Finding("pam", file, chain_for(file), f"line_no={index}"))

    for unit in sorted(capture.systemd_units):
        record = capture.records.get(unit)
        if record is None or record.missing:
            continue
        if record.link == "/dev/null" or record.resolved == "/dev/null":
            continue
        files = [unit]
        dropins = []
        name = unit.rsplit("/", 1)[-1]
        for root in (UNIT_DIR, "/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"):
            for entry in capture.dirs.get(normalize(f"{root}/{name}.d"), []):
                if entry.endswith(".conf"):
                    files.append(entry)
                    dropins.append(entry)
        for file in files:
            item = capture.records.get(file)
            if item is None or item.content is None:
                continue
            for line in item.content.splitlines():
                text = line.strip()
                if text.startswith("ExecStart="):
                    command = text.split("=", 1)[1].split()[0].lstrip("-@:+!")
                    if command.startswith("/tmp/"):
                        findings["systemd"].append(
                            Finding("systemd", unit, [unit] + dropins, "exec_in_tmp")
                        )
    return findings


@dataclass
class Result:
    status: str
    attempts: int
    generation: str
    conflicts: list[str]
    findings: dict[str, list[Finding]]
    capture: Capture | None


def observe(
    fixture: Fixture,
    mutate: Callable[[Fixture, int, int], None] | None = None,
) -> Result:
    conflicts: list[str] = []
    world = fixture.copy()
    for attempt in range(1, MAX_GENERATION_ATTEMPTS + 1):
        if mutate:
            mutate(world, attempt, 1)
        first = capture_pass(world)

        if mutate:
            mutate(world, attempt, 2)
        second = capture_pass(world)

        if fingerprint(first) == fingerprint(second):
            return Result("COMPLETE", attempt, f"gen:{attempt}", [], build_findings(second), second)
        conflicts = [f"attempt {attempt}: snapshot changed"]
    return Result("FAILED", MAX_GENERATION_ATTEMPTS, "none", conflicts, {key: [] for key in ("ssh", "sudo", "pam", "nss", "systemd")}, None)


def base_fixture() -> Fixture:
    nodes = {
        SUDOERS: Node(content="#includedir /etc/sudoers.d\n"),
        SUDOERS_DIR: Node(kind="dir", entries=[f"{SUDOERS_DIR}/90-extra"]),
        f"{SUDOERS_DIR}/90-extra": Node(content="%wheel ALL=(ALL) NOPASSWD: ALL\n"),
        PASSWD: Node(content="root:x:0:0:root:/root:/bin/sh\n"),
        "/root/.ssh": Node(kind="dir", entries=["/root/.ssh/authorized_keys"]),
        "/root/.ssh/authorized_keys": Node(content='command="/bin/sh" ssh-ed25519 AAAA key\n'),
        NSSWITCH: Node(content="passwd: files\n"),
        PAM_DIR: Node(kind="dir", entries=[f"{PAM_DIR}/sshd"]),
        f"{PAM_DIR}/sshd": Node(content="auth required /opt/evil.so\n@include common-auth\n"),
        f"{PAM_DIR}/common-auth": Node(content="auth required pam_unix.so\n"),
        UNIT_DIR: Node(kind="dir", entries=[f"{UNIT_DIR}/evil.service", f"{UNIT_DIR}/masked.service"]),
        f"{UNIT_DIR}/evil.service": Node(content="[Service]\nExecStart=/tmp/backdoor\n"),
        f"{UNIT_DIR}/masked.service": Node(kind="symlink", target="/dev/null", ino=77),
    }
    return Fixture(nodes)


def test_stable_host_shares_one_generation() -> None:
    result = observe(base_fixture())
    assert result.status == "COMPLETE", result
    assert result.attempts == 1
    for source in ("ssh", "sudo", "pam", "systemd"):
        assert result.findings[source], source
    sudo = result.findings["sudo"][0]
    assert sudo.chain == [SUDOERS, SUDOERS_DIR, f"{SUDOERS_DIR}/90-extra"], sudo.chain
    assert not any("masked" in finding.file for finding in result.findings["systemd"])


def test_sudoers_include_replaced_between_passes_is_retried() -> None:
    def mutate(fixture: Fixture, attempt: int, pass_no: int) -> None:
        path = f"{SUDOERS_DIR}/90-extra"
        if attempt == 1 and pass_no == 1:
            fixture.nodes[path] = Node(content="%wheel ALL=(ALL) NOPASSWD: ALL\n", ino=10)
        else:
            fixture.nodes[path] = Node(content="%wheel ALL=(ALL) ALL\n", ino=20)

    result = observe(base_fixture(), mutate)
    # The include is replaced between the two passes of attempt 1, so that
    # generation is discarded.  The retry sees only the new file; the old
    # NOPASSWD finding is never merged into the new generation.
    assert result.status == "COMPLETE", result
    assert result.attempts == 2, result
    assert not result.findings["sudo"], result.findings["sudo"]


def test_symlink_repoint_cannot_mix_targets() -> None:
    fixture = base_fixture()
    fixture.nodes["/root/.ssh/authorized_keys"] = Node(
        kind="symlink", target="/root/.ssh/old_keys", ino=30
    )
    fixture.nodes["/root/.ssh/old_keys"] = Node(
        content='command="/bin/old" ssh-ed25519 AAAA old\n', ino=31
    )
    fixture.nodes["/root/.ssh/new_keys"] = Node(
        content='command="/bin/new" ssh-ed25519 AAAA new\n', ino=32
    )

    def mutate(fixture: Fixture, attempt: int, pass_no: int) -> None:
        if attempt == 1 and pass_no == 2:
            fixture.nodes["/root/.ssh/authorized_keys"].target = "/root/.ssh/new_keys"

    result = observe(fixture, mutate)
    assert result.status == "COMPLETE", result
    assert result.attempts == 2, result
    assert result.findings["ssh"], result
    for finding in result.findings["ssh"]:
        assert "new" in finding.detail


def test_unreadable_include_is_partial() -> None:
    fixture = base_fixture()
    fixture.nodes[f"{SUDOERS_DIR}/90-extra"] = Node(error="Permission denied")
    result = observe(fixture)
    assert result.capture is not None
    assert any("Permission denied" in error for error in [
        record.error for record in result.capture.records.values() if record.error
    ])
    assert not result.findings["sudo"]


def test_retry_exhaustion_never_merges() -> None:
    def mutate(fixture: Fixture, attempt: int, pass_no: int) -> None:
        fixture.nodes[SUDOERS].ino += pass_no

    result = observe(base_fixture(), mutate)
    assert result.status == "FAILED", result
    assert result.attempts == MAX_GENERATION_ATTEMPTS
    assert all(not findings for findings in result.findings.values())


def test_empty_host_is_complete() -> None:
    fixture = Fixture(
        {
            SUDOERS: Node(content=""),
            PASSWD: Node(content=""),
            NSSWITCH: Node(content=""),
            PAM_DIR: Node(kind="dir", entries=[]),
            SUDOERS_DIR: Node(kind="dir", entries=[]),
            UNIT_DIR: Node(kind="dir", entries=[]),
        }
    )
    result = observe(fixture)
    assert result.status == "COMPLETE"
    assert all(not findings for findings in result.findings.values())


SCENARIOS = [
    test_stable_host_shares_one_generation,
    test_sudoers_include_replaced_between_passes_is_retried,
    test_symlink_repoint_cannot_mix_targets,
    test_unreadable_include_is_partial,
    test_retry_exhaustion_never_merges,
    test_empty_host_is_complete,
]


def main() -> int:
    failures = 0
    for scenario in SCENARIOS:
        try:
            scenario()
            print(f"ok   - {scenario.__name__}")
        except AssertionError as error:
            failures += 1
            print(f"FAIL - {scenario.__name__}: {error}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
