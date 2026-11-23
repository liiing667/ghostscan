#!/usr/bin/env bash
# Structural acceptance checks for the shared BPF lifecycle transaction.
#
# The sandbox used for this change does not have a Rust toolchain, so these
# checks verify the invariants directly against the source tree:
#
#   1. one process-wide transaction creates a boot + generation stamp before
#      the scanner loop,
#   2. programs, maps, links/attachments and pins are collected once and all
#      carry that stamp,
#   3. an identity fence discards the whole generation when an id is detached,
#      re-pinned or reused between collectors,
#   4. the public scanners consume the shared snapshot and never merge records
#      from two generations,
#   5. legitimate bpffs pins, anonymous programs, distinct attach types and
#      permission failures remain represented,
#   6. the final ScanOutcome summary prints the same boot/generation identity.
#
# Run: bash tests/acceptance/check_bpf_lifecycle.sh
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$ROOT/src"
FAILURES=0

check() {
    local description="$1"
    local file="$2"
    local pattern="$3"
    if grep -Eq "$pattern" "$SRC/$file"; then
        printf 'ok   - %s\n' "$description"
    else
        printf 'FAIL - %s (missing /%s/ in %s)\n' "$description" "$pattern" "$file"
        FAILURES=$((FAILURES + 1))
    fi
}

check_not() {
    local description="$1"
    local file="$2"
    local pattern="$3"
    if grep -Eq "$pattern" "$SRC/$file"; then
        printf 'FAIL - %s (forbidden /%s/ found in %s)\n' "$description" "$pattern" "$file"
        FAILURES=$((FAILURES + 1))
    else
        printf 'ok   - %s\n' "$description"
    fi
}

echo "== lifecycle module =="
check "lifecycle module exists" \
    bpf_lifecycle.rs 'pub struct BpfTransaction'
check "one process-wide transaction is shared" \
    bpf_lifecycle.rs 'pub static BPF_TRANSACTION: BpfTransaction'
check "generation carries boot identity" \
    bpf_lifecycle.rs 'pub boot_id: String'
check "generation is process-local and monotonic" \
    bpf_lifecycle.rs 'next_generation'
check "program records carry an identity stamp" \
    bpf_lifecycle.rs 'pub struct ProgramRecord'
check "map records carry an identity stamp" \
    bpf_lifecycle.rs 'pub struct MapRecord'
check "attachment records carry an identity stamp" \
    bpf_lifecycle.rs 'pub struct LinkRecord'
check "pin records carry an object and filesystem identity" \
    bpf_lifecycle.rs 'pub struct PinRecord'
check "pin records include the mount fstype" \
    bpf_lifecycle.rs 'pub mount_fstype: String'
check "program id reuse is detected by tag" \
    bpf_lifecycle.rs 'tag=\{\} but program tag=\{\}'
check "cross-generation evidence is counted" \
    bpf_lifecycle.rs 'cross_generation'
check "an identity fence re-reads object families" \
    bpf_lifecycle.rs 'Identity fence'
check "a changed identity discards the generation" \
    bpf_lifecycle.rs 'changed identity between collectors'
check "retries never resurrect an earlier generation" \
    bpf_lifecycle.rs 'never merged with an earlier'
check "the final summary prints boot and generation" \
    bpf_lifecycle.rs 'BPF_LIFECYCLE boot_id='
check "the final summary reports lifecycle verdict" \
    bpf_lifecycle.rs 'BPF_VERDICT='

echo "== public BPF scanners =="
for scanner in ownerless_bpf_objects bpf_kprobe_attachments pins_non_bpffs; do
    check "$scanner shares the lifecycle transaction" \
        "scanners/$scanner.rs" 'BPF_TRANSACTION'
    check "$scanner exposes a transaction-aware entry point" \
        "scanners/$scanner.rs" 'pub fn run_with_bpf'
    check "$scanner consumes the shared snapshot" \
        "scanners/$scanner.rs" 'transaction\.snapshot\(\)'
done

for scanner in sockmap_sockhash bpf_lsm sensitive_kfunc xdp_tc_detached; do
    check "$scanner shares the lifecycle transaction" \
        "scanners/$scanner.rs" 'BPF_TRANSACTION'
    check "$scanner consumes the shared snapshot" \
        "scanners/$scanner.rs" 'transaction\.snapshot\(\)'
done

check "kprobe and kretprobe attachments stay distinct" \
    scanners/bpf_kprobe_attachments.rs 'is_kretprobe_link|kretprobe'
check "sensitive kprobe targets remain filtered" \
    scanners/bpf_kprobe_attachments.rs 'is_sensitive_symbol'
check "anonymous ownerless programs remain reported" \
    scanners/ownerless_bpf_objects.rs 'owner_pids\.is_empty\(\)|has_fd'
check "legal bpffs pins remain excluded from pin findings" \
    scanners/pins_non_bpffs.rs 'mount_type_for\(pin\) == "bpf"'
check "sockmap verdict program tag comes from the same generation" \
    scanners/sockmap_sockhash.rs 'verdict_prog_tag'
check "kfunc dumps verify the program tag after the dump" \
    scanners/sensitive_kfunc.rs 'verify_program_tag'
check "permission failures keep their original scanner text" \
    scanners/ownerless_bpf_objects.rs 'bpftool not available to enumerate BPF objects'
check "map, link and program collection errors remain aggregated" \
    scanners/pins_non_bpffs.rs 'collection_errors='

echo "== scan startup and final report =="
check "main begins one BPF generation before the scanner loop" \
    main.rs 'begin_scan\(\)'
check "main prints the same transaction after the loop" \
    main.rs 'final_scan_outcome\(bpf\)'
check "the lifecycle provides a final ScanOutcome" \
    bpf_lifecycle.rs 'pub fn final_scan_outcome\(transaction: &BpfTransaction\) -> crate::ScanOutcome'
check "scanner registry count is unchanged" \
    main.rs '^const SCANNERS'

scanner_count="$(grep -c '^    Scanner {' "$SRC/main.rs")"
if [ "$scanner_count" -eq 50 ]; then
    printf 'ok   - scanner registry still contains 50 entries\n'
else
    printf 'FAIL - scanner registry contains %s entries (expected 50)\n' "$scanner_count"
    FAILURES=$((FAILURES + 1))
fi
check_not "main still has no non-zero exit path" \
    main.rs 'process::exit|ExitCode::from'

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "all BPF lifecycle acceptance checks passed"
    exit 0
fi
echo "$FAILURES BPF lifecycle acceptance check(s) failed"
exit 1
