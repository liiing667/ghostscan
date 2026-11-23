#!/usr/bin/env bash
# Structural acceptance checks for the boot-scoped kernel evidence generation.
#
# Run: bash tests/acceptance/check_kernel_evidence_generation.sh
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$ROOT/src"
FAILURES=0

check() {
    local description="$1" file="$2" pattern="$3"
    if grep -Eq "$pattern" "$SRC/$file"; then
        printf 'ok   - %s\n' "$description"
    else
        printf 'FAIL - %s (missing /%s/ in %s)\n' "$description" "$pattern" "$file"
        FAILURES=$((FAILURES + 1))
    fi
}

check_not() {
    local description="$1" file="$2" pattern="$3"
    if grep -Eq "$pattern" "$SRC/$file"; then
        printf 'FAIL - %s (forbidden /%s/ found in %s)\n' "$description" "$pattern" "$file"
        FAILURES=$((FAILURES + 1))
    else
        printf 'ok   - %s\n' "$description"
    fi
}

echo "== collection generation =="
check "kernel evidence module exists" kernel_evidence.rs 'pub struct KernelEvidence'
check "boot id and kernel release are frozen" kernel_evidence.rs 'pub boot_id: String'
check "kernel release is part of the generation" kernel_evidence.rs 'pub kernel_release: String'
check "module-set fingerprint is part of the generation" kernel_evidence.rs 'pub module_fingerprint: String'
check "empty module set stays distinguishable from unknown" kernel_evidence.rs 'pub module_count: Option<usize>'
check "symbol-source fingerprint is part of the generation" kernel_evidence.rs 'pub symbol_source_fingerprint: String'
check "one process generation is begun before scanners" kernel_evidence.rs 'pub fn begin_scan'
check "a full scan can pin one generation" kernel_evidence.rs 'pub fn begin_scan_pinned'
check "cross-boot comparison is explicit" kernel_evidence.rs 'pub fn same_boot'
check "cross-generation comparison is explicit" kernel_evidence.rs 'pub fn same_generation'
check "cross-generation evidence is counted" kernel_evidence.rs 'cross_generation_evidence'
check "foreign kernel source is rejected with a reason" kernel_evidence.rs 'foreign_kernel_release'
check "superseded evidence becomes unknown" kernel_evidence.rs 'state=unknown'
check "a mid-scan host change becomes unknown" kernel_evidence.rs 'host_changed_during_scan'
check "host identity is revalidated against the same roots" kernel_evidence.rs 'host_still_matches'
check "summary prints boot, release, module and symbol identity" kernel_evidence.rs 'KERNEL_EVIDENCE boot_id='
check "summary prints the generation label" kernel_evidence.rs 'symbol_source_fingerprint=\{\}'

echo "== kernel scanners share the generation =="
for scanner in hidden_lkm module_list_linkage_tamper syscall_table kernel_taint; do
    check "$scanner uses the active generation" "scanners/$scanner.rs" 'current_or_collect'
    check "$scanner exposes a generation-aware entry point" "scanners/$scanner.rs" 'pub fn run_with_evidence'
done
check "hidden LKM consumes the frozen proc module inventory" \
    scanners/hidden_lkm.rs 'fn collect_proc_modules'
check "module linkage consumes the frozen sysfs inventory" \
    scanners/module_list_linkage_tamper.rs 'fn read_sys_modules'
check "syscall table consumes frozen kallsyms evidence" \
    scanners/syscall_table.rs 'fn resolve_from_kallsyms'
check "taint consumes frozen module taint letters" \
    scanners/kernel_taint.rs 'fn collect_module_taint_letters'
check "syscall table rejects a foreign kernel release" \
    scanners/syscall_table.rs 'foreign_release_reason'
check "old syscall risk text is retained" \
    scanners/syscall_table.rs 'inconsistent_addresses sources='
check "old missing-symbol text is retained" \
    scanners/syscall_table.rs 'issue=missing_sys_call_table'
check "old collection error text is retained" \
    scanners/hidden_lkm.rs 'collection_errors='
check "old module linkage finding text is retained" \
    scanners/module_list_linkage_tamper.rs 'anomaly=null_gap'

echo "== scan startup and report =="
check "main begins one generation before the loop" main.rs 'kernel_evidence::begin_scan\(\)'
check "main prints the same generation after the loop" main.rs 'kernel_evidence::summary\(&kernel_generation\)'
check "main consults the generation verdict" main.rs 'kernel_evidence::final_scan_outcome'

scanner_count="$(grep -c '^    Scanner {' "$SRC/main.rs")"
if [ "$scanner_count" -eq 50 ]; then
    printf 'ok   - scanner registry still contains 50 entries\n'
else
    printf 'FAIL - scanner registry contains %s entries (expected 50)\n' "$scanner_count"
    FAILURES=$((FAILURES + 1))
fi
check_not "main still has no non-zero exit path" main.rs 'process::exit|ExitCode::from'

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "all kernel evidence generation acceptance checks passed"
    exit 0
fi
echo "$FAILURES kernel evidence acceptance check(s) failed"
exit 1
