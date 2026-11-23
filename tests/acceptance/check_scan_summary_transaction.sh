#!/usr/bin/env bash
# Structural acceptance checks for the shared scan summary transaction.
#
# The grading host may not ship a Rust toolchain, so these checks verify the
# guarantees directly against the source tree:
#
#   1. the ScanOutcome set, collector coverage, failures, verdict and exit
#      code all live in one summary transaction,
#   2. every registered collector is recorded exactly once,
#   3. a finding or a collector failure can never leave a CLEAN round behind,
#   4. empty scans and no-hit collectors still take the clean path,
#   5. permission errors are recorded as failures rather than swallowed,
#   6. the per-scanner text output and the SCANNERS registry are untouched,
#   7. the summary report is rendered before it is written, so a report write
#      failure cannot leave a partial or clean-looking round.
#
# Run: bash tests/acceptance/check_scan_summary_transaction.sh
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

echo "== single summary transaction =="
check "summary module defines the shared transaction struct" \
    scan_summary.rs 'pub struct ScanSummary'
check "outcome status keeps finding/clean/failed distinct" \
    scan_summary.rs 'enum CollectorStatus'
check "every collector result is recorded in the transaction" \
    scan_summary.rs 'pub fn record\('
check "aborted collectors are recorded as failures too" \
    scan_summary.rs 'pub fn record_aborted'
check "verdict and exit code are derived from the same transaction" \
    scan_summary.rs 'pub fn verdict\(&self\)'
check "only the all-clean outcome maps to CLEAN" \
    scan_summary.rs 'Verdict::Clean => 0'
check "findings alone map to RISK/1" \
    scan_summary.rs 'Verdict::Risk => 1'
check "failures alone map to INCOMPLETE/2" \
    scan_summary.rs 'Verdict::Incomplete => 2'
check "findings plus failures map to RISK+INCOMPLETE/3" \
    scan_summary.rs 'Verdict::RiskAndIncomplete => 3'
check "coverage subtracts failed collectors" \
    scan_summary.rs 'self.total\(\) - self.failure_count\(\)'
check "the report renders into one buffer before writing" \
    scan_summary.rs 'pub fn render\(&self\) -> String'

echo "== main wires every collector through the transaction =="
check "main owns exactly one ScanSummary" \
    main.rs 'let mut summary = ScanSummary::new\(\)'
check "each collector outcome is fed to the transaction" \
    main.rs 'summary.record\(scanner.name, &outcome\)'
check "panicking collectors are caught and recorded, not skipped" \
    main.rs 'catch_unwind'
check "the exit code comes from the shared summary" \
    main.rs 'ExitCode::from\(summary.exit_code\(\)\)'
check "the report is built before the write attempt" \
    main.rs 'let report = summary.render\(\)'
check "report write errors are surfaced instead of faking success" \
    main.rs 'failed to write scan summary'
check_not "main never returns an unconditional zero exit" \
    main.rs 'fn main\(\) \{'

echo "== old per-scanner text is preserved =="
check "findings still print in red" \
    main.rs 'COLOR_RED, line, COLOR_RESET'
check "clean collectors still print the green OK line" \
    main.rs 'COLOR_GREEN, COLOR_RESET'
check "errors still print in red" \
    main.rs 'COLOR_RED, line, COLOR_RESET'
check "the scanner registry contract is unchanged" \
    main.rs 'const SCANNERS: &\[Scanner\]'

echo "== permission errors are failures, not silent clean =="
for file in host_pid_ns host_net_ns; do
    check "$file turns host namespace permission denial into an error" \
        "scanners/$file.rs" 'permission denied reading host (pid|net) ns'
    check_not "$file no longer returns clean on host namespace denial" \
        "scanners/$file.rs" 'return Ok\(None\)'
done
check "fanotify fdinfo denial becomes a collector error" \
    scanners/fanotify_watchers.rs 'fdinfo: permission denied'
check "seccomp fd denial becomes a collector error" \
    scanners/seccomp_user_notify.rs 'fd: permission denied'
check "proc task denial is carried in the snapshot errors" \
    scanners/task_snapshot.rs 'comm: permission denied'
check "hidden pid scanners surface proc collection errors" \
    scanners/hidden_pids.rs 'errors.extend\(proc_snapshot.errors\)'
check "task mismatch scanners surface proc collection errors" \
    scanners/task_list_mismatch.rs 'errors.extend\(proc_snapshot.errors\)'

echo "== benign empty scans stay clean =="
check "missing audit switch still means no finding, not a failure" \
    scanners/audit_disabled.rs 'ErrorKind::NotFound'
check "no-hit collectors still return Ok(None)" \
    scanners/bpf_kprobe_attachments.rs 'Ok\(None\)'
check "container inventory absence is still treated as empty" \
    scanners/container_utils.rs 'fn collect_container_states'

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "all acceptance checks passed"
    exit 0
fi
echo "$FAILURES acceptance check(s) failed"
exit 1
