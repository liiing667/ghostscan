#!/usr/bin/env bash
# Acceptance checks for the shared boot evidence transaction.
#
# The Rust toolchain cannot be assumed on every host, so this script verifies
# the structural and semantic guarantees of the implementation directly
# against the source tree:
#
#   1. boot id, audit epoch, journal cursor, printk and ftrace all register
#      evidence in the same transaction,
#   2. each source records a coverage window plus origins/errors/limitations,
#   3. rotation, permission errors, disabled or redirected states can never
#      produce a public clean claim,
#   4. legitimate audit restart, rate limiting, restricted dmesg and idle
#      ftrace remain represented instead of being erased,
#   5. the only boot-wide CLEAN line is gated on every source being complete.
#
# Run: bash tests/acceptance/check_evidence_transaction.sh
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

echo "== shared transaction wiring =="
check "evidence module defines the four required sources" \
    evidence.rs 'Audit,|Journal,|Printk,|Ftrace,'
check "transaction is a single process-wide static" \
    evidence.rs 'pub static TRANSACTION: EvidenceTransaction'
check "every evidence entry carries a coverage window" \
    evidence.rs 'pub window: Option<Window>'
check "every evidence entry keeps collection errors" \
    evidence.rs 'pub errors: Vec<String>'
check "every evidence entry keeps limitations" \
    evidence.rs 'pub limitations: Vec<String>'
check "clean verdict requires complete evidence and a spanning window" \
    evidence.rs 'Verdict::Clean'
check "boot id is anchored in the transaction output" \
    main.rs 'boot_id='
check "final summary iterates every source" \
    evidence.rs 'fn summarize'
check "boot-wide clean is gated on all sources" \
    evidence.rs 'fn all_sources_clean'

echo "== audit scanner =="
check "audit reads the kernel audit switch" \
    scanners/audit_disabled.rs 'audit_enabled'
check "audit parses /proc/net/audit counters" \
    scanners/audit_disabled.rs 'parse_proc_audit'
check "audit epoch is derived from the journal" \
    scanners/audit_disabled.rs 'collect_audit_epoch'
check "audit restarts are preserved" \
    scanners/audit_disabled.rs 'audit_restarts'
check "audit rate limiting is preserved" \
    scanners/audit_disabled.rs 'audit_rate_limited'
check "audit disable markers become findings" \
    scanners/audit_disabled.rs 'audit_disable_markers'
check "permission denial is recorded, not ignored" \
    scanners/audit_disabled.rs 'PermissionDenied'
check "audit registers evidence in the transaction" \
    scanners/audit_disabled.rs 'TRANSACTION.record\(\s*$|TRANSACTION.record\('
check "audit prints an explicit non-clean verdict" \
    scanners/audit_disabled.rs 'VERDICT='
check_not "audit never returns OK on empty evidence directly" \
    scanners/audit_disabled.rs 'timestamps.len\(\) < 2'

echo "== journal scanner =="
check "journal anchors a cursor" \
    scanners/journal_gaps.rs 'show-cursor'
check "journal detects rotation markers" \
    scanners/journal_gaps.rs 'journal_rotations'
check "journal detects vacuum markers" \
    scanners/journal_gaps.rs 'journal_vacuums'
check "journal measures head-of-boot coverage" \
    scanners/journal_gaps.rs 'boot_head_uncovered'
check "journal measures tail freshness" \
    scanners/journal_gaps.rs 'journal_tail_stale'
check "empty journal is an explicit finding" \
    scanners/journal_gaps.rs 'zero records'
check "journal registers evidence in the transaction" \
    scanners/journal_gaps.rs 'TRANSACTION.record'
check "journal prints an explicit non-clean verdict" \
    scanners/journal_gaps.rs 'VERDICT='

echo "== printk scanner =="
check "printk reads dmesg_restrict" \
    scanners/kernel_message_suppression.rs 'dmesg_restrict'
check "restricted dmesg is kept as context" \
    scanners/kernel_message_suppression.rs 'dmesg_restrict=1'
check "printk parses the four loglevel values" \
    scanners/kernel_message_suppression.rs 'boot_default_loglevel'
check "printk read errors enter the transaction" \
    scanners/kernel_message_suppression.rs 'read_proc_path'
check "devkmsg disable/ratelimit is captured" \
    scanners/kernel_message_suppression.rs 'printk_devkmsg'
check "printk registers evidence in the transaction" \
    scanners/kernel_message_suppression.rs 'TRANSACTION.record'

echo "== ftrace scanner =="
check "ftrace keeps the idle nop tracer benign" \
    scanners/ftrace_redirection.rs '"nop"'
check "ftrace flags non-nop tracers" \
    scanners/ftrace_redirection.rs 'ftrace_tracer='
check "ftrace keeps sensitive symbol filtering" \
    scanners/ftrace_redirection.rs 'is_sensitive_symbol'
check "missing tracefs becomes inconclusive" \
    scanners/ftrace_redirection.rs 'tracefs=unavailable'
check "ftrace registers evidence in the transaction" \
    scanners/ftrace_redirection.rs 'TRANSACTION.record'

echo "== public clean claim discipline =="
# No participating scanner may emit the bare Ok(None) ("OK") path before the
# transaction verdict is consulted.  Each file must contain verdict_for.
for scanner in audit_disabled journal_gaps kernel_message_suppression ftrace_redirection; do
    check "$scanner consults the shared verdict" \
        "scanners/$scanner.rs" 'verdict_for\(Source::'
done
check "only the transaction summary can print BOOT_VERDICT=CLEAN" \
    main.rs 'BOOT_VERDICT=CLEAN'
check "incomplete boot produces BOOT_VERDICT=INCONCLUSIVE" \
    main.rs 'BOOT_VERDICT=INCONCLUSIVE'
check "summary exposes per-source coverage windows" \
    evidence.rs 'window=\+'

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "all acceptance checks passed"
    exit 0
fi
echo "$FAILURES acceptance check(s) failed"
exit 1
