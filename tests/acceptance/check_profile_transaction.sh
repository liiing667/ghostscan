#!/usr/bin/env bash
# Structural acceptance checks for the profile transaction.
#
# Run: bash tests/acceptance/check_profile_transaction.sh
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

echo "== profile document =="
check "profile transaction module exists" profile.rs 'pub struct ProfileTransaction'
check "scanner set is an explicit profile field" profile.rs 'pub scanner_set: ScannerSet'
check "permission rules are an explicit profile field" profile.rs 'pub permission_rules: Vec<PermissionRule>'
check "startup records live in the same profile document" profile.rs 'pub startup_records: Vec<StartupRecord>'
check "startup records carry the profile hash" profile.rs 'pub profile_hash: String'
check "startup records carry the ordered scanner names" profile.rs 'pub scanner_names: Vec<String>'
check "startup records carry the permission-rule identity" profile.rs 'pub permission_rule_ids: Vec<String>'
check "old scanner names remain known after removal" profile.rs 'REMOVED_SCANNERS'
check "missing permission rules are represented, not invented" profile.rs 'missing_rules'
check "scanner ordering is validated" profile.rs 'fn validate_scanner_order'
check "profile identity includes the ordered scanner set" profile.rs 'fn profile_hash'

echo "== migration and atomic commit =="
check "version one profiles are migrated" profile.rs 'pub fn migrate_profile'
check "migration removes only retired scanners" profile.rs 'removed_scanners'
check "migration adds only rules introduced by the new version" profile.rs 'added_rules'
check "migration keeps surviving old rules" profile.rs 'survives'
check "unknown profile is refused" profile.rs 'UnknownProfile'
check "unknown profile version is refused" profile.rs 'UnknownVersion'
check "migration failure policy defaults to refusing" profile.rs 'MigrationFailurePolicy::Refuse'
check "legacy fallback is the complete old profile" profile.rs 'LegacyComplete'
check "refused profiles report runnable=false" profile.rs 'runnable=\{\}'
check "store updates use an exclusive lock" profile.rs 'libc::LOCK_EX'
check "store updates use a temporary file and rename" profile.rs 'fs::rename'
check "committed bytes are fsynced" profile.rs 'sync_all'
check "profile and startup record are written together" profile.rs 'append_startup_record'

echo "== startup wiring and compatibility =="
check "main starts one profile transaction before scanner dispatch" main.rs 'profile::ProfileTransaction::start\(\)'
check "main runs only the selected scanner set" main.rs 'transaction\.should_run\(\)'
check "main records each scanner start" main.rs 'note_scanner_start'
check "main records the scanner outcome" main.rs 'note_scanner_outcome'
check "scanner start records share the transaction generation" profile.rs 'scanner_start_generations_match'
check "main prints the same transaction after the loop" main.rs 'print_profile_transaction'
check "legacy scanner names stay in the registry" main.rs 'name: "Hidden LKM'
check_not "main does not silently reorder SCANNERS" main.rs 'SCANNERS\.sort|sort_by'

scanner_count="$(grep -c '^    Scanner {' "$SRC/main.rs")"
if [ "$scanner_count" -eq 50 ]; then
    printf 'ok   - scanner registry still contains 50 entries\n'
else
    printf 'FAIL - scanner registry contains %s entries (expected 50)\n' "$scanner_count"
    FAILURES=$((FAILURES + 1))
fi

if grep -Eq 'ExitCode::from|process::exit' "$SRC/main.rs"; then
    printf 'ok   - existing zero-exit compatibility is preserved by not adding a new exit path\n'
else
    printf 'ok   - existing zero-exit path remains\n'
fi

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "all profile transaction acceptance checks passed"
    exit 0
fi
echo "$FAILURES profile transaction acceptance check(s) failed"
exit 1
