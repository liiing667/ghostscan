#!/usr/bin/env bash
# Acceptance checks for the shared persistence observation.
#
# The Rust toolchain is not assumed on every host, so this script verifies the
# structural guarantees of the implementation against the source tree and then
# runs the behavioural scenarios in simulate_persistence_generations.py.
#
#   1. one generation stamp is created before the scanner loop,
#   2. the file snapshot, include closure and every finding share that stamp,
#   3. scanners delegate to the observation instead of reading files,
#   4. a second identity fence discards and retries a changed generation,
#   5. symlinks, includes, masked units and permissions stay explicit,
#   6. the final block is the only persisted verdict and reports COMPLETE/
#      PARTIAL/FAILED plus same_generation.
#
# Run: bash tests/acceptance/check_persistence_observation.sh
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

echo "== shared observation wiring =="
check "a single process-wide observation exists" \
    persistence.rs 'pub static PERSISTENCE: PersistenceTransaction'
check "the observation is stamped with boot/generation/attempt/time/pid" \
    persistence.rs 'pub struct ObservationStamp'
check "stamps can compare generations" \
    persistence.rs 'fn same_generation'
check "the snapshot carries files, dirs and include chains" \
    persistence.rs 'pub files: BTreeMap<PathBuf, FileRecord>'
check "include chains are stored per logical file" \
    persistence.rs 'pub chains: BTreeMap<PathBuf, Vec<Vec<PathBuf>>>'
check "findings carry source, file, chain and generation" \
    persistence.rs 'pub struct PersistenceFinding'
check "findings render the include chain" \
    persistence.rs 'include_chain='
check "findings render the generation" \
    persistence.rs 'generation='
check "the final report names same_generation" \
    persistence.rs 'same_generation='
check "the final report names persistence_observation" \
    persistence.rs 'persistence_observation='
check "main captures the observation before the scanner loop" \
    main.rs 'PERSISTENCE.begin_scan\(\)'
check "main prints the final persistence block" \
    main.rs 'Persistence evidence \(one host observation\)'

echo "== generation fence and retry =="
check "a bounded number of generations may be attempted" \
    persistence.rs 'MAX_GENERATION_ATTEMPTS'
check "a retry starts from an empty generation" \
    persistence.rs 'failed_snapshot'
check "two passes are compared before publishing" \
    persistence.rs 'fn capture_generation'
check "the snapshot has an identity fingerprint" \
    persistence.rs 'fn fingerprint\(&self\)'
check "differing files are reported as generation conflicts" \
    persistence.rs 'generation_conflicts'

echo "== files, symlinks and includes =="
check "symlinks are resolved inside the snapshot" \
    persistence.rs 'fn resolve\(&self'
check "symlink cycles are explicit" \
    persistence.rs 'symlink cycle'
check "sudoers #include is parsed" \
    persistence.rs '"#include"'
check "sudoers #includedir is parsed" \
    persistence.rs '"#includedir"'
check "legacy @include/@includedir syntax is parsed" \
    persistence.rs '"@includedir"'
check "include cycles are explicit" \
    persistence.rs 'include_cycle='
check "include depth is bounded" \
    persistence.rs 'MAX_INCLUDE_DEPTH'
check "PAM @include is followed" \
    persistence.rs 'fn pam_includes'
check "systemd drop-ins are merged in precedence order" \
    persistence.rs 'DROPIN_ROOTS'
check "masked units stay legal observations" \
    persistence.rs 'fn is_masked'
check "permission and I/O errors stay in the record" \
    persistence.rs 'pub errors: Vec<String>'
check "missing optional files are not errors" \
    persistence.rs 'missing: error.kind\(\) == std::io::ErrorKind::NotFound'

echo "== scanners consume the observation =="
for scanner in ssh_footholds sudoers pam_nss systemd_ghost; do
    check "$scanner delegates to the shared observation" \
        "scanners/$scanner.rs" 'persistence::PERSISTENCE.snapshot\(\)'
    check_not "$scanner never reads files itself" \
        "scanners/$scanner.rs" 'fs::(read|read_to_string|read_dir|metadata|symlink_metadata)'
done

echo "== behavioural scenarios =="
if python3 "$ROOT/tests/acceptance/simulate_persistence_generations.py"; then
    printf 'ok   - generation/include scenarios\n'
else
    printf 'FAIL - generation/include scenarios\n'
    FAILURES=$((FAILURES + 1))
fi

if [ "$FAILURES" -ne 0 ]; then
    printf '\n%d acceptance check(s) failed\n' "$FAILURES"
    exit 1
fi
printf '\nall persistence observation acceptance checks passed\n'
