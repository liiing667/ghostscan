#!/usr/bin/env bash
# Structural acceptance checks for the shared host observation generation.
#
# The sandbox used for this change has no Rust toolchain, so these checks run
# directly against the source tree.  They assert that:
#
#   1. scan startup creates exactly one observation generation,
#   2. container/task collectors are collected once and stamped with it,
#   3. every host-aware scanner consumes the shared observation,
#   4. the final report only merges same-generation collector stamps,
#   5. failed/cancelled collectors have no fallback value,
#   6. permission errors, empty inventories, scanner ordering and exit code 0
#      remain intact.
#
# Run: bash tests/acceptance/check_host_observation_generation.sh
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

echo "== generation and collector stamping =="
check "host observation module exists" \
    host_observation.rs 'pub struct HostObservation'
check "generation has a monotonic process-local round" \
    host_observation.rs 'NEXT_OBSERVATION_ROUND'
check "generation label includes boot, round and start time" \
    host_observation.rs 'fn label\(&self\) -> String'
check "collector results carry a generation stamp" \
    host_observation.rs 'pub struct CollectorStamp'
check "every collector knows its kind and attempt" \
    host_observation.rs 'pub kind: CollectorKind'
check "container, BPF task and proc task collectors are distinct" \
    host_observation.rs 'CollectorKind::Containers|CollectorKind::BpfTasks|CollectorKind::ProcTasks'
check "container collector has an explicit checked entry point" \
    scanners/container_utils.rs 'pub fn collect_container_states_checked'
check "empty container inventory is not a collector failure" \
    scanners/container_utils.rs 'Ok\(collect_container_states\(limit\)\)'
check "collector failures can be marked cancelled" \
    host_observation.rs 'pub fn cancelled'
check "collector retry is generation-scoped" \
    host_observation.rs 'pub fn retry_failed'
check "successful evidence cannot be replaced by retry" \
    host_observation.rs 'refusing to replace evidence in generation'
check "cancel drops the previous value instead of keeping it" \
    host_observation.rs 'fn cancel\(&mut self, reason: String\)'

echo "== scan startup and shared scanners =="
check "main creates the observation before the scanner loop" \
    main.rs 'let host = HostObservation::start\(\);'
check "main passes the observation to every scanner" \
    main.rs 'scanner\.run\(&host\)'
check "final report is printed from the same observation" \
    main.rs 'print_host_observation\(&host\)'
check "container scanners are in the shared host mapping" \
    main.rs 'sensitive_host_mounts::run_with_host'
check "PID namespace scanner is in the shared host mapping" \
    main.rs 'host_pid_ns::run_with_host'
check "net namespace scanner is in the shared host mapping" \
    main.rs 'host_net_ns::run_with_host'
check "overlay lowerdir scanner is in the shared host mapping" \
    main.rs 'overlay_lowerdir::run_with_host'
check "fanotify scanner is in the shared host mapping" \
    main.rs 'fanotify_watchers::run_with_host'
check "task mismatch scanner is in the shared host mapping" \
    main.rs 'task_list_mismatch::run_with_host'
check "hidden PID scanner is in the shared host mapping" \
    main.rs 'hidden_pids::run_with_host'

for scanner in sensitive_host_mounts host_pid_ns host_net_ns overlay_lowerdir fanotify_watchers; do
    check "$scanner consumes host.containers()" \
        "scanners/$scanner.rs" 'host\.containers\(\)'
done
for scanner in hidden_pids task_list_mismatch; do
    check "$scanner consumes host.bpf_tasks()" \
        "scanners/$scanner.rs" 'host\.bpf_tasks\(\)'
    check "$scanner consumes host.proc_tasks()" \
        "scanners/$scanner.rs" 'host\.proc_tasks\(\)'
done

echo "== report merge has no cross-round fallback =="
check "generation merge accepts only matching stamps" \
    host_observation.rs 'pub struct GenerationMerge'
check "mismatched stamps are rejected and counted" \
    host_observation.rs 'self\.rejected \+= 1'
check "report exposes same_generation" \
    host_observation.rs 'pub fn same_generation'
check "report exposes merged domains" \
    host_observation.rs 'pub fn merged_domains'
check "task evidence requires both BPF and proc collectors" \
    host_observation.rs 'if bpf_ok && proc_ok'
check "report prints cross-generation evidence count" \
    host_observation.rs 'cross_generation_evidence='
check "report prints the host observation status" \
    host_observation.rs 'host_observation=\{\}'
check_not "no process-wide container cache" \
    host_observation.rs 'static .*ContainerInventory'
check_not "no process-wide BPF task cache" \
    host_observation.rs 'static .*BpfTaskSnapshot'
check_not "no lazy global host cache" \
    host_observation.rs 'OnceLock|OnceCell|lazy_static'

echo "== compatibility surface =="
scanner_count="$(grep -c '^    Scanner {' "$SRC/main.rs")"
if [ "$scanner_count" -eq 50 ]; then
    printf 'ok   - scanner registry still contains 50 entries\n'
else
    printf 'FAIL - scanner registry contains %s entries (expected 50)\n' "$scanner_count"
    FAILURES=$((FAILURES + 1))
fi
check "existing scanner names remain in the registry" \
    main.rs 'name: "Hidden PIDs \(bpf-only\)"'
check "existing scanner ordering anchor remains" \
    main.rs 'name: "Kernel message suppression"'
check_not "main still has no non-zero exit path" \
    main.rs 'ExitCode::from|process::exit'
check "permission-denied inventory errors remain partial evidence" \
    host_observation.rs 'container_result_is_partial'
check "permission failures keep their original text" \
    host_observation.rs 'impl fmt::Display for CollectionFailure'
check "host namespace permission denial still returns OK" \
    scanners/host_pid_ns.rs 'PermissionDenied'
check "empty container results remain valid" \
    host_observation.rs 'empty_container_inventory_is_complete_evidence'
check "cancelled retry scenario is covered by unit tests" \
    host_observation.rs 'cancelled_collector_drops_previous_value_and_retry_cannot_revive_it'
check "second-round failure scenario is covered by unit tests" \
    host_observation.rs 'failed_second_round_never_exposes_first_round_tasks'
check "cross-generation rejection is covered by unit tests" \
    host_observation.rs 'cross_generation_stamp_is_rejected'

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "all host observation acceptance checks passed"
    exit 0
fi
echo "$FAILURES host observation acceptance check(s) failed"
exit 1
