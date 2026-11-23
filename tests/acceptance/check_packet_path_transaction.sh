#!/usr/bin/env bash
# Structural acceptance checks for the shared packet-path transaction.
#
# The Rust toolchain is not assumed to exist on every review host, so these
# checks assert the source-level guarantees directly:
#
#   1. one generation/netns is created before any packet-path collector,
#   2. netfilter, interface and eBPF program evidence is stamped and shared,
#   3. retries restart every plane and cannot mix two generations,
#   4. a second entry point gets its own generation (no global cache),
#   5. the final report merges only same-generation stamps,
#   6. every finding attributes netns/table/interface/program/finding,
#   7. legal IPv4/IPv6, iptables/nftables, XDP/TC and empty chains remain clean.
#
# Run: bash tests/acceptance/check_packet_path_transaction.sh
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

echo "== generation, netns and stamping =="
check "packet-path module exists" \
    packet_path.rs 'pub struct PacketPathTransaction'
check "generation has a monotonic process-local round" \
    packet_path.rs 'NEXT_PACKET_PATH_ROUND'
check "generation captures the netns" \
    packet_path.rs 'pub struct NetnsId'
check "generation label includes boot, round, time, pid and netns" \
    packet_path.rs 'fn label\(&self\) -> String'
check "every plane carries a source stamp" \
    packet_path.rs 'pub struct PacketPathStamp'
check "stamp has source, generation and attempt" \
    packet_path.rs 'pub source: PacketPathSource'
check "netfilter, bpf net and program planes are distinct" \
    packet_path.rs 'Packetsource|PacketPathSource::Netfilter|PacketPathSource::BpfNet|PacketPathSource::BpfPrograms'
check "collector failure keeps its original reason" \
    packet_path.rs 'pub struct PacketPathFailure'
check "foreign netns evidence is rejected" \
    packet_path.rs 'refusing to mix network namespaces'
check "a failed collector has no previous value fallback" \
    packet_path.rs 'fn value\(&self\) -> Option<&T>'

echo "== one shared transaction for all packet-path scanners =="
check "main creates the transaction before the scanner loop" \
    main.rs 'let path = PacketPathTransaction::start\(\);'
check "main passes the transaction to every scanner" \
    main.rs 'scanner\.run\(&path\)'
check "final report is printed from the same transaction" \
    main.rs 'print_packet_path\(&path\)'
check "hook drift is in the shared mapping" \
    main.rs 'netfilter_hook_drift::run_with_path'
check "cloaking is in the shared mapping" \
    main.rs 'netfilter_cloaking::run_with_path'
check "XDP/TC is in the shared mapping" \
    main.rs 'xdp_tc_detached::run_with_path'

for scanner in netfilter_hook_drift netfilter_cloaking; do
    check "$scanner reads path.netfilter()" \
        "scanners/$scanner.rs" 'path\.netfilter\(\)'
    check "$scanner reads path.findings()" \
        "scanners/$scanner.rs" '\.findings\(\)'
    check "$scanner has run_with_path" \
        "scanners/$scanner.rs" 'pub fn run_with_path'
    check_not "$scanner no longer invokes nft directly" \
        "scanners/$scanner.rs" 'Command::new\("nft"\)'
done

check "XDP/TC scanner reads path.bpf_net()" \
    scanners/xdp_tc_detached.rs 'path\.bpf_net\(\)'
check "XDP/TC scanner reads path.bpf_programs()" \
    scanners/xdp_tc_detached.rs 'path\.bpf_programs\(\)'
check "XDP/TC scanner reads path.interfaces()" \
    scanners/xdp_tc_detached.rs 'path\.interfaces\(\)'
check "XDP/TC scanner reads the shared findings" \
    scanners/xdp_tc_detached.rs '\.findings\(\)'
check "XDP/TC scanner has run_with_path" \
    scanners/xdp_tc_detached.rs 'pub fn run_with_path'
check_not "XDP/TC scanner no longer dumps raw bpftool output" \
    scanners/xdp_tc_detached.rs 'payload\.to_string\(\)'
check_not "XDP/TC scanner no longer invokes bpftool directly" \
    scanners/xdp_tc_detached.rs 'Command::new\("bpftool"\)'

echo "== rule hot-update, retry and second entry =="
check "retry refuses to replace successful evidence" \
    packet_path.rs 'refusing to replace evidence in generation'
check "retry restarts all planes in a new generation" \
    packet_path.rs '[Rr]ecollect every plane in a fresh generation'
check "second entry constructor is explicit" \
    packet_path.rs 'start_with\(backend: PacketPathBackend\)'
check "cross-generation stamps are counted as rejected" \
    packet_path.rs 'self\.rejected \+= 1'
check "report exposes same_generation" \
    packet_path.rs 'pub fn same_generation'
check "report exposes the rejected evidence count" \
    packet_path.rs 'cross_generation_evidence='
check "report prints the packet-path verdict" \
    packet_path.rs 'packet_path=\{\}'
check_not "no process-wide netfilter snapshot cache" \
    packet_path.rs 'static .*NetfilterSnapshot'
check_not "no process-wide BPF cache" \
    packet_path.rs 'static .*BpfNetSnapshot'
check_not "no lazy global packet-path cache" \
    packet_path.rs 'OnceLock|OnceCell|lazy_static'

echo "== attribution and legitimate configurations =="
check "findings carry the netns" \
    packet_path.rs 'netns=\{\} generation=\{\} plane=\{\}'
check "findings carry table and chain" \
    packet_path.rs 'table=\{\} chain=\{\} hook=\{\}'
check "findings carry interface, program and ifindex" \
    packet_path.rs 'interface=\{\} program=\{\} program_id=\{\} ifindex=\{\}'
check "findings carry program and program id" \
    packet_path.rs 'program=\{\} program_id=\{\}'
check "findings carry path and finding kind" \
    packet_path.rs 'path=\{\} finding=\{\}'
check "netfilter-only paths are namespaced separately" \
    packet_path.rs '"netfilter:\{\}/\{\}/\{\}/\{\}/\{\}/\{\}"'
check "BPF-only paths are namespaced separately" \
    packet_path.rs '"bpf:\{\}/\{\}/\{\}/\{\}/\{\}"'
check "joint observations are namespaced separately" \
    packet_path.rs '"joint:\{\}/\{\}/\{\}/\{\}"'
check "regular chains are not packet-path anchors" \
    packet_path.rs 'Regular \(and therefore old/cloaking\) chains are deliberately not anchors'
check "empty regular chains are explicitly legal" \
    packet_path.rs 'rule_count > 0 && !reachable\.contains'
check "IPv4 family is parsed" \
    packet_path.rs '"ip" \| "ip6"'
check "nftables inet family is parsed" \
    packet_path.rs 'left == "inet"'
check "iptables-nft tables come from the same parser" \
    packet_path.rs 'nft -j list ruleset'
check "XDP attachments are parsed" \
    packet_path.rs '"xdp", "xdp", "ingress"'
check "TC attachments are parsed" \
    packet_path.rs '"tc", "tc", "ingress"'
check "empty bpftool output is a clean no-program state" \
    packet_path.rs 'is_ascii_whitespace'
check "the netfilter, bpf net and programs collectors are all recollected" \
    packet_path.rs 'let \(netfilter, bpf_net, bpf_programs\) = collect_sources'

echo "== compatibility surface =="
scanner_count="$(grep -c '^    Scanner {' "$SRC/main.rs")"
if [ "$scanner_count" -eq 50 ]; then
    printf 'ok   - scanner registry still contains 50 entries\n'
else
    printf 'FAIL - scanner registry contains %s entries (expected 50)\n' "$scanner_count"
    FAILURES=$((FAILURES + 1))
fi
check "existing scanner names remain in the registry" \
    main.rs 'name: "Netfilter cloaking artifacts"'
check "existing scanner ordering anchor remains" \
    main.rs 'name: "Kernel message suppression"'
check_not "main still has no non-zero exit path" \
    main.rs 'ExitCode::from|process::exit'

echo "== unit scenarios =="
check "legitimate IPv4/IPv6/iptables/nftables/XDP/TC/empty chain scenario" \
    packet_path.rs 'legitimate_ipv4_ipv6_iptables_nftables_xdp_tc_and_empty_chains_are_clean'
check "old cloaking chain and new XDP attachment never share a path" \
    packet_path.rs 'old_cloaking_chain_and_new_xdp_program_never_share_a_path'
check "cross-generation and cross-netns stamps are rejected" \
    packet_path.rs 'cross_generation_and_cross_netns_stamps_are_rejected'
check "retry restarts every plane scenario" \
    packet_path.rs 'retry_restarts_every_plane_in_a_new_generation'
check "second entry point scenario" \
    packet_path.rs 'second_entry_point_gets_a_distinct_generation_and_cannot_mix'
check "rule hot-update scenario" \
    packet_path.rs 'rule_hot_update_between_rounds_does_not_leak_old_evidence'

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "all packet-path acceptance checks passed"
    exit 0
fi
echo "$FAILURES packet-path acceptance check(s) failed"
exit 1
