use crate::packet_path::PacketPathTransaction;
use crate::ScanOutcome;

/// XDP/TC attachment problems, attributed through the shared transaction.
///
/// The scanner consumes the transaction's interface/program snapshot instead
/// of dumping the raw `bpftool net list` payload.  Every finding names the
/// netns, interface, eBPF program (and its id) and the `bpf:` path it belongs
/// to, so it cannot be mistaken for an unrelated netfilter chain.
pub fn run_with_path(path: &PacketPathTransaction) -> ScanOutcome {
    let net = path.bpf_net().map_err(|failure| failure.to_string())?;
    // Keep the interface and program planes explicitly attached to this
    // scanner's evidence even when a program inventory is unavailable: the
    // report below is still derived from the same transaction.
    let _interfaces = path.interfaces();
    let _ = path.bpf_programs();
    let findings: Vec<String> = path
        .findings()
        .into_iter()
        .filter(|finding| finding.kind.is_bpf())
        .map(|finding| finding.render_line())
        .collect();

    if findings.is_empty() {
        if net.errors.is_empty() {
            Ok(None)
        } else {
            Err(net.errors.join(", "))
        }
    } else {
        Ok(Some(findings.join("\n")))
    }
}

/// Alias for callers that use the transaction vocabulary.
#[allow(dead_code)]
pub fn run_with_transaction(path: &PacketPathTransaction) -> ScanOutcome {
    run_with_path(path)
}

/// Standalone entry point with its own transaction generation.
pub fn run() -> ScanOutcome {
    run_with_path(&PacketPathTransaction::start())
}
