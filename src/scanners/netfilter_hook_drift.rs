use crate::packet_path::{FindingKind, PacketPathTransaction};
use crate::ScanOutcome;

/// Netfilter hook drift, read from the shared packet-path transaction.
///
/// This scanner deliberately does not invoke `nft` itself: the ruleset seen
/// here is exactly the snapshot collected once for every packet-path scanner
/// in this round, so a hot rule update cannot make this scanner report a
/// different table generation than the XDP/TC scanner.
pub fn run_with_path(path: &PacketPathTransaction) -> ScanOutcome {
    let snapshot = path.netfilter().map_err(|failure| failure.to_string())?;
    let findings: Vec<String> = path
        .findings()
        .into_iter()
        .filter(|finding| {
            matches!(
                finding.kind,
                FindingKind::OrphanBaseChain
                    | FindingKind::MissingJumpTarget
                    | FindingKind::UnresolvedSet
            )
        })
        .map(|finding| finding.render_line())
        .collect();

    if findings.is_empty() {
        if snapshot.errors.is_empty() {
            Ok(None)
        } else {
            Err(snapshot.errors.join(", "))
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

/// Standalone entry point.  It creates its own transaction generation and
/// therefore can never reuse evidence from another entry point.
pub fn run() -> ScanOutcome {
    run_with_path(&PacketPathTransaction::start())
}
