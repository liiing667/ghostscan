use crate::packet_path::{FindingKind, PacketPathTransaction};
use crate::ScanOutcome;

/// Netfilter cloaking artifacts, read from the shared packet-path transaction.
///
/// Empty regular chains are explicitly legal and never reported.  A cloaking
/// candidate is a non-empty regular chain that cannot be reached from any
/// base chain in the same table.  Every finding keeps its table, chain, hook
/// and interface attribution and stays on the `netfilter:` plane; it is not
/// merged with an unrelated interface/XDP attachment.
pub fn run_with_path(path: &PacketPathTransaction) -> ScanOutcome {
    let snapshot = path.netfilter().map_err(|failure| failure.to_string())?;
    let findings: Vec<String> = path
        .findings()
        .into_iter()
        .filter(|finding| {
            matches!(
                finding.kind,
                FindingKind::CloakedChain
                    | FindingKind::OrphanBaseChain
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

/// Standalone entry point with its own transaction generation.
pub fn run() -> ScanOutcome {
    run_with_path(&PacketPathTransaction::start())
}
