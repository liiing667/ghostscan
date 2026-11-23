use crate::bpf_lifecycle::{
    conflict_error, scanner_error, BPF_TRANSACTION, BpfSnapshot, BpfTransaction, CollectorKind,
};
use crate::ScanOutcome;

pub fn run() -> ScanOutcome {
    run_with_bpf(&BPF_TRANSACTION)
}

/// Ownerless-program scan sharing the caller's lifecycle transaction.
///
/// The program list carries the same boot/generation stamp as every other BPF
/// scanner, so a program detached and repinned between collectors cannot be
/// paired with a link observed in another generation.
pub fn run_with_bpf(transaction: &BpfTransaction) -> ScanOutcome {
    let snapshot = transaction.snapshot();
    run_with_snapshot(&snapshot)
}

pub fn run_with_snapshot(snapshot: &BpfSnapshot) -> ScanOutcome {
    if let Some(error) = scanner_error(
        snapshot,
        CollectorKind::Programs,
        "bpftool not available to enumerate BPF objects",
    ) {
        return Err(error);
    }

    if let Some(error) = conflict_error(snapshot) {
        return Err(error);
    }

    let mut findings = Vec::new();
    for program in &snapshot.programs {
        // Keep the original ownerless semantics: an anonymous program has no
        // task holding an fd and no pin keeping it alive.  Both identities come
        // from the same lifecycle generation.
        let has_pinned = program.pinned_flag || !program.pinned.is_empty();
        let has_fd = !program.owner_pids.is_empty();
        if has_pinned || has_fd {
            continue;
        }
        findings.push(format!(
            "object=prog, id={}, name={}, pinned=false, owner_pids=∅, tag={}, generation={}, boot_id={}",
            program.id,
            program.name,
            program.tag,
            program.stamp.label(),
            program.stamp.boot_id
        ));
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        findings.sort();
        Ok(Some(findings.join("\n")))
    }
}
