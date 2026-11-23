use crate::bpf_lifecycle::{
    conflict_error, scanner_error, BpfSnapshot, BpfTransaction, CollectorKind, BPF_TRANSACTION,
};
use crate::ScanOutcome;

pub fn run() -> ScanOutcome {
    run_with_bpf(&BPF_TRANSACTION)
}

/// BPF LSM scan sharing the caller's lifecycle transaction.
pub fn run_with_bpf(transaction: &BpfTransaction) -> ScanOutcome {
    let snapshot = transaction.snapshot();
    run_with_snapshot(&snapshot)
}

pub fn run_with_snapshot(snapshot: &BpfSnapshot) -> ScanOutcome {
    if let Some(error) = scanner_error(
        snapshot,
        CollectorKind::Programs,
        "bpftool not available to enumerate BPF programs",
    ) {
        return Err(error);
    }

    if let Some(error) = conflict_error(snapshot) {
        return Err(error);
    }

    let mut findings = Vec::new();
    for program in &snapshot.programs {
        let prog_type = program.prog_type.to_ascii_lowercase();
        if !prog_type.contains("lsm") {
            continue;
        }
        let attach_point = &program.attach_type;

        findings.push(format!(
            "prog_id={}, attach_point={}, name={}, tag={}, generation={}, boot_id={}",
            program.id,
            attach_point,
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
