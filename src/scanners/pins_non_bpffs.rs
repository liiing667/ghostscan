use crate::bpf_lifecycle::{
    conflict_error, scanner_error, BpfSnapshot, BpfTransaction, CollectorKind, FailureKind,
    PinRecord, BPF_TRANSACTION,
};
use crate::ScanOutcome;

pub fn run() -> ScanOutcome {
    run_with_bpf(&BPF_TRANSACTION)
}

/// Non-bpffs pin scan sharing the caller's lifecycle transaction.  Mount
/// classification and the pinned object identity are captured in the same
/// generation, so a pin moved while the scan was running cannot be reported as
/// belonging to a different object.
///
/// The transaction performs `parse_mountinfo` once; this scanner only consumes
/// the already-classified `mount_fstype` of each pin.
pub fn run_with_bpf(transaction: &BpfTransaction) -> ScanOutcome {
    let snapshot = transaction.snapshot();
    run_with_snapshot(&snapshot)
}

pub fn run_with_snapshot(snapshot: &BpfSnapshot) -> ScanOutcome {
    let mut errors = Vec::new();

    let all_collectors_missing = [CollectorKind::Programs, CollectorKind::Maps, CollectorKind::Links]
        .iter()
        .all(|collector| {
            snapshot
                .error_for(*collector)
                .map(|error| error.kind == FailureKind::NotAvailable)
                .unwrap_or(false)
        });
    if all_collectors_missing {
        return Err("bpftool not available to inspect pinned objects".to_string());
    }

    if let Some(error) = snapshot.mount_errors.first() {
        return Err(error.clone());
    }

    if let Some(error) = scanner_error(
        snapshot,
        CollectorKind::Programs,
        "bpftool not available to inspect pinned objects",
    ) {
        errors.push(format!("prog: {error}"));
    }
    if let Some(error) = scanner_error(
        snapshot,
        CollectorKind::Maps,
        "bpftool not available to inspect pinned objects",
    ) {
        errors.push(format!("map: {error}"));
    }
    if let Some(error) = scanner_error(
        snapshot,
        CollectorKind::Links,
        "bpftool not available to inspect pinned objects",
    ) {
        errors.push(format!("link: {error}"));
    }
    let mut findings = Vec::new();
    for pin in collect_pins(snapshot) {
        if mount_type_for(pin) == "bpf" {
            // A legal bpffs pin is not a finding.
            continue;
        }
        let file_identity = pin
            .file_identity
            .as_ref()
            .map(|identity| format!("{}:{}", identity.dev, identity.ino))
            .unwrap_or_else(|| "unknown".to_string());
        findings.push(format!(
            "pinned_path={}, obj_type={}, id={}, mount_fstype={}, obj_tag={}, file_identity={}, generation={}, boot_id={}",
            pin.path,
            pin.object_kind.label(),
            pin.object_id,
            pin.mount_fstype,
            pin.object_tag.as_deref().unwrap_or("unknown"),
            file_identity,
            pin.stamp.label(),
            pin.stamp.boot_id
        ));
    }

    if let Some(error) = conflict_error(snapshot) {
        // A conflicted generation may contain records from two object
        // lifetimes; publish the instability instead of those findings.
        return Err(error);
    }

    if findings.is_empty() {
        if errors.is_empty() {
            Ok(None)
        } else {
            Err(errors.join(", "))
        }
    } else {
        findings.sort();
        if !errors.is_empty() {
            findings.push(format!("collection_errors={}", errors.join(", ")));
        }
        Ok(Some(findings.join("\n")))
    }
}

fn mount_type_for(pin: &PinRecord) -> &str {
    pin.mount_fstype.as_str()
}

fn collect_pins(snapshot: &BpfSnapshot) -> &[PinRecord] {
    &snapshot.pins
}
