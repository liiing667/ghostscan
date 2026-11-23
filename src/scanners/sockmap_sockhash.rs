use crate::bpf_lifecycle::{
    conflict_error, scanner_error, BpfSnapshot, BpfTransaction, CollectorKind, MapRecord,
    BPF_TRANSACTION,
};
use crate::ScanOutcome;

pub fn run() -> ScanOutcome {
    run_with_bpf(&BPF_TRANSACTION)
}

/// Sockmap/sockhash verdict scan sharing the caller's lifecycle transaction.
pub fn run_with_bpf(transaction: &BpfTransaction) -> ScanOutcome {
    let snapshot = transaction.snapshot();
    run_with_snapshot(&snapshot)
}

pub fn run_with_snapshot(snapshot: &BpfSnapshot) -> ScanOutcome {
    if let Some(error) = scanner_error(
        snapshot,
        CollectorKind::Maps,
        "bpftool not available to inspect SOCKMAP/SOCKHASH state",
    ) {
        return Err(error);
    }

    if let Some(error) = conflict_error(snapshot) {
        return Err(error);
    }

    let mut findings = Vec::new();

    for map in &snapshot.maps {
        let map_type = map.map_type.to_ascii_lowercase();
        if map_type != "sockmap" && map_type != "sockhash" {
            continue;
        }

        if has_pin(map) || !map.owner_pids.is_empty() {
            continue;
        }

        let verdict_prog = map
            .verdict_prog_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let verdict_tag = map
            .verdict_prog_tag
            .clone()
            .or_else(|| {
                map.verdict_prog_id
                    .and_then(|id| snapshot.program(id))
                    .map(|program| program.tag.clone())
            })
            .unwrap_or_else(|| "unknown".to_string());

        findings.push(format!(
            "map_id={}, type={}, verdict_prog_id={}, has_pin=false, owner_pids=∅, verdict_prog_tag={}, generation={}, boot_id={}",
            map.id,
            map.map_type,
            verdict_prog,
            verdict_tag,
            map.stamp.label(),
            map.stamp.boot_id
        ));
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        findings.sort();
        Ok(Some(findings.join("\n")))
    }
}

fn has_pin(map: &MapRecord) -> bool {
    map.pinned_flag || !map.pinned.is_empty()
}
