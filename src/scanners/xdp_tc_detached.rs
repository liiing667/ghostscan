use crate::bpf_lifecycle::{
    conflict_error, scanner_error, BpfSnapshot, BpfTransaction, CollectorKind, BPF_TRANSACTION,
};
use crate::ScanOutcome;
use serde_json::Value;

fn value_has_meaningful_data(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(_) | Value::Number(_) => true,
        Value::String(s) => !s.trim().is_empty(),
        Value::Array(items) => items.iter().any(value_has_meaningful_data),
        Value::Object(map) => map.values().any(value_has_meaningful_data),
    }
}

pub fn run() -> ScanOutcome {
    run_with_bpf(&BPF_TRANSACTION)
}

/// XDP/TC scan sharing the caller's lifecycle transaction.
///
/// The raw `bpftool net list` payload is preserved because its shape is part of
/// the public scanner output; the generation label is carried by the shared
/// transaction summary printed after the scanner loop.
pub fn run_with_bpf(transaction: &BpfTransaction) -> ScanOutcome {
    let snapshot = transaction.snapshot();
    run_with_snapshot(&snapshot)
}

pub fn run_with_snapshot(snapshot: &BpfSnapshot) -> ScanOutcome {
    if let Some(error) = scanner_error(
        snapshot,
        CollectorKind::Net,
        "bpftool not available to inspect XDP/TC programs",
    ) {
        return Err(error);
    }

    if let Some(error) = conflict_error(snapshot) {
        return Err(error);
    }

    let Some(payload) = snapshot.net_list.as_deref() else {
        return Ok(None);
    };
    let payload = payload.trim();
    if payload.is_empty() {
        return Ok(None);
    }

    match serde_json::from_str::<Value>(payload) {
        Ok(value) if !value_has_meaningful_data(&value) => Ok(None),
        _ => Ok(Some(payload.to_string())),
    }
}
