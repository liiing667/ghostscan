use super::task_snapshot::{collect_bpf_tasks, collect_proc_tasks};
use super::task_snapshot::BpfTaskSnapshot;
use crate::host_observation::HostObservation;
use crate::ScanOutcome;
use std::collections::HashMap;

const MAP_SCAN_LIMIT: usize = 64;
const ENTRY_SCAN_LIMIT: usize = 65536;

pub fn run() -> ScanOutcome {
    let bpf_snapshot = match collect_bpf_tasks(MAP_SCAN_LIMIT, ENTRY_SCAN_LIMIT) {
        Ok(snapshot) => snapshot,
        Err(err) => return Err(err),
    };

    let proc_snapshot = match collect_proc_tasks() {
        Ok(map) => map,
        Err(err) => return Err(err),
    };

    scan(&bpf_snapshot, &proc_snapshot)
}

pub fn run_with_host(host: &HostObservation) -> ScanOutcome {
    let bpf_snapshot = match host.bpf_tasks() {
        Ok(snapshot) => snapshot,
        Err(err) => return Err(err.to_string()),
    };
    let proc_snapshot = match host.proc_tasks() {
        Ok(snapshot) => snapshot,
        Err(err) => return Err(err.to_string()),
    };

    scan(bpf_snapshot, proc_snapshot)
}

fn scan(
    bpf_snapshot: &BpfTaskSnapshot,
    proc_snapshot: &HashMap<i32, String>,
) -> ScanOutcome {
    let mut findings = Vec::new();
    let errors = &bpf_snapshot.errors;

    for (pid, record) in &bpf_snapshot.tasks {
        if !proc_snapshot.contains_key(pid) {
            let comm = record.comm.as_deref().unwrap_or("unknown");
            let sources = record.sources.join("|");
            findings.push(format!(
                "pid={}, comm={}, seen_by=bpf_only, sources={}",
                pid, comm, sources
            ));
        }
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
