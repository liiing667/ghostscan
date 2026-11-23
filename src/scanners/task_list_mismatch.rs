use super::task_snapshot::{
    BpfTaskSnapshot, ProcTaskSnapshot, TaskKey, collect_bpf_tasks, collect_proc_tasks,
};
use crate::ScanOutcome;

const MAP_SCAN_LIMIT: usize = 64;
const ENTRY_SCAN_LIMIT: usize = 65536;

pub fn run() -> ScanOutcome {
    let bpf_snapshot = match collect_bpf_tasks(MAP_SCAN_LIMIT, ENTRY_SCAN_LIMIT) {
        Ok(snapshot) => snapshot,
        Err(err) => return Err(err),
    };

    let proc_snapshot = match collect_proc_tasks() {
        Ok(snapshot) => snapshot,
        Err(err) => return Err(err),
    };

    if proc_snapshot.tasks.is_empty() {
        return Err("no tasks enumerated via /proc".to_string());
    }

    let findings = mismatch_findings(&bpf_snapshot, &proc_snapshot);
    finish(bpf_snapshot.errors, findings)
}

fn mismatch_findings(
    bpf_snapshot: &BpfTaskSnapshot,
    proc_snapshot: &ProcTaskSnapshot,
) -> Vec<String> {
    let mut findings = Vec::new();

    for (key, record) in &bpf_snapshot.tasks {
        if key.pidns_inum != proc_snapshot.pidns_inum {
            continue;
        }
        if proc_snapshot.tasks.contains_key(&key.pid) {
            continue;
        }

        let comm = record.comm.as_deref().unwrap_or("unknown");
        let sources = record.sources.join("|");
        findings.push(format!(
            "seen_by=bpf_only, pid={}, pidns_inum={}, comm={}, sources={}",
            key.pid, key.pidns_inum, comm, sources
        ));
    }

    for (pid, comm) in &proc_snapshot.tasks {
        let key = TaskKey {
            pidns_inum: proc_snapshot.pidns_inum,
            pid: *pid,
        };
        if !bpf_snapshot.tasks.contains_key(&key) {
            findings.push(format!(
                "seen_by=proc_only, pid={}, pidns_inum={}, comm={}",
                pid, key.pidns_inum, comm
            ));
        }
    }

    findings.sort();
    findings
}

fn finish(errors: Vec<String>, findings: Vec<String>) -> ScanOutcome {
    if findings.is_empty() {
        if errors.is_empty() {
            Ok(None)
        } else {
            Err(errors.join(", "))
        }
    } else {
        let mut findings = findings;
        if !errors.is_empty() {
            findings.push(format!("collection_errors={}", errors.join(", ")));
        }
        Ok(Some(findings.join("\n")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::task_snapshot::BpfTaskRecord;
    use std::collections::BTreeMap;

    #[test]
    fn same_pid_in_another_namespace_does_not_match_proc() {
        let proc = ProcTaskSnapshot {
            pidns_inum: 700,
            tasks: BTreeMap::from([(1, "init".to_string())]),
        };
        let bpf = BpfTaskSnapshot {
            tasks: BTreeMap::from([
                (
                    TaskKey {
                        pidns_inum: 700,
                        pid: 2,
                    },
                    BpfTaskRecord {
                        comm: Some("worker".to_string()),
                        sources: vec!["iter#7".to_string()],
                    },
                ),
                (
                    TaskKey {
                        pidns_inum: 701,
                        pid: 1,
                    },
                    BpfTaskRecord {
                        comm: Some("other-container".to_string()),
                        sources: vec!["iter#8".to_string()],
                    },
                ),
            ]),
            errors: Vec::new(),
        };

        let findings = mismatch_findings(&bpf, &proc);

        assert_eq!(findings.len(), 2, "findings: {findings:?}");
        assert!(findings
            .iter()
            .any(|line| line.contains("seen_by=bpf_only, pid=2, pidns_inum=700")));
        assert!(findings
            .iter()
            .any(|line| line.contains("seen_by=proc_only, pid=1, pidns_inum=700")));
        assert!(!findings
            .iter()
            .any(|line| line.contains("pidns_inum=701")));
    }
}
