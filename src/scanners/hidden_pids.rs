use super::task_snapshot::{
    BpfTaskSnapshot, ProcTaskSnapshot, collect_bpf_tasks, collect_proc_tasks,
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

    let findings = bpf_only_findings(&bpf_snapshot, &proc_snapshot);
    finish(bpf_snapshot.errors, findings)
}

fn bpf_only_findings(
    bpf_snapshot: &BpfTaskSnapshot,
    proc_snapshot: &ProcTaskSnapshot,
) -> Vec<String> {
    let mut findings = Vec::new();

    for (key, record) in &bpf_snapshot.tasks {
        // A task from another PID namespace is not a hidden task in this
        // namespace, even when both namespaces assign the same numeric PID.
        if key.pidns_inum != proc_snapshot.pidns_inum {
            continue;
        }
        if proc_snapshot.tasks.contains_key(&key.pid) {
            continue;
        }

        let comm = record.comm.as_deref().unwrap_or("unknown");
        let sources = record.sources.join("|");
        findings.push(format!(
            "pid={}, pidns_inum={}, comm={}, seen_by=bpf_only, sources={}",
            key.pid, key.pidns_inum, comm, sources
        ));
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
    use crate::scanners::task_snapshot::{BpfTaskRecord, TaskKey};
    use std::collections::BTreeMap;

    #[test]
    fn other_namespace_pid_does_not_become_hidden_here() {
        let proc = ProcTaskSnapshot {
            pidns_inum: 700,
            tasks: BTreeMap::from([(1, "init".to_string())]),
        };
        let bpf = BpfTaskSnapshot {
            tasks: BTreeMap::from([
                (
                    TaskKey {
                        pidns_inum: 700,
                        pid: 1,
                    },
                    BpfTaskRecord {
                        comm: Some("init".to_string()),
                        sources: vec!["iter#7".to_string()],
                    },
                ),
                (
                    TaskKey {
                        pidns_inum: 700,
                        pid: 2,
                    },
                    BpfTaskRecord {
                        comm: Some("ghost".to_string()),
                        sources: vec!["iter#8".to_string()],
                    },
                ),
                (
                    TaskKey {
                        pidns_inum: 701,
                        pid: 1,
                    },
                    BpfTaskRecord {
                        comm: Some("other-container".to_string()),
                        sources: vec!["iter#9".to_string()],
                    },
                ),
            ]),
            errors: Vec::new(),
        };

        let findings = bpf_only_findings(&bpf, &proc);

        assert_eq!(
            findings,
            vec![
                "pid=2, pidns_inum=700, comm=ghost, seen_by=bpf_only, sources=iter#8"
                    .to_string()
            ]
        );
    }

    #[test]
    fn empty_snapshots_stay_clean() {
        assert!(matches!(
            finish(Vec::new(), Vec::new()),
            Ok(None)
        ));
        assert_eq!(
            finish(vec!["map truncated".to_string()], Vec::new()),
            Err("map truncated".to_string())
        );
    }
}
