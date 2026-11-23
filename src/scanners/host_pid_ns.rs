use super::discovery::{snapshot, NsResolution};
use crate::ScanOutcome;

pub fn run() -> ScanOutcome {
    let discovery = snapshot();
    let host_ns = match &discovery.host_pid_ns {
        NsResolution::Resolved(target) => target,
        NsResolution::PermissionDenied => return Ok(None),
        NsResolution::Failed(err) => return Err(format!("failed to read host pid ns: {err}")),
    };

    let mut findings = Vec::new();
    let errors = &discovery.inventory_errors;

    for state in &discovery.containers {
        if let Some(pid_ns) = &state.pid_ns {
            if pid_ns == host_ns {
                findings.push(format!("container_id={}, host_pid_ns=true", state.id));
            }
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
