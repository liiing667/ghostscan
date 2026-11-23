use super::container_utils::collect_container_states;
use crate::ScanOutcome;
use std::fs;

pub fn run() -> ScanOutcome {
    let host_ns = match fs::read_link("/proc/1/ns/net") {
        Ok(link) => link,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::PermissionDenied {
                return Err(format!("permission denied reading host net ns: {err}"));
            }
            return Err(format!("failed to read host net ns: {err}"));
        }
    };

    let inventory = collect_container_states(1024);
    let mut findings = Vec::new();
    let mut errors = inventory.errors;

    for state in inventory.states {
        if let Some(pid) = state.pid {
            match fs::read_link(format!("/proc/{pid}/ns/net")) {
                Ok(link) => {
                    if link == host_ns {
                        findings.push(format!("container_id={}, host_net_ns=true", state.id));
                    }
                }
                Err(err) => {
                    if err.kind() == std::io::ErrorKind::PermissionDenied {
                        errors.push(format!(
                            "pid={} net namespace: permission denied",
                            pid
                        ));
                    }
                    // Other races (process exited, link vanished) are
                    // transient inventory churn rather than coverage loss.
                }
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
