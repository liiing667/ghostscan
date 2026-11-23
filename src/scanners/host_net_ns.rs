use super::container_utils::{collect_container_states, ContainerInventory};
use crate::host_observation::HostObservation;
use crate::ScanOutcome;
use std::fs;
use std::path::{Path, PathBuf};

pub fn run() -> ScanOutcome {
    let host_ns = match host_namespace() {
        Ok(Some(host_ns)) => host_ns,
        Ok(None) => return Ok(None),
        Err(err) => return Err(err),
    };
    let inventory = collect_container_states(1024);
    scan(&host_ns, &inventory)
}

pub fn run_with_host(host: &HostObservation) -> ScanOutcome {
    let host_ns = match host_namespace() {
        Ok(Some(host_ns)) => host_ns,
        Ok(None) => return Ok(None),
        Err(err) => return Err(err),
    };
    match host.containers() {
        Ok(inventory) => scan(&host_ns, inventory),
        Err(err) => Err(err.to_string()),
    }
}

fn host_namespace() -> Result<Option<PathBuf>, String> {
    match fs::read_link("/proc/1/ns/net") {
        Ok(link) => Ok(Some(link)),
        Err(err) => {
            if err.kind() == std::io::ErrorKind::PermissionDenied {
                return Ok(None);
            }
            Err(format!("failed to read host net ns: {err}"))
        }
    }
}

fn scan(host_ns: &Path, inventory: &ContainerInventory) -> ScanOutcome {
    let mut findings = Vec::new();
    let errors = &inventory.errors;

    for state in &inventory.states {
        if let Some(pid) = state.pid {
            match fs::read_link(format!("/proc/{pid}/ns/net")) {
                Ok(link) => {
                    if link.as_path() == host_ns {
                        findings.push(format!("container_id={}, host_net_ns=true", state.id));
                    }
                }
                Err(err) => {
                    if err.kind() != std::io::ErrorKind::PermissionDenied {
                        continue;
                    }
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
