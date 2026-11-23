use super::discovery::snapshot;
use crate::ScanOutcome;

const CRITICAL_PATHS: &[&str] = &["/etc", "/bin", "/sbin", "/usr", "/proc"];

pub fn run() -> ScanOutcome {
    let discovery = snapshot();
    if let Some(err) = &discovery.mountinfo_error {
        return Err(format!("failed to read mountinfo: {err}"));
    }

    let mut findings = Vec::new();

    for mount in &discovery.mounts {
        let mount_point = mount.mount_point.as_str();

        if mount.is_bind() {
            for critical in CRITICAL_PATHS {
                if mount_point == *critical || mount_point.starts_with(&format!("{critical}/")) {
                    findings.push(format!(
                        "mount_point={}, covering={}, anomaly=bind_over_system_path",
                        mount_point, critical
                    ));
                }
            }
        }

        if mount.fs_type == "proc" && mount.has_super_option("hidepid=2") {
            findings.push(format!(
                "mount_point={}, covering=/proc, anomaly=hidepid=2_on_/proc",
                mount_point
            ));
        }
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        findings.sort();
        Ok(Some(findings.join("\n")))
    }
}
