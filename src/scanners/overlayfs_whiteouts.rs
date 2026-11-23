use super::discovery::snapshot;
use crate::ScanOutcome;
use std::{
    collections::VecDeque,
    fs,
    path::Path,
};

pub fn run() -> ScanOutcome {
    let discovery = snapshot();
    if let Some(err) = &discovery.mountinfo_error {
        return Err(format!("failed to read mountinfo: {err}"));
    }

    let mut findings = Vec::new();
    for mount in &discovery.mounts {
        if mount.fs_type != "overlay" {
            continue;
        }
        let root = mount.mount_point_path();
        if !root.exists() {
            continue;
        }
        match scan_mount(&root, 5000) {
            Ok(mut list) => findings.append(&mut list),
            Err(err) => findings.push(format!("{}: {}", root.display(), err)),
        }
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        findings.sort();
        Ok(Some(findings.join("\n")))
    }
}

fn scan_mount(root: &Path, limit: usize) -> Result<Vec<String>, String> {
    let mut findings = Vec::new();
    let mut queue = VecDeque::new();
    queue.push_back(root.to_path_buf());
    let mut visited = 0usize;

    while let Some(dir) = queue.pop_front() {
        if visited >= limit {
            break;
        }
        visited += 1;

        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) => {
                if let Some(13) = err.raw_os_error() {
                    continue;
                }
                return Err(format!("failed to read {}: {err}", dir.display()));
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name == ".wh..wh..opq" {
                        findings.push(format!("path={}, kind=opaque", path.display()));
                        continue;
                    }
                }
                queue.push_back(path);
            } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with(".wh.") {
                    findings.push(format!("path={}, kind=whiteout", path.display()));
                }
            }
        }
    }

    Ok(findings)
}
