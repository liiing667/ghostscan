use super::discovery::snapshot;
use crate::ScanOutcome;
use serde_json::Value;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

pub fn run() -> ScanOutcome {
    if Command::new("bpftool")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        return Err("bpftool not available to inspect pinned objects".to_string());
    }

    let discovery = snapshot();
    if let Some(err) = &discovery.mountinfo_error {
        return Err(format!("failed to parse /proc/self/mountinfo: {err}"));
    }
    let mut mounts: Vec<(PathBuf, &str)> = discovery
        .mounts
        .iter()
        .map(|mount| (mount.mount_point_path(), mount.fs_type.as_str()))
        .collect();
    mounts.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));

    let mut pins = Vec::new();
    let mut errors = Vec::new();

    match collect_pins(["-j", "prog", "show"], "prog") {
        Ok(mut list) => pins.append(&mut list),
        Err(err) => errors.push(format!("prog: {err}")),
    }

    match collect_pins(["-j", "map", "show"], "map") {
        Ok(mut list) => pins.append(&mut list),
        Err(err) => errors.push(format!("map: {err}")),
    }

    match collect_pins(["-j", "link", "show"], "link") {
        Ok(mut list) => pins.append(&mut list),
        Err(err) => errors.push(format!("link: {err}")),
    }

    let mut findings = Vec::new();

    for pin in pins {
        let path = Path::new(&pin.path);
        let mount_type = mount_type_for(path, &mounts).unwrap_or("unknown");
        if mount_type != "bpf" {
            findings.push(format!(
                "pinned_path={}, obj_type={}, id={}, mount_fstype={}",
                pin.path, pin.obj_type, pin.id, mount_type
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

struct PinRecord {
    obj_type: &'static str,
    id: String,
    path: String,
}

fn collect_pins<const N: usize>(
    args: [&str; N],
    obj_type: &'static str,
) -> Result<Vec<PinRecord>, String> {
    let output = Command::new("bpftool")
        .args(args)
        .output()
        .map_err(|err| format!("failed to execute bpftool {obj_type} show: {err}"))?;

    if !output.status.success() {
        return Err(format!(
            "bpftool {obj_type} show exited with {}",
            output.status
        ));
    }

    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("failed to parse bpftool {obj_type} output: {err}"))?;

    let mut records = Vec::new();

    if let Some(array) = value.as_array() {
        for entry in array {
            let id = entry
                .get("id")
                .and_then(|v| v.as_u64())
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string());

            for path in extract_pin_paths(entry) {
                records.push(PinRecord {
                    obj_type,
                    id: id.clone(),
                    path,
                });
            }
        }
    }

    Ok(records)
}

fn extract_pin_paths(value: &Value) -> BTreeSet<String> {
    let mut set = BTreeSet::new();

    if let Some(pinned) = value.get("pinned") {
        collect_paths(pinned, &mut set);
    }

    if let Some(pins) = value.get("pins") {
        collect_paths(pins, &mut set);
    }

    set
}

fn collect_paths(value: &Value, set: &mut BTreeSet<String>) {
    match value {
        Value::String(s) => {
            if !s.is_empty() {
                set.insert(s.to_string());
            }
        }
        Value::Array(arr) => {
            for item in arr {
                collect_paths(item, set);
            }
        }
        Value::Object(map) => {
            for item in map.values() {
                collect_paths(item, set);
            }
        }
        _ => {}
    }
}

fn mount_type_for<'a>(path: &Path, mounts: &'a [(PathBuf, &'a str)]) -> Option<&'a str> {
    for entry in mounts {
        if path.starts_with(&entry.0) {
            return Some(entry.1);
        }
    }
    None
}
