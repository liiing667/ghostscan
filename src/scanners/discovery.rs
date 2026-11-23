//! Single discovery transaction for mount, namespace, and container state.
//!
//! Containers may switch mount namespaces, retry unmounts, or appear through
//! a second entry point while a scan is running. If every scanner re-reads
//! `/proc/self/mountinfo`, re-walks the container state roots, and re-resolves
//! namespaces on its own, one report can splice together two generations of
//! paths (e.g. attribute a mature sensitive host mount to a freshly created
//! container, or miss a brand-new overlay whiteout). To prevent that, every
//! consumer shares the snapshot built here exactly once per process.

use super::container_utils::{collect_container_states, ContainerMount};
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

const CONTAINER_STATE_LIMIT: usize = 1024;
const MOUNTINFO_PATH: &str = "/proc/self/mountinfo";
const HOST_PID_NS_PATH: &str = "/proc/1/ns/pid";
const HOST_NET_NS_PATH: &str = "/proc/1/ns/net";

/// One parsed `/proc/self/mountinfo` line, including the mount id that ties
/// a mount point to a single mount-table generation.
#[derive(Debug, Clone)]
pub struct MountEntry {
    pub id: u64,
    pub parent_id: Option<u64>,
    pub major_minor: String,
    pub root: String,
    pub mount_point: String,
    pub mount_options: Vec<String>,
    pub optional_fields: Vec<String>,
    pub fs_type: String,
    pub source: Option<String>,
    pub super_options: Vec<String>,
}

impl MountEntry {
    pub fn is_bind(&self) -> bool {
        self.optional_fields.iter().any(|field| field == "bind")
    }

    pub fn mount_point_path(&self) -> PathBuf {
        PathBuf::from(&self.mount_point)
    }

    pub fn has_super_option(&self, needle: &str) -> bool {
        self.super_options.iter().any(|opt| opt.contains(needle))
    }
}

/// Result of resolving a namespace symlink exactly once.
#[derive(Debug, Clone)]
pub enum NsResolution {
    Resolved(String),
    PermissionDenied,
    Failed(String),
}

/// A container observed inside the discovery transaction: inventory record
/// plus the namespace identity it held at observation time.
#[derive(Debug, Clone)]
pub struct ContainerObservation {
    pub id: String,
    pub pid: Option<u32>,
    pub mounts: Vec<ContainerMount>,
    pub pid_ns: Option<String>,
    pub net_ns: Option<String>,
}

/// Immutable snapshot shared by every mount/namespace/container scanner.
#[derive(Debug)]
pub struct Discovery {
    pub mounts: Vec<MountEntry>,
    pub mountinfo_error: Option<String>,
    pub containers: Vec<ContainerObservation>,
    pub inventory_errors: Vec<String>,
    pub host_pid_ns: NsResolution,
    pub host_net_ns: NsResolution,
}

static DISCOVERY: OnceLock<Discovery> = OnceLock::new();

/// Returns the one discovery transaction for this process. The first caller
/// triggers collection; every later caller (including second entry points)
/// reuses the same generation instead of re-reading divergent state.
pub fn snapshot() -> &'static Discovery {
    DISCOVERY.get_or_init(Discovery::collect)
}

impl Discovery {
    fn collect() -> Discovery {
        // One read, one parse: mount ids and mount points seen by any
        // scanner always belong to the same mount-table generation.
        let (mounts, mountinfo_error) = match fs::read_to_string(MOUNTINFO_PATH) {
            Ok(content) => (parse_mountinfo(&content), None),
            Err(err) => (Vec::new(), Some(err.to_string())),
        };

        // One container-inventory sweep shared by all container scanners.
        let inventory = collect_container_states(CONTAINER_STATE_LIMIT);

        // Namespace identity is captured alongside the inventory, so a
        // container switching namespaces mid-scan cannot mix two
        // generations of paths into one report.
        let host_pid_ns = read_namespace(HOST_PID_NS_PATH);
        let host_net_ns = read_namespace(HOST_NET_NS_PATH);

        let containers = inventory
            .states
            .into_iter()
            .map(|state| {
                let pid_ns = state
                    .pid
                    .and_then(|pid| read_namespace_target(&format!("/proc/{pid}/ns/pid")));
                let net_ns = state
                    .pid
                    .and_then(|pid| read_namespace_target(&format!("/proc/{pid}/ns/net")));
                ContainerObservation {
                    id: state.id,
                    pid: state.pid,
                    mounts: state.mounts,
                    pid_ns,
                    net_ns,
                }
            })
            .collect();

        Discovery {
            mounts,
            mountinfo_error,
            containers,
            inventory_errors: inventory.errors,
            host_pid_ns,
            host_net_ns,
        }
    }
}

fn read_namespace(path: &str) -> NsResolution {
    match fs::read_link(path) {
        Ok(link) => NsResolution::Resolved(link.display().to_string()),
        Err(err) => {
            if err.kind() == std::io::ErrorKind::PermissionDenied {
                NsResolution::PermissionDenied
            } else {
                NsResolution::Failed(err.to_string())
            }
        }
    }
}

fn read_namespace_target(path: &str) -> Option<String> {
    fs::read_link(path)
        .ok()
        .map(|link| link.display().to_string())
}

/// Parses mountinfo content into structured entries. Empty content yields an
/// empty table; malformed lines are skipped so one bad line cannot poison
/// the shared transaction.
pub fn parse_mountinfo(content: &str) -> Vec<MountEntry> {
    let mut mounts = Vec::new();

    for line in content.lines() {
        let Some((prefix, suffix)) = line.split_once(" - ") else {
            continue;
        };

        let prefix_fields: Vec<&str> = prefix.split_whitespace().collect();
        if prefix_fields.len() < 6 {
            continue;
        }

        let suffix_fields: Vec<&str> = suffix.split_whitespace().collect();
        if suffix_fields.len() < 3 {
            continue;
        }

        let id = match prefix_fields[0].parse::<u64>() {
            Ok(id) => id,
            Err(_) => continue,
        };
        let parent_id = prefix_fields[1].parse::<u64>().ok();

        mounts.push(MountEntry {
            id,
            parent_id,
            major_minor: prefix_fields[2].to_string(),
            root: decode_mount_field(prefix_fields[3]),
            mount_point: decode_mount_field(prefix_fields[4]),
            mount_options: split_options(prefix_fields[5]),
            optional_fields: prefix_fields[6..]
                .iter()
                .map(|field| field.to_string())
                .collect(),
            fs_type: suffix_fields[0].to_string(),
            source: Some(suffix_fields[1].to_string()),
            super_options: split_options(suffix_fields[2]),
        });
    }

    mounts
}

fn split_options(raw: &str) -> Vec<String> {
    raw.split(',')
        .filter(|opt| !opt.is_empty())
        .map(|opt| opt.to_string())
        .collect()
}

/// Decodes the octal escapes the kernel uses for spaces and control
/// characters in mountinfo path fields.
pub fn decode_mount_field(field: &str) -> String {
    let mut result = String::new();
    let mut chars = field.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let (Some(a), Some(b), Some(c)) = (chars.next(), chars.next(), chars.next()) {
                let code = [a, b, c];
                let decoded = match &code {
                    ['0', '4', '0'] => ' ',
                    ['0', '1', '1'] => '\t',
                    ['0', '1', '2'] => '\n',
                    ['0', '1', '3'] => '\r',
                    ['0', '1', '4'] => 0x0c as char,
                    ['0', '1', '5'] => 0x0b as char,
                    ['0', '1', '6'] => 0x0e as char,
                    ['0', '1', '7'] => 0x0f as char,
                    ['0', '1', '0'] => 0x08 as char,
                    ['1', '3', '4'] => '\\',
                    _ => {
                        result.push('\\');
                        result.push(a);
                        result.push(b);
                        result.push(c);
                        continue;
                    }
                };
                result.push(decoded);
            }
        } else {
            result.push(ch);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_legitimate_overlay_mount() {
        let content = "512 480 0:98 / /var/lib/docker/overlay2/abc/merged rw,relatime - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/A:/var/lib/docker/overlay2/l/B,upperdir=/var/lib/docker/overlay2/abc/diff,workdir=/var/lib/docker/overlay2/abc/work\n";
        let mounts = parse_mountinfo(content);
        assert_eq!(mounts.len(), 1);
        let mount = &mounts[0];
        assert_eq!(mount.id, 512);
        assert_eq!(mount.parent_id, Some(480));
        assert_eq!(mount.fs_type, "overlay");
        assert_eq!(mount.mount_point, "/var/lib/docker/overlay2/abc/merged");
        assert!(!mount.is_bind());
        assert!(mount
            .super_options
            .iter()
            .any(|opt| opt.starts_with("lowerdir=/var/lib/docker/")));
    }

    #[test]
    fn keeps_shared_and_bind_optional_fields() {
        let content = "28 22 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
                       40 28 8:1 / /etc rw,relatime bind - ext4 /dev/sda1 rw\n";
        let mounts = parse_mountinfo(content);
        assert_eq!(mounts.len(), 2);
        assert!(mounts[0]
            .optional_fields
            .iter()
            .any(|field| field.starts_with("shared:")));
        assert!(!mounts[0].is_bind());
        assert!(mounts[1].is_bind());
        assert!(!mounts[1]
            .optional_fields
            .iter()
            .any(|field| field.starts_with("shared:")));
    }

    #[test]
    fn empty_mountinfo_yields_empty_table() {
        assert!(parse_mountinfo("").is_empty());
        assert!(parse_mountinfo("\n\n").is_empty());
    }

    #[test]
    fn skips_malformed_lines_without_poisoning_transaction() {
        let content = "not a mount line\n\
                       40 28 8:1 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw,hidepid=2\n";
        let mounts = parse_mountinfo(content);
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].fs_type, "proc");
        assert!(mounts[0].has_super_option("hidepid=2"));
    }

    #[test]
    fn decodes_escaped_mount_points() {
        let content = "41 28 8:1 / /mnt/with\\040space rw - ext4 /dev/sda1 rw\n";
        let mounts = parse_mountinfo(content);
        assert_eq!(mounts[0].mount_point, "/mnt/with space");
    }
}
