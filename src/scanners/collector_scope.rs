use std::{fs, path::Path};

/// Namespace identity shared by every procfs/netlink/BPF collector in one pass.
///
/// Keeping both namespace inodes next to the process/socket identity is what
/// makes it impossible to join a PID from one container with a socket from
/// another container that happens to reuse the same numeric ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CollectorScope {
    pub netns_inum: u32,
    pub pidns_inum: u32,
}

impl CollectorScope {
    pub fn current() -> Result<Self, String> {
        Ok(Self {
            netns_inum: current_netns_inum()?,
            pidns_inum: current_pidns_inum()?,
        })
    }
}

pub fn current_netns_inum() -> Result<u32, String> {
    namespace_inum("/proc/self/ns/net", "netns")
}

pub fn current_pidns_inum() -> Result<u32, String> {
    namespace_inum("/proc/self/ns/pid", "pidns")
}

fn namespace_inum(path: &str, kind: &str) -> Result<u32, String> {
    namespace_inum_from_path(Path::new(path), kind)
}

fn namespace_inum_from_path(path: &Path, kind: &str) -> Result<u32, String> {
    let link =
        fs::read_link(path).map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let target = link.to_string_lossy();
    let start = target
        .rfind('[')
        .ok_or_else(|| format!("unexpected {kind} symlink target: {target}"))?;
    let end = target[start + 1..]
        .find(']')
        .map(|idx| start + 1 + idx)
        .ok_or_else(|| format!("unexpected {kind} symlink target: {target}"))?;
    let slice = &target[start + 1..end];
    let value = slice
        .parse::<u64>()
        .map_err(|err| format!("failed to parse {kind} inum from '{}': {err}", target))?;
    if value > u32::MAX as u64 {
        return Err(format!("{kind} inum {} exceeds u32 range", value));
    }
    Ok(value as u32)
}

#[cfg(all(test, unix))]
mod tests {
    use super::namespace_inum_from_path;
    use std::fs;
    use std::os::unix::fs::symlink;

    #[test]
    fn parses_namespace_inode_from_link_target() {
        let dir = std::env::temp_dir().join(format!("ghostscan-scope-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let link = dir.join("net");
        symlink("net:[4026532679]", &link).unwrap();

        assert_eq!(
            namespace_inum_from_path(&link, "netns").unwrap(),
            4026532679
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
