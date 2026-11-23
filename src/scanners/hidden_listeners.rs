use super::collector_scope::CollectorScope;
use crate::ScanOutcome;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    process::{Command, Stdio},
};

const BPF_LISTENER_ENTRY_LIMIT: usize = 65536;

/// Identity of one socket in one network namespace.
///
/// Endpoints are metadata, not identity: an endpoint can be closed and rebound
/// with a different socket inode (and often a different owner PID). Joining
/// collectors by endpoint is therefore unsafe across retries and namespaces.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SocketKey {
    netns_inum: u32,
    inode: u64,
    proto: String,
    local: String,
    remote: String,
}

#[derive(Clone, Debug)]
struct NetlinkEntry {
    pids: BTreeSet<u32>,
    pidns_inum: u32,
}

#[derive(Clone, Debug)]
struct BpfListenerRecord {
    sources: BTreeSet<String>,
    state: Option<u32>,
}

impl BpfListenerRecord {
    fn new(source: &str, state: Option<u32>) -> Self {
        let mut sources = BTreeSet::new();
        sources.insert(source.to_string());
        Self { sources, state }
    }

    fn merge(&mut self, source: &str, state: Option<u32>) {
        if let Some(value) = state {
            if self.state.is_none() {
                self.state = Some(value);
            }
        }
        self.sources.insert(source.to_string());
    }

    fn format_sources(&self) -> String {
        self.sources
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("|")
    }
}

#[derive(Default)]
struct BpfListenerSnapshot {
    entries: BTreeMap<SocketKey, BpfListenerRecord>,
    errors: Vec<String>,
}

#[derive(Default)]
struct ListenerTables {
    netlink: BTreeMap<SocketKey, NetlinkEntry>,
    proc: BTreeSet<SocketKey>,
    bpf: BTreeMap<SocketKey, BpfListenerRecord>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct BpfListenerKey {
    inode: u64,
    netns_inum: u32,
    proto: u8,
    family: u8,
    port: u16,
    addr: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct BpfListenerValue {
    state: u32,
    netns_inum: u32,
    inode: u64,
}

fn listener_identity_matches(key: &BpfListenerKey, value: &BpfListenerValue) -> bool {
    key.netns_inum == value.netns_inum && key.inode == value.inode
}

#[cfg(target_os = "linux")]
mod bpf_support {
    use super::{
        BpfListenerKey, BpfListenerRecord, BpfListenerSnapshot, BpfListenerValue,
        decode_listener_key, listener_identity_matches,
    };
    use libbpf_rs::{AsRawLibbpf, Iter, Link, MapFlags, ObjectBuilder};
    use std::io::Read;
    use std::mem;
    use std::ptr::{self, NonNull};

    const BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/hidden_listeners.bpf.o"));
    const MAP_NAME: &str = "ghostscan_listener_sockets";
    const TCP_PROG: &str = "ghostscan_iter_tcp";
    const UDP_PROG: &str = "ghostscan_iter_udp";
    const TCP_SOURCE: &str = "ghostscan_bpf_tcp_iter";
    const UDP_SOURCE: &str = "ghostscan_bpf_udp_iter";

    pub(super) fn collect_listeners(entry_limit: usize) -> Result<BpfListenerSnapshot, String> {
        let mut snapshot = BpfListenerSnapshot::default();
        if entry_limit == 0 {
            return Err("entry_limit must be non-zero".to_string());
        }

        if let Err(err) = bump_memlock_limit() {
            snapshot.errors.push(err);
        }

        // A fresh object/map is loaded for every collector pass. A retry can
        // therefore never read entries left behind by the previous attempt.
        let mut builder = ObjectBuilder::default();
        builder.relaxed_maps(true);

        let mut obj = match builder
            .open_memory(BPF_OBJECT)
            .map_err(|err| format!("failed to open embedded hidden listener BPF: {err}"))?
            .load()
            .map_err(|err| format!("failed to load embedded hidden listener BPF: {err}"))
        {
            Ok(obj) => obj,
            Err(err) => {
                snapshot.errors.push(err);
                return Ok(snapshot);
            }
        };

        if let Err(err) = run_iter(&mut obj, TCP_PROG) {
            snapshot.errors.push(err);
        }
        if let Err(err) = run_iter(&mut obj, UDP_PROG) {
            snapshot.errors.push(err);
        }

        let map = match obj.map(MAP_NAME) {
            Some(map) => map,
            None => {
                snapshot
                    .errors
                    .push("embedded listener map missing".to_string());
                return Ok(snapshot);
            }
        };

        let key_size = mem::size_of::<BpfListenerKey>();
        let value_size = mem::size_of::<BpfListenerValue>();
        let mut processed = 0usize;

        for key_bytes in map.keys() {
            if processed >= entry_limit {
                snapshot
                    .errors
                    .push(format!("listener map truncated at {} entries", entry_limit));
                break;
            }

            if key_bytes.len() < key_size {
                snapshot
                    .errors
                    .push("listener map returned a truncated key".to_string());
                continue;
            }

            processed += 1;

            let key = unsafe { ptr::read_unaligned(key_bytes.as_ptr() as *const BpfListenerKey) };

            let value = match map.lookup(&key_bytes, MapFlags::ANY) {
                Ok(Some(bytes)) if bytes.len() >= value_size => unsafe {
                    ptr::read_unaligned(bytes.as_ptr() as *const BpfListenerValue)
                },
                Ok(Some(_)) => {
                    snapshot.errors.push(format!(
                        "listener value truncated for netns {} inode {}",
                        key.netns_inum, key.inode
                    ));
                    continue;
                }
                Ok(None) => {
                    snapshot.errors.push(format!(
                        "listener value missing for netns {} inode {}",
                        key.netns_inum, key.inode
                    ));
                    continue;
                }
                Err(err) => {
                    snapshot
                        .errors
                        .push(format!("listener map lookup failed: {err}"));
                    continue;
                }
            };

            if !listener_identity_matches(&key, &value) {
                snapshot.errors.push(format!(
                    "listener key/value identity mismatch: key netns {} inode {}, value netns {} inode {}",
                    key.netns_inum, key.inode, value.netns_inum, value.inode
                ));
                continue;
            }

            let (socket_key, source) = match decode_listener_key(&key) {
                Some(socket_key) => {
                    let source = match key.proto {
                        6 => TCP_SOURCE,
                        17 => UDP_SOURCE,
                        _ => continue,
                    };
                    (socket_key, source)
                }
                None => continue,
            };

            let record = snapshot
                .entries
                .entry(socket_key)
                .or_insert_with(|| BpfListenerRecord::new(source, Some(value.state)));
            record.merge(source, Some(value.state));
        }

        Ok(snapshot)
    }

    fn run_iter(obj: &mut libbpf_rs::Object, prog_name: &str) -> Result<(), String> {
        let mut prog = obj
            .prog_mut(prog_name)
            .ok_or_else(|| format!("embedded listener program '{}' missing", prog_name))?;
        let link = attach_iter(&mut prog)
            .map_err(|err| format!("failed to attach {}: {err}", prog_name))?;
        let mut iter = Iter::new(&link)
            .map_err(|err| format!("failed to create iterator for {}: {err}", prog_name))?;
        let mut drain = [0u8; 4096];
        while iter
            .read(&mut drain)
            .map_err(|err| format!("failed to drain iterator for {}: {err}", prog_name))?
            > 0
        {}
        drop(iter);
        drop(link);
        Ok(())
    }

    fn attach_iter(prog: &mut libbpf_rs::Program) -> Result<Link, libbpf_rs::Error> {
        unsafe {
            let prog_ptr = prog.as_libbpf_object();
            let mut link_info = libbpf_sys::bpf_iter_link_info::default();
            let attach_opts = libbpf_sys::bpf_iter_attach_opts {
                link_info: &mut link_info as *mut libbpf_sys::bpf_iter_link_info,
                link_info_len: mem::size_of::<libbpf_sys::bpf_iter_link_info>() as _,
                sz: mem::size_of::<libbpf_sys::bpf_iter_attach_opts>() as _,
                ..Default::default()
            };

            let raw = libbpf_sys::bpf_program__attach_iter(
                prog_ptr.as_ptr(),
                &attach_opts as *const libbpf_sys::bpf_iter_attach_opts,
            );
            if raw.is_null() {
                let errno = std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EPERM);
                return Err(libbpf_rs::Error::from_raw_os_error(errno));
            }

            let err = libbpf_sys::libbpf_get_error(raw.cast());
            if err != 0 {
                return Err(libbpf_rs::Error::from_raw_os_error(-err as i32));
            }

            let ptr = NonNull::new(raw)
                .ok_or_else(|| libbpf_rs::Error::from_raw_os_error(libc::EINVAL))?;
            Ok(Link::from_ptr(ptr))
        }
    }

    fn bump_memlock_limit() -> Result<(), String> {
        let rlimit = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            Err(format!("failed to raise memlock rlimit: {err}"))
        } else {
            Ok(())
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod bpf_support {
    use super::BpfListenerSnapshot;

    pub(super) fn collect_listeners(_entry_limit: usize) -> Result<BpfListenerSnapshot, String> {
        let mut snapshot = BpfListenerSnapshot::default();
        snapshot
            .errors
            .push("BPF listener collection not supported on this platform".to_string());
        Ok(snapshot)
    }
}

fn decode_listener_key(key: &BpfListenerKey) -> Option<SocketKey> {
    let proto_name = match key.proto {
        6 => "tcp",
        17 => "udp",
        _ => return None,
    };

    let (local_ip, remote_ip) = match key.family {
        2 => {
            let mut raw = [0u8; 4];
            raw.copy_from_slice(&key.addr[..4]);
            (
                IpAddr::V4(Ipv4Addr::from(raw)),
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            )
        }
        10 => {
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&key.addr);
            (
                IpAddr::V6(Ipv6Addr::from(raw)),
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            )
        }
        _ => return None,
    };

    Some(SocketKey {
        netns_inum: key.netns_inum,
        inode: key.inode,
        proto: proto_name.to_string(),
        local: format_endpoint(local_ip, key.port),
        remote: format_endpoint(remote_ip, 0),
    })
}

fn collect_bpf_listeners(entry_limit: usize) -> Result<BpfListenerSnapshot, String> {
    bpf_support::collect_listeners(entry_limit)
}

pub fn run() -> ScanOutcome {
    if Command::new("ss")
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        return Err("ss not available to query listeners".to_string());
    }

    // A collector pass must have one namespace identity. Without it, a PID or
    // inode from one namespace could be compared with a socket in another.
    let scope = match CollectorScope::current() {
        Ok(scope) => scope,
        Err(err) => return Err(err),
    };

    let mut errors = Vec::new();

    let bpf_snapshot = match collect_bpf_listeners(BPF_LISTENER_ENTRY_LIMIT) {
        Ok(snapshot) => snapshot,
        Err(err) => {
            errors.push(err);
            BpfListenerSnapshot::default()
        }
    };

    errors.extend(bpf_snapshot.errors.iter().cloned());

    let mut tables = ListenerTables {
        bpf: bpf_snapshot.entries,
        ..ListenerTables::default()
    };

    for (flags, proto) in [(["-l", "-t"], "tcp"), (["-l", "-u"], "udp")] {
        match collect_ss(&flags, proto, scope.netns_inum, scope.pidns_inum) {
            Ok(map) => tables.netlink.extend(map),
            Err(err) => errors.push(err),
        }

        match collect_proc(proto, scope.netns_inum) {
            Ok(map) => tables.proc.extend(map),
            Err(err) => errors.push(err),
        }
    }

    let mut scopes = BTreeSet::new();
    scopes.insert(scope.netns_inum);
    let findings = evaluate_listeners(&tables, &scopes);
    finish_listener_scan(findings, errors)
}

fn finish_listener_scan(findings: Vec<String>, errors: Vec<String>) -> ScanOutcome {
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

/// Compare only records with the same `(netns, inode, endpoint)` identity.
///
/// This function is deliberately pure so the cross-namespace/retry guarantees
/// can be checked with fixed snapshots without requiring BPF privileges.
fn evaluate_listeners(tables: &ListenerTables, scopes: &BTreeSet<u32>) -> Vec<String> {
    let mut findings = Vec::new();

    for netns_inum in scopes {
        for (key, entry) in &tables.netlink {
            if key.netns_inum != *netns_inum || tables.proc.contains(key) {
                continue;
            }

            let bpf_record = tables.bpf.get(key);
            let mut segments = listener_segments(key);

            let mut seen_by = vec!["netlink".to_string()];
            if let Some(record) = bpf_record {
                seen_by.push("bpf".to_string());
                segments.push(format!("bpf_sources={}", record.format_sources()));
                if let Some(state) = record.state {
                    segments.push(format!("bpf_state={state}"));
                }
            }
            segments.push(format!("seen_by={}", seen_by.join("|")));

            let mut missing = vec!["proc".to_string()];
            if bpf_record.is_none() {
                missing.push("bpf".to_string());
            }
            segments.push(format!("missing={}", missing.join("|")));
            segments.push(format!("owner_pids={}", format_owner_pids(&entry.pids)));
            segments.push(format!("owner_pidns_inum={}", entry.pidns_inum));

            findings.push(segments.join(", "));
        }

        for (key, record) in &tables.bpf {
            if key.netns_inum != *netns_inum || tables.netlink.contains_key(key) {
                continue;
            }

            let proc_seen = tables.proc.contains(key);
            let mut segments = listener_segments(key);

            let mut seen_by = vec!["bpf".to_string()];
            if proc_seen {
                seen_by.push("proc".to_string());
            }
            segments.push(format!("seen_by={}", seen_by.join("|")));

            let mut missing = vec!["netlink".to_string()];
            if !proc_seen {
                missing.push("proc".to_string());
            }
            segments.push(format!("missing={}", missing.join("|")));
            segments.push(format!("bpf_sources={}", record.format_sources()));
            if let Some(state) = record.state {
                segments.push(format!("bpf_state={state}"));
            }

            findings.push(segments.join(", "));
        }
    }

    findings.sort();
    findings
}

fn listener_segments(key: &SocketKey) -> Vec<String> {
    vec![
        format!("netns_inum={}", key.netns_inum),
        format!("inode={}", key.inode),
        format!("proto={}", key.proto),
        format!("laddr={}", key.local),
        format!("raddr={}", key.remote),
    ]
}

fn collect_ss(
    flags: &[&str],
    proto: &str,
    netns_inum: u32,
    pidns_inum: u32,
) -> Result<BTreeMap<SocketKey, NetlinkEntry>, String> {
    let mut args = vec!["-H", "-n", "-a", "-p"];
    args.extend_from_slice(flags);
    let output = Command::new("ss")
        .args(&args)
        .output()
        .map_err(|err| format!("failed to execute ss {}: {err}", flags.join("")))?;

    if !output.status.success() {
        return Err(format!(
            "ss {} exited with {}",
            flags.join(""),
            output.status
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut map = BTreeMap::new();

    for line in stdout.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 5 {
            continue;
        }
        let local = match normalize_endpoint(tokens[3]) {
            Some(value) => value,
            None => continue,
        };
        let remote = match normalize_endpoint(tokens[4]) {
            Some(value) => value,
            None => continue,
        };

        let key = SocketKey {
            netns_inum,
            inode: extract_inode(line).unwrap_or(0),
            proto: proto.to_string(),
            local,
            remote,
        };

        let entry = map.entry(key).or_insert_with(|| NetlinkEntry {
            pids: BTreeSet::new(),
            pidns_inum,
        });
        entry.pids.extend(extract_pids(line));
    }

    Ok(map)
}

fn extract_inode(line: &str) -> Option<u64> {
    line.split_whitespace()
        .find_map(|segment| segment.strip_prefix("ino:"))
        .and_then(|inode| inode.parse::<u64>().ok())
}

fn extract_pids(line: &str) -> BTreeSet<u32> {
    let mut pids = BTreeSet::new();
    let mut remaining = line;
    while let Some(idx) = remaining.find("pid=") {
        let tail = &remaining[idx + 4..];
        let pid_str: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(pid) = pid_str.parse::<u32>() {
            pids.insert(pid);
        }
        remaining = &tail[pid_str.len()..];
    }
    pids
}

fn format_owner_pids(pids: &BTreeSet<u32>) -> String {
    if pids.is_empty() {
        "∅".to_string()
    } else {
        pids.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("|")
    }
}

fn normalize_endpoint(raw: &str) -> Option<String> {
    if raw == "*" {
        return Some("0.0.0.0:0".to_string());
    }

    if raw.starts_with('[') {
        let end = raw.rfind(']')?;
        let addr = &raw[1..end];
        let port = raw.get(end + 2..).unwrap_or("0");
        let port = port.parse::<u16>().unwrap_or(0);
        let ip = addr.parse::<Ipv6Addr>().unwrap_or(Ipv6Addr::UNSPECIFIED);
        return Some(format!("[{}]:{}", ip, port));
    }

    if let Some(idx) = raw.rfind(':') {
        let addr = &raw[..idx];
        let port = raw[idx + 1..].parse::<u16>().unwrap_or(0);
        let ip = addr
            .parse::<Ipv4Addr>()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        return Some(format_endpoint(ip, port));
    }

    None
}

fn collect_proc(proto: &str, netns_inum: u32) -> Result<BTreeSet<SocketKey>, String> {
    let mut map = BTreeSet::new();
    let files = [
        format!("/proc/net/{proto}"),
        format!("/proc/net/{}6", proto),
    ];

    for path in files {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        let ipv6 = path.ends_with('6');
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }

            let state = fields[3];
            if proto == "tcp" && state != "0A" {
                continue;
            }

            let local = match parse_proc_endpoint(fields[1], ipv6) {
                Some(value) => value,
                None => continue,
            };
            let remote = match parse_proc_endpoint(fields[2], ipv6) {
                Some(value) => value,
                None => continue,
            };
            let Ok(inode) = fields[9].parse::<u64>() else {
                continue;
            };

            map.insert(SocketKey {
                netns_inum,
                inode,
                proto: proto.to_string(),
                local,
                remote,
            });
        }
    }

    Ok(map)
}

fn parse_proc_endpoint(raw: &str, ipv6: bool) -> Option<String> {
    let mut parts = raw.split(':');
    let addr_hex = parts.next()?;
    let port_hex = parts.next()?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    if ipv6 {
        let ip = parse_ipv6(addr_hex)?;
        Some(format_endpoint(IpAddr::V6(ip), port))
    } else {
        let ip = parse_ipv4(addr_hex)?;
        Some(format_endpoint(IpAddr::V4(ip), port))
    }
}

fn parse_ipv4(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    let mut bytes = [0u8; 4];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let value = std::str::from_utf8(chunk).ok()?;
        bytes[i] = u8::from_str_radix(value, 16).ok()?;
    }
    bytes.reverse();
    Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

fn parse_ipv6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let value = std::str::from_utf8(chunk).ok()?;
        bytes[i] = u8::from_str_radix(value, 16).ok()?;
    }
    for chunk in bytes.chunks_mut(4) {
        chunk.reverse();
    }
    Some(Ipv6Addr::from(bytes))
}

fn format_endpoint(addr: IpAddr, port: u16) -> String {
    match addr {
        IpAddr::V4(v4) => format!("{}:{}", v4, port),
        IpAddr::V6(v6) => format!("[{}]:{}", v6, port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    fn socket_key(
        netns_inum: u32,
        inode: u64,
        proto: &str,
        local: &str,
        remote: &str,
    ) -> SocketKey {
        SocketKey {
            netns_inum,
            inode,
            proto: proto.to_string(),
            local: local.to_string(),
            remote: remote.to_string(),
        }
    }

    fn netlink_entry(pidns_inum: u32, pids: &[u32]) -> NetlinkEntry {
        NetlinkEntry {
            pids: pids.iter().copied().collect(),
            pidns_inum,
        }
    }

    #[test]
    fn same_endpoint_after_retry_never_reuses_old_pid() {
        let endpoint = ("tcp", "0.0.0.0:8080", "0.0.0.0:0");
        let old_socket = socket_key(100, 11, endpoint.0, endpoint.1, endpoint.2);
        let new_socket = socket_key(100, 12, endpoint.0, endpoint.1, endpoint.2);

        let mut tables = ListenerTables::default();
        tables
            .netlink
            .insert(old_socket, netlink_entry(700, &[111]));
        tables.proc.insert(new_socket);

        let findings = evaluate_listeners(&tables, &BTreeSet::from([100u32]));

        assert_eq!(
            findings,
            vec![
                "netns_inum=100, inode=11, proto=tcp, laddr=0.0.0.0:8080, raddr=0.0.0.0:0, seen_by=netlink, missing=proc|bpf, owner_pids=111, owner_pidns_inum=700"
                    .to_string()
            ]
        );
    }

    #[test]
    fn bpf_record_never_moves_to_a_reused_endpoint() {
        let endpoint = ("tcp", "0.0.0.0:8080", "0.0.0.0:0");
        let old_socket = socket_key(100, 11, endpoint.0, endpoint.1, endpoint.2);
        let new_socket = socket_key(100, 12, endpoint.0, endpoint.1, endpoint.2);

        let mut tables = ListenerTables::default();
        tables
            .netlink
            .insert(old_socket, netlink_entry(700, &[111]));
        tables.proc.insert(new_socket.clone());
        tables
            .bpf
            .insert(new_socket, BpfListenerRecord::new("bpf#9", Some(10)));

        let findings = evaluate_listeners(&tables, &BTreeSet::from([100u32]));

        assert_eq!(findings.len(), 2, "findings: {findings:?}");
        let old_line = findings
            .iter()
            .find(|line| line.contains("inode=11"))
            .unwrap();
        let new_line = findings
            .iter()
            .find(|line| line.contains("inode=12"))
            .unwrap();
        assert!(old_line.contains("owner_pids=111"), "{old_line}");
        assert!(old_line.contains("seen_by=netlink"), "{old_line}");
        assert!(!old_line.contains("bpf_sources"), "{old_line}");
        assert!(new_line.contains("bpf_sources=bpf#9"), "{new_line}");
        assert!(!new_line.contains("owner_pids=111"), "{new_line}");
    }

    #[test]
    fn identical_endpoints_in_two_netns_are_not_joined() {
        let endpoint = ("tcp", "0.0.0.0:8080", "0.0.0.0:0");
        let hidden = socket_key(100, 11, endpoint.0, endpoint.1, endpoint.2);
        let visible = socket_key(200, 22, endpoint.0, endpoint.1, endpoint.2);

        let mut tables = ListenerTables::default();
        tables
            .netlink
            .insert(hidden, netlink_entry(700, &[111]));
        tables
            .netlink
            .insert(visible.clone(), netlink_entry(800, &[222]));
        tables.proc.insert(visible);

        let findings = evaluate_listeners(&tables, &BTreeSet::from([100u32, 200]));

        assert_eq!(findings.len(), 1, "findings: {findings:?}");
        assert!(findings[0].contains("netns_inum=100"), "{}", findings[0]);
        assert!(findings[0].contains("inode=11"), "{}", findings[0]);
        assert!(findings[0].contains("owner_pids=111"), "{}", findings[0]);
    }

    #[test]
    fn ipv4_and_ipv6_keep_distinct_socket_identity() {
        let v4 = socket_key(100, 11, "tcp", "0.0.0.0:8080", "0.0.0.0:0");
        let v6 = socket_key(100, 12, "tcp", "[::]:8080", "[::]:0");

        let mut tables = ListenerTables::default();
        tables.netlink.insert(v4, netlink_entry(700, &[111]));
        tables.netlink.insert(v6, netlink_entry(700, &[112]));

        let findings = evaluate_listeners(&tables, &BTreeSet::from([100u32]));

        assert_eq!(findings.len(), 2, "findings: {findings:?}");
        assert!(findings
            .iter()
            .any(|line| line.contains("laddr=0.0.0.0:8080")));
        assert!(findings
            .iter()
            .any(|line| line.contains("laddr=[::]:8080")));
    }

    #[test]
    fn empty_tables_are_clean_and_truncation_errors_are_kept() {
        assert!(matches!(
            finish_listener_scan(Vec::new(), Vec::new()),
            Ok(None)
        ));
        #[cfg(target_os = "linux")]
        assert!(matches!(
            collect_bpf_listeners(0),
            Err(err) if err == "entry_limit must be non-zero"
        ));
        assert_eq!(
            finish_listener_scan(Vec::new(), vec!["listener map truncated".to_string()]),
            Err("listener map truncated".to_string())
        );
    }

    #[test]
    fn bpf_key_and_value_must_describe_the_same_object() {
        assert_eq!(mem::size_of::<BpfListenerKey>(), 32);
        assert_eq!(mem::size_of::<BpfListenerValue>(), 16);
        let key = BpfListenerKey {
            inode: 11,
            netns_inum: 100,
            proto: 6,
            family: 2,
            port: 8080,
            addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let decoded = decode_listener_key(&key).unwrap();
        assert_eq!(decoded.netns_inum, 100);
        assert_eq!(decoded.inode, 11);
        assert_eq!(decoded.local, "127.0.0.1:8080");

        let mut value = BpfListenerValue {
            state: 10,
            netns_inum: 100,
            inode: 12,
        };
        assert!(!listener_identity_matches(&key, &value));
        value.inode = key.inode;
        assert!(listener_identity_matches(&key, &value));
    }

    #[test]
    fn proc_endpoint_parser_supports_ipv4_and_ipv6() {
        assert_eq!(
            parse_proc_endpoint("0100007F:1F90", false),
            Some("127.0.0.1:8080".to_string())
        );
        assert_eq!(
            parse_proc_endpoint("00000000000000000000000000000000:1F90", true),
            Some("[::]:8080".to_string())
        );
    }
}
