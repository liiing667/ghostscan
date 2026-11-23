use crate::bpf_lifecycle::{
    conflict_error, scanner_error, BpfSnapshot, BpfTransaction, CollectorKind, LinkRecord,
    BPF_TRANSACTION,
};
use crate::ScanOutcome;

pub fn run() -> ScanOutcome {
    run_with_bpf(&BPF_TRANSACTION)
}

/// Kprobe/kretprobe attachment scan sharing the caller's lifecycle
/// transaction.  A link is published only together with the program tag from
/// the same generation, which makes a detached/reused program id visible
/// instead of merging two observations.
pub fn run_with_bpf(transaction: &BpfTransaction) -> ScanOutcome {
    let snapshot = transaction.snapshot();
    run_with_snapshot(&snapshot)
}

pub fn run_with_snapshot(snapshot: &BpfSnapshot) -> ScanOutcome {
    if let Some(error) = scanner_error(
        snapshot,
        CollectorKind::Links,
        "bpftool not available to inspect BPF links",
    ) {
        return Err(error);
    }

    if let Some(error) = conflict_error(snapshot) {
        return Err(error);
    }

    let mut findings = Vec::new();

    for link in &snapshot.links {
        if !is_kprobe_link(link) && !is_kretprobe_link(link) {
            continue;
        }

        let target = extract_target_symbol(link).unwrap_or_else(|| "unknown".to_string());
        if !is_sensitive_symbol(&target) {
            continue;
        }

        let prog_tag = link
            .prog_tag
            .clone()
            .or_else(|| {
                link.prog_id
                    .and_then(|id| snapshot.program(id))
                    .map(|program| program.tag.clone())
            })
            .unwrap_or_else(|| "unknown".to_string());

        let attach_kind = if is_kretprobe_link(link) {
            "kretprobe"
        } else {
            "kprobe"
        };

        findings.push(format!(
            "link_id={}, prog_id={}, attach={}, target={}, prog_tag={}, generation={}, boot_id={}",
            link.id,
            link.prog_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            attach_kind,
            target,
            prog_tag,
            link.stamp.label(),
            link.stamp.boot_id
        ));
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        findings.sort();
        Ok(Some(findings.join("\n")))
    }
}

fn is_kprobe_link(link: &LinkRecord) -> bool {
    let link_type = link.link_type.to_ascii_lowercase();
    let attach_type = link.attach_type.to_ascii_lowercase();
    link_type.contains("kprobe") || attach_type.contains("kprobe")
}

fn extract_target_symbol(link: &LinkRecord) -> Option<String> {
    if link.target.trim().is_empty() {
        None
    } else {
        Some(link.target.clone())
    }
}

fn is_kretprobe_link(link: &LinkRecord) -> bool {
    let link_type = link.link_type.to_ascii_lowercase();
    let attach_type = link.attach_type.to_ascii_lowercase();
    link_type.contains("kretprobe") || attach_type.contains("kretprobe")
}

fn is_sensitive_symbol(symbol: &str) -> bool {
    const PREFIXES: [&str; 4] = ["sys_", "vfs_", "tcp_", "security_"];
    PREFIXES.iter().any(|prefix| symbol.starts_with(prefix))
}
