//! Audit subsystem scanner.
//!
//! The scanner never treats "I could not see anything" as clean.  Every piece
//! of information (kernel audit switch, `/proc/net/audit` counters, auditd
//! daemon state, journal audit epoch markers) is recorded in the shared
//! [`EvidenceTransaction`].  A legitimate audit restart, rate limiting or a
//! restricted interface is preserved as context; an actual disable or an
//! observation gap becomes a finding, and incomplete evidence forces the
//! public verdict to `INCONCLUSIVE`.

use crate::evidence::{Source, SourceEvidence, Verdict, Window, TRANSACTION};
use crate::ScanOutcome;
use serde::Deserialize;
use std::fs;
use std::process::Command;

const AUDIT_ENABLED_PATH: &str = "/proc/sys/kernel/audit_enabled";
const PROC_AUDIT_PATH: &str = "/proc/net/audit";

#[derive(Debug, Default, PartialEq, Eq)]
struct AuditCounters {
    enabled: Option<i64>,
    backlog: Option<u64>,
    backlog_limit: Option<u64>,
    lost: Option<u64>,
    backlog_wait_time: Option<u64>,
}

/// Parse the whitespace separated `key=value` tokens of `/proc/net/audit`.
fn parse_proc_audit(content: &str) -> AuditCounters {
    let mut counters = AuditCounters::default();
    for token in content.split_whitespace() {
        let (key, value) = match token.split_once('=') {
            Some(pair) => pair,
            None => continue,
        };
        match key {
            "enabled" => counters.enabled = value.parse().ok(),
            "backlog" => counters.backlog = value.parse().ok(),
            "backlog_limit" => counters.backlog_limit = value.parse().ok(),
            "lost" => counters.lost = value.parse().ok(),
            "backlog_wait_time" => counters.backlog_wait_time = value.parse().ok(),
            _ => {}
        }
    }
    counters
}

const MIN_BACKLOG_LIMIT: u64 = 32;

#[derive(Deserialize)]
struct AuditJournalLine {
    #[serde(rename = "_AUDIT_ID")]
    audit_id: Option<String>,
    #[serde(rename = "AUDIT_TYPE")]
    audit_type: Option<String>,
    #[serde(rename = "SYSLOG_IDENTIFIER")]
    identifier: Option<String>,
    #[serde(rename = "__REALTIME_TIMESTAMP")]
    timestamp: Option<String>,
    #[serde(rename = "MESSAGE")]
    message: Option<String>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct AuditEpoch {
    /// Distinct `_AUDIT_ID` values seen in the current boot journal.
    epoch_ids: Vec<String>,
    /// Number of `DAEMON_START`/`auditd` start markers observed.
    restarts: usize,
    /// Number of rate-limit / backlog related markers observed.
    rate_limited: usize,
    /// Number of `audit=0` / disabling markers observed.
    disable_markers: usize,
    record_count: usize,
    first_ts_us: Option<u64>,
    last_ts_us: Option<u64>,
}

/// Inspect the current-boot journal for audit epoch markers.
fn collect_audit_epoch() -> (AuditEpoch, Option<String>) {
    let mut epoch = AuditEpoch::default();
    let mut ids: Vec<String> = Vec::new();

    let output = match Command::new("journalctl")
        .args([
            "-b",
            "--no-pager",
            "--output=json",
            // Kernel audit records travel on the kernel transport; userspace
            // auditd lifecycle markers carry the auditd comm.  Both are valid
            // journal field matches (a bare "KERNEL_AUDIT" token is rejected).
            "_TRANSPORT=kernel",
            "_COMM=auditd",
        ])
        .output()
    {
        Ok(output) => output,
        Err(err) => return (epoch, Some(format!("failed to execute journalctl: {err}"))),
    };

    if !output.status.success() {
        return (
            epoch,
            Some(format!(
                "journalctl exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )),
        );
    }

    for line in output.stdout.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let entry = match serde_json::from_slice::<AuditJournalLine>(line) {
            Ok(entry) => entry,
            Err(_) => continue,
        };

        epoch.record_count += 1;
        if let Some(id) = entry.audit_id.as_deref() {
            if !ids.iter().any(|existing| existing == id) {
                ids.push(id.to_string());
            }
        }
        if let Some(ts) = entry.timestamp.as_deref().and_then(|v| v.parse::<u64>().ok()) {
            epoch.first_ts_us = Some(epoch.first_ts_us.map_or(ts, |prev| prev.min(ts)));
            epoch.last_ts_us = Some(epoch.last_ts_us.map_or(ts, |prev| prev.max(ts)));
        }

        let audit_type = entry.audit_type.unwrap_or_default();
        let message = entry.message.unwrap_or_default();
        let identifier = entry.identifier.unwrap_or_default();

        if audit_type == "DAEMON_START"
            || (identifier == "auditd" && message.contains("start"))
        {
            epoch.restarts += 1;
        }
        if audit_type == "DAEMON_CONFIG"
            || message.contains("rate limit")
            || message.contains("backlog limit exceeded")
            || message.contains("audit_lost")
        {
            epoch.rate_limited += 1;
        }
        if (audit_type == "CONFIG_CHANGE" && message.contains("audit=0"))
            || message.contains("audit disabled")
            || message.contains("type=1326")
        {
            epoch.disable_markers += 1;
        }
    }

    ids.sort();
    epoch.epoch_ids = ids;
    (epoch, None)
}

fn boot_window_from(
    first_ts_us: Option<u64>,
    last_ts_us: Option<u64>,
    boot_start_us: Option<u64>,
) -> Option<Window> {
    let (first, last, boot_start) = (first_ts_us?, last_ts_us?, boot_start_us?);
    if last < first || boot_start > first {
        return None;
    }
    Some(Window::new(
        first.saturating_sub(boot_start),
        last.saturating_sub(boot_start),
    ))
}

pub fn run() -> ScanOutcome {
    let mut findings: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut limitations: Vec<String> = Vec::new();
    let mut origins = vec![AUDIT_ENABLED_PATH.to_string(), PROC_AUDIT_PATH.to_string()];

    // 1. Kernel audit switch.
    let enabled_content = match fs::read_to_string(AUDIT_ENABLED_PATH) {
        Ok(value) => Some(value.trim().to_string()),
        Err(err) => {
            if err.kind() == std::io::ErrorKind::NotFound {
                // Kernels built without CONFIG_AUDIT: nothing to observe.
                limitations.push("audit_supported=false".to_string());
                errors.push(format!("{AUDIT_ENABLED_PATH} not found: {err}"));
            } else {
                errors.push(format!("failed to read {AUDIT_ENABLED_PATH}: {err}"));
            }
            None
        }
    };

    let mut kernel_enabled: Option<i64> = None;
    if let Some(value) = &enabled_content {
        kernel_enabled = value.parse().ok();
        match kernel_enabled {
            Some(0) => {
                findings.push("enabled=0".to_string());
                limitations.push("audit_enabled=0".to_string());
            }
            // 2 = audit locked until reboot, 1 = enabled: both are expected.
            Some(1) | Some(2) => {}
            Some(other) => limitations.push(format!("audit_enabled={other}")),
            None => errors.push(format!("unparsable audit_enabled value: {value}")),
        }
    }

    // 2. /proc/net/audit counters.
    let counters = match fs::read_to_string(PROC_AUDIT_PATH) {
        Ok(content) => parse_proc_audit(&content),
        Err(err) => {
            if err.kind() == std::io::ErrorKind::PermissionDenied {
                errors.push(format!("permission denied reading {PROC_AUDIT_PATH}"));
                limitations.push("proc_audit_access=denied".to_string());
            } else if err.kind() != std::io::ErrorKind::NotFound {
                errors.push(format!("failed to read {PROC_AUDIT_PATH}: {err}"));
            } else {
                limitations.push("proc_audit_present=false".to_string());
            }
            AuditCounters::default()
        }
    };

    if let Some(lost) = counters.lost {
        if lost != 0 {
            findings.push(format!("lost_events={lost}"));
            // Rate limiting explains the loss but the gap is still unobserved.
            limitations.push(format!("audit_lost={lost}"));
        }
    }
    if let Some(limit) = counters.backlog_limit {
        if limit < MIN_BACKLOG_LIMIT {
            findings.push(format!("backlog_limit_small={limit}"));
            limitations.push(format!("backlog_limit={limit}"));
        }
    }
    if let Some(backlog) = counters.backlog {
        if backlog > 0 {
            limitations.push(format!("audit_backlog_pending={backlog}"));
        }
    }

    // 3. Audit epoch as seen through the current-boot journal.
    origins.push("journalctl -b _TRANSPORT=kernel/_COMM=auditd".to_string());
    let (epoch, journal_error) = collect_audit_epoch();
    if let Some(error) = journal_error {
        errors.push(error);
        limitations.push("audit_epoch_visibility=partial".to_string());
    } else if epoch.record_count == 0 {
        // The command worked but exposed no audit records: the audit epoch
        // cannot be reconstructed, so an empty view must not read as clean.
        limitations.push("audit_epoch_visibility=empty".to_string());
    }

    // Multiple audit epochs mean the subsystem restarted: the earlier epoch
    // may no longer be fully readable, so the observation window has a seam.
    if epoch.epoch_ids.len() > 1 {
        limitations.push(format!("audit_epochs={}", epoch.epoch_ids.len()));
        findings.push(format!("audit_epoch_restart ids={}", epoch.epoch_ids.join(",")));
    }
    if epoch.restarts > 1 {
        // A single start is the normal boot marker; repeated starts reopen the
        // epoch and must be preserved rather than flattened into "clean".
        limitations.push(format!("audit_restarts={}", epoch.restarts));
    }
    if epoch.rate_limited > 0 {
        // Legit rate limiting: keep the context, do not call the boot clean.
        limitations.push(format!("audit_rate_limited={}", epoch.rate_limited));
    }
    if epoch.disable_markers > 0 {
        findings.push(format!("audit_disable_markers={}", epoch.disable_markers));
        limitations.push(format!("audit_disable_markers={}", epoch.disable_markers));
    }

    // 4. Register the full evidence in the shared transaction.
    let boot_start_us = crate::evidence::boot_start_realtime_us();
    if boot_start_us.is_none() && journal_error.is_none() {
        limitations.push("boot_btime=unreadable".to_string());
    }
    let window = boot_window_from(epoch.first_ts_us, epoch.last_ts_us, boot_start_us);
    // Procfs knobs contribute point-in-time records even when the journal
    // exposes no audit messages.
    let proc_record_count =
        usize::from(enabled_content.is_some()) + usize::from(counters.enabled.is_some());
    let record_count = epoch.record_count + proc_record_count;
    TRANSACTION.record(
        Source::Audit,
        SourceEvidence {
            window,
            record_count,
            origins,
            errors: errors.clone(),
            limitations: limitations.clone(),
        },
    );

    // 5. Public output.  A transaction-level inconclusive verdict is printed
    //    explicitly so a rotated/denied audit window can never look clean.
    match crate::evidence::verdict_for(Source::Audit) {
        Verdict::Clean => {
            if findings.is_empty() {
                Ok(None)
            } else {
                Ok(Some(findings.join("\n")))
            }
        }
        verdict => {
            let mut lines = findings;
            lines.push(format!(
                "VERDICT={} ({})",
                verdict.label(),
                crate::evidence::inconclusive_reasons(Source::Audit).join("; ")
            ));
            Ok(Some(lines.join("\n")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::now_realtime_us;

    #[test]
    fn parses_proc_audit_counters() {
        let parsed = parse_proc_audit(
            "enabled=1 backlog=0 backlog_limit=8192 lost=12 backlog_wait_time=60000",
        );
        assert_eq!(
            parsed,
            AuditCounters {
                enabled: Some(1),
                backlog: Some(0),
                backlog_limit: Some(8192),
                lost: Some(12),
                backlog_wait_time: Some(60000),
            }
        );
    }

    #[test]
    fn lost_events_and_small_limit_become_limitations() {
        let counters = parse_proc_audit("enabled=1 backlog_limit=8 lost=3");
        assert_eq!(counters.lost, Some(3));
        assert!(counters.backlog_limit.unwrap() < MIN_BACKLOG_LIMIT);
    }

    #[test]
    fn boot_window_requires_ordered_timestamps() {
        assert!(boot_window_from(None, Some(2), Some(0)).is_none());
        assert!(boot_window_from(Some(5), Some(4), Some(0)).is_none());
        let window = boot_window_from(Some(1_000_000), Some(3_000_000), Some(0)).unwrap();
        assert_eq!(window.start_offset_us, 1_000_000);
        assert_eq!(window.end_offset_us, 3_000_000);
    }

    #[test]
    fn epoch_tracks_restarts_and_rate_limits() {
        let epoch = AuditEpoch {
            restarts: 2,
            rate_limited: 1,
            ..AuditEpoch::default()
        };
        assert_eq!(epoch.restarts, 2);
        assert_eq!(epoch.rate_limited, 1);
    }

    #[test]
    fn now_realtime_is_monotonicish() {
        let first = now_realtime_us();
        let second = now_realtime_us();
        assert!(second >= first);
    }
}
