//! Current-boot journal coverage scanner.
//!
//! A legitimate journal rotation must not be interpreted as a clean,
//! gap-free boot.  The scanner therefore records, in the shared
//! [`EvidenceTransaction`]:
//!
//! * the journal cursor (`journalctl --show-cursor`) so the exact end of the
//!   observed range is anchored,
//! * rotation / vacuum markers (`_SYSTEMD_UNIT=systemd-journald.service`,
//!   `Rotating` / `Vacuuming` messages) and the files backing the boot,
//! * the first/last entry timestamps relative to boot time,
//! * every internal silence longer than [`GAP_THRESHOLD_SECS`].
//!
//! When entries do not reach boot start (or now), or rotation happened inside
//! the boot, the public verdict is `INCONCLUSIVE` instead of `OK`.

use crate::evidence::{
    boot_relative_offset_us, boot_start_realtime_us, now_realtime_us, Source, SourceEvidence,
    Verdict, Window, TRANSACTION,
};
use crate::ScanOutcome;
use serde::Deserialize;
use std::process::Command;

const GAP_THRESHOLD_SECS: u64 = 3600;
/// How close (seconds) the first journal entry must be to boot time before we
/// accept that the journal covers the beginning of the boot.
const BOOT_EDGE_TOLERANCE_SECS: u64 = 120;
/// How close (seconds) the last entry must be to scan time.
const TAIL_EDGE_TOLERANCE_SECS: u64 = 300;

#[derive(Deserialize)]
struct JournalLine {
    #[serde(rename = "__REALTIME_TIMESTAMP")]
    timestamp: Option<String>,
    #[serde(rename = "MESSAGE")]
    message: Option<String>,
    #[serde(rename = "_SYSTEMD_UNIT")]
    unit: Option<String>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct JournalObservation {
    timestamps_us: Vec<u64>,
    rotations: usize,
    vacuums: usize,
    /// Files journald reported as part of the current boot sequence.
    journal_files: Vec<String>,
    invocation_error: Option<String>,
}

fn run_journalctl(extra_args: &[&str]) -> Result<std::process::Output, String> {
    Command::new("journalctl")
        .args(["-b", "--no-pager"])
        .args(extra_args)
        .output()
        .map_err(|err| format!("failed to execute journalctl: {err}"))
}

fn collect_cursor() -> (Option<String>, Option<String>) {
    let output = match run_journalctl(&["--output=json", "-n", "1", "--show-cursor"]) {
        Ok(output) => output,
        Err(err) => return (None, Some(err)),
    };
    if !output.status.success() {
        return (
            None,
            Some(format!(
                "journalctl --show-cursor exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )),
        );
    }

    // The cursor line is emitted on stderr as `-- cursor: ...`.
    let stderr = String::from_utf8_lossy(&output.stderr);
    for line in stderr.lines() {
        if let Some(cursor) = line.strip_prefix("-- cursor: ") {
            let cursor = cursor.trim();
            if !cursor.is_empty() {
                return (Some(cursor.to_string()), None);
            }
        }
    }
    (None, Some("journalctl returned no cursor".to_string()))
}

fn collect_entries() -> JournalObservation {
    let mut observation = JournalObservation::default();

    let output = match run_journalctl(&["--output=json", "--all"]) {
        Ok(output) => output,
        Err(err) => {
            observation.invocation_error = Some(err);
            return observation;
        }
    };
    if !output.status.success() {
        observation.invocation_error = Some(format!(
            "journalctl exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
        return observation;
    }

    for line in output.stdout.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let entry = match serde_json::from_slice::<JournalLine>(line) {
            Ok(entry) => entry,
            Err(_) => continue,
        };

        if let Some(ts) = entry.timestamp.as_deref().and_then(|v| v.parse::<u64>().ok()) {
            observation.timestamps_us.push(ts);
        }

        let message = entry.message.clone().unwrap_or_default();
        let unit = entry.unit.clone().unwrap_or_default();
        if unit == "systemd-journald.service" {
            if message.contains("Rotating") || message.contains("rotating") {
                observation.rotations += 1;
            }
            if message.contains("Vacuuming") || message.contains("vacuum") {
                observation.vacuums += 1;
            }
            if let Some(path) = message.split(' ').find(|token| token.ends_with(".journal")) {
                if !observation.journal_files.iter().any(|p| p == path) {
                    observation.journal_files.push(path.to_string());
                }
            }
        }
    }

    observation.timestamps_us.sort_unstable();
    observation.timestamps_us.dedup();
    observation
}

#[derive(Debug, PartialEq, Eq)]
struct Gap {
    /// Boot-relative offsets when btime was known; raw realtime otherwise.
    start_offset_us: u64,
    end_offset_us: u64,
    /// Raw realtime timestamps, always populated.
    start_realtime_us: u64,
    end_realtime_us: u64,
    /// Whether the offsets above are boot-relative (`true`) or raw realtime.
    boot_relative: bool,
    gap_secs: u64,
}

fn find_gaps(timestamps_us: &[u64]) -> Vec<Gap> {
    let mut gaps = Vec::new();
    for window in timestamps_us.windows(2) {
        let gap = window[1].saturating_sub(window[0]);
        if gap / 1_000_000 > GAP_THRESHOLD_SECS {
            let start_offset = boot_relative_offset_us(window[0]);
            let end_offset = boot_relative_offset_us(window[1]);
            let boot_relative = start_offset.is_some() && end_offset.is_some();
            gaps.push(Gap {
                start_offset_us: start_offset.unwrap_or(window[0]),
                end_offset_us: end_offset.unwrap_or(window[1]),
                start_realtime_us: window[0],
                end_realtime_us: window[1],
                boot_relative,
                gap_secs: gap / 1_000_000,
            });
        }
    }
    gaps
}

pub fn run() -> ScanOutcome {
    let mut findings: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut limitations: Vec<String> = Vec::new();
    let mut origins = vec!["journalctl -b --output=json --all".to_string()];

    let (cursor, cursor_error) = collect_cursor();
    match &cursor {
        Some(value) => origins.push(format!("cursor={value}")),
        None => limitations.push("journal_cursor=unavailable".to_string()),
    }
    if let Some(error) = cursor_error {
        errors.push(error);
    }

    let observation = collect_entries();
    if let Some(error) = &observation.invocation_error {
        errors.push(error.clone());
        limitations.push("journal_access=failed".to_string());
    }

    if observation.rotations > 0 {
        limitations.push(format!("journal_rotations={}", observation.rotations));
        findings.push(format!(
            "journal_rotation markers={} (legal rotation splits the observed window)",
            observation.rotations
        ));
    }
    if observation.vacuums > 0 {
        limitations.push(format!("journal_vacuums={}", observation.vacuums));
        findings.push(format!("journal_vacuum markers={}", observation.vacuums));
    }
    if !observation.journal_files.is_empty() {
        origins.push(format!("files={}", observation.journal_files.join(",")));
    }

    // Internal silence gaps.
    let gaps = find_gaps(&observation.timestamps_us);
    for gap in &gaps {
        if gap.boot_relative {
            findings.push(format!(
                "gap_start=+{}s gap_end=+{}s gap_secs={}",
                gap.start_offset_us / 1_000_000,
                gap.end_offset_us / 1_000_000,
                gap.gap_secs
            ));
        } else {
            findings.push(format!(
                "gap_start_realtime={} gap_end_realtime={} gap_secs={} \
                 (boot btime unavailable, offsets unknown)",
                gap.start_realtime_us, gap.end_realtime_us, gap.gap_secs
            ));
        }
    }

    // Edge coverage: does the journal actually span the whole boot?
    let boot_start_us = boot_start_realtime_us();
    let mut window: Option<Window> = None;
    if boot_start_us.is_none() && observation.invocation_error.is_none() {
        limitations.push("boot_btime=unreadable".to_string());
    }
    if let (Some(first), Some(last), Some(boot)) = (
        observation.timestamps_us.first().copied(),
        observation.timestamps_us.last().copied(),
        boot_start_us,
    ) {
        let start_offset = first.saturating_sub(boot);
        let end_offset = last.saturating_sub(boot);
        window = Some(Window::new(start_offset, end_offset));

        if start_offset / 1_000_000 > BOOT_EDGE_TOLERANCE_SECS {
            limitations.push(format!(
                "boot_head_uncovered={}s",
                start_offset / 1_000_000
            ));
            findings.push(format!(
                "no journal coverage for first {}s of boot",
                start_offset / 1_000_000
            ));
        }

        let age = now_realtime_us().saturating_sub(last) / 1_000_000;
        if age > TAIL_EDGE_TOLERANCE_SECS {
            limitations.push(format!("journal_tail_stale={age}s"));
            findings.push(format!("journal tail is {age}s behind scan time"));
        }
    } else if observation.invocation_error.is_none() {
        // Command worked but returned nothing: the "empty record" case from
        // the incident must never be rendered as a clean boot.
        limitations.push("journal_records=0".to_string());
        findings.push("journal returned zero records for current boot".to_string());
    }

    TRANSACTION.record(
        Source::Journal,
        SourceEvidence {
            window,
            record_count: observation.timestamps_us.len(),
            origins,
            errors: errors.clone(),
            limitations: limitations.clone(),
        },
    );

    match crate::evidence::verdict_for(Source::Journal) {
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
                crate::evidence::inconclusive_reasons(Source::Journal).join("; ")
            ));
            Ok(Some(lines.join("\n")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_gaps_beyond_threshold() {
        let base = 1_000_000_000_000;
        let timestamps = vec![
            base,
            base + 10 * 60 * 1_000_000,
            base + (GAP_THRESHOLD_SECS + 60) * 1_000_000 + 10 * 60 * 1_000_000,
        ];
        let gaps = find_gaps(&timestamps);
        assert_eq!(gaps.len(), 1);
        assert!(gaps[0].gap_secs > GAP_THRESHOLD_SECS);
        assert_eq!(gaps[0].start_realtime_us, base);
        assert!(gaps[0].end_realtime_us > gaps[0].start_realtime_us);
    }

    #[test]
    fn quiet_boot_without_threshold_gap_has_no_findings() {
        let base = 1_000_000_000_000;
        let timestamps = vec![
            base,
            base + 30 * 60 * 1_000_000,
            base + 60 * 60 * 1_000_000,
        ];
        assert!(find_gaps(&timestamps).is_empty());
    }

    #[test]
    fn cursor_line_is_parsed_from_stderr() {
        let sample = "-- cursor: s=123;i=456;b=abc;m=123;t=xyz;x=yyy\n";
        let cursor = sample
            .lines()
            .find_map(|line| line.strip_prefix("-- cursor: ").map(str::trim));
        assert_eq!(cursor, Some("s=123;i=456;b=abc;m=123;t=xyz;x=yyy"));
    }
}
