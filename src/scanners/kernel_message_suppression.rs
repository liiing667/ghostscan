//! Kernel printk / ring-buffer visibility scanner.
//!
//! Two distinct facts must stay separated:
//!
//! * `dmesg_restrict=1` is the *expected hardening* on production hosts.  It
//!   limits who can read the ring buffer, so it is recorded as an access
//!   limitation of the evidence window, never as a malicious finding.
//! * `dmesg_restrict=0` combined with a silenced console loglevel means kernel
//!   messages are being suppressed where operators would normally see them.
//!
//! Every read error (including permission denied) is registered in the shared
//! [`EvidenceTransaction`] so an unreadable printk interface cannot result in a
//! public clean claim.

use crate::evidence::{Source, SourceEvidence, Verdict, TRANSACTION};
use crate::ScanOutcome;
use std::fs;

const DMESG_RESTRICT_PATH: &str = "/proc/sys/kernel/dmesg_restrict";
const PRINTK_PATH: &str = "/proc/sys/kernel/printk";
const PRINTK_RATELIMIT_PATH: &str = "/proc/sys/kernel/printk_devkmsg";

fn parse_printk(content: &str) -> PrintkState {
    let values: Vec<i32> = content
        .split_whitespace()
        .filter_map(|token| token.parse().ok())
        .collect();
    PrintkState {
        console_loglevel: values.first().copied(),
        default_loglevel: values.get(1).copied(),
        minimum_loglevel: values.get(2).copied(),
        boot_default_loglevel: values.get(3).copied(),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct PrintkState {
    console_loglevel: Option<i32>,
    default_loglevel: Option<i32>,
    #[allow(dead_code)]
    minimum_loglevel: Option<i32>,
    #[allow(dead_code)]
    boot_default_loglevel: Option<i32>,
}

fn read_proc_path(path: &str, errors: &mut Vec<String>) -> Option<String> {
    match fs::read_to_string(path) {
        Ok(content) => Some(content.trim().to_string()),
        Err(err) => {
            errors.push(format!("failed to read {path}: {err}"));
            None
        }
    }
}

pub fn run() -> ScanOutcome {
    let mut findings: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut limitations: Vec<String> = Vec::new();
    let origins = vec![
        DMESG_RESTRICT_PATH.to_string(),
        PRINTK_PATH.to_string(),
        PRINTK_RATELIMIT_PATH.to_string(),
    ];

    let mut readable_sources = 0usize;

    if let Some(content) = read_proc_path(DMESG_RESTRICT_PATH, &mut errors) {
        readable_sources += 1;
        match content.parse::<i32>() {
            Some(1) => {
                // Expected hardening: preserve it as context.  It narrows who
                // can observe the ring buffer, so the evidence is limited.
                limitations.push("dmesg_restrict=1".to_string());
            }
            Some(0) => findings.push("dmesg_restrict!=1".to_string()),
            Some(other) => errors.push(format!("unexpected dmesg_restrict={other}")),
            None => errors.push(format!("unparsable dmesg_restrict: {content}")),
        }
    } else {
        limitations.push("dmesg_restrict=unreadable".to_string());
    }

    if let Some(content) = read_proc_path(PRINTK_PATH, &mut errors) {
        readable_sources += 1;
        let levels = parse_printk(&content);

        // A console level below the default level silences messages the
        // kernel would otherwise surface.
        if let (Some(console), Some(default)) = (levels.console_loglevel, levels.default_loglevel)
        {
            if console < default {
                findings.push(format!(
                    "printk_console_level_silenced=true console={console} default={default}"
                ));
                limitations.push(format!("printk_console={console}"));
            }
        } else if let Some(console) = levels.console_loglevel {
            // Fallback to the historical heuristic when no default level was
            // parsable.
            if console < 7 {
                findings.push("printk_console_level_silenced=true".to_string());
                limitations.push(format!("printk_console={console}"));
            }
        }
    } else {
        limitations.push("printk_levels=unreadable".to_string());
    }

    if let Some(content) = read_proc_path(PRINTK_RATELIMIT_PATH, &mut errors) {
        readable_sources += 1;
        // `ratelimit` and `off` reduce what can be observed from /dev/kmsg.
        if content.trim() == "ratelimit" || content.trim() == "off" {
            let content = content.trim();
            limitations.push(format!("printk_devkmsg={content}"));
            if content == "off" {
                findings.push("devkmsg_disabled=true".to_string());
            }
        }
    }

    // The printk "window" is the live ring-buffer configuration snapshot: a
    // zero-width, point-in-time observation.  When any interface was
    // unreadable there is no window at all, so the transaction cannot support
    // a clean claim.
    let window = if errors.is_empty() {
        Some(crate::evidence::Window::new(0, 0))
    } else {
        None
    };

    TRANSACTION.record(
        Source::Printk,
        SourceEvidence {
            window,
            // The configuration knobs themselves are the records.
            record_count: readable_sources,
            origins,
            errors: errors.clone(),
            limitations: limitations.clone(),
        },
    );

    match crate::evidence::verdict_for(Source::Printk) {
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
                crate::evidence::inconclusive_reasons(Source::Printk).join("; ")
            ));
            Ok(Some(lines.join("\n")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_four_printk_levels() {
        let state = parse_printk("4 4 1 7\n");
        assert_eq!(state.console_loglevel, Some(4));
        assert_eq!(state.default_loglevel, Some(4));
        assert_eq!(state.minimum_loglevel, Some(1));
        assert_eq!(state.boot_default_loglevel, Some(7));
    }

    #[test]
    fn console_below_default_is_silenced() {
        let state = parse_printk("3 4 1 7");
        assert!(state.console_loglevel.unwrap() < state.default_loglevel.unwrap());
    }

    #[test]
    fn normal_levels_are_not_silenced() {
        let state = parse_printk("7 4 1 7");
        assert!(state.console_loglevel.unwrap() >= state.default_loglevel.unwrap());
    }
}
