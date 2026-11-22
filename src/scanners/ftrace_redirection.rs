//! Ftrace/tracefs state scanner.
//!
//! The scanner distinguishes three situations:
//!
//! * `current_tracer == nop` with no sensitive filters: the expected idle
//!   state.  It is recorded as complete evidence and stays clean.
//! * A non-`nop` tracer or sensitive function filters: a redirection finding.
//! * tracefs missing/unmounted or unreadable: the observation is impossible,
//!   which is registered as an error/limitation and yields `INCONCLUSIVE`,
//!   never a clean claim.

use crate::evidence::{Source, SourceEvidence, Verdict, Window, TRANSACTION};
use crate::ScanOutcome;
use std::{
    collections::BTreeSet,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

const TRACEFS_ROOTS: [&str; 2] =
    ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];

fn find_tracefs_root() -> io::Result<PathBuf> {
    for root in TRACEFS_ROOTS {
        let path = Path::new(root);
        if path.exists() {
            return Ok(path.to_path_buf());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "tracefs not mounted in expected locations",
    ))
}

fn read_trimmed(path: PathBuf) -> io::Result<String> {
    let content = fs::read_to_string(&path)?;
    Ok(content.trim().to_string())
}

fn read_file(path: PathBuf) -> io::Result<String> {
    let mut file = fs::File::open(&path)?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)?;
    Ok(buf)
}

fn is_sensitive_symbol(symbol: &str) -> bool {
    const PREFIXES: [&str; 4] = ["sys_", "vfs_", "tcp_", "security_"];
    PREFIXES.iter().any(|prefix| symbol.starts_with(prefix))
}

fn collect_sensitive_matches(content: &str) -> BTreeSet<String> {
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            let symbol = trimmed.split_whitespace().next().unwrap_or(trimmed);
            if is_sensitive_symbol(symbol) {
                Some(symbol.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Tracers that are part of normal kernel operation rather than redirection.
fn is_benign_tracer(tracer: &str) -> bool {
    matches!(tracer, "nop" | "")
}

pub fn run() -> ScanOutcome {
    let mut findings: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut limitations: Vec<String> = Vec::new();
    let mut origins: Vec<String> = TRACEFS_ROOTS.iter().map(|r| (*r).to_string()).collect();

    let trace_root = match find_tracefs_root() {
        Ok(root) => root,
        Err(err) => {
            errors.push(format!("failed to locate tracefs: {err}"));
            limitations.push("tracefs=unavailable".to_string());
            TRANSACTION.record(
                Source::Ftrace,
                SourceEvidence {
                    window: None,
                    record_count: 0,
                    origins,
                    errors: errors.clone(),
                    limitations: limitations.clone(),
                },
            );
            return Ok(Some(format!(
                "VERDICT={} ({})",
                crate::evidence::verdict_for(Source::Ftrace).label(),
                crate::evidence::inconclusive_reasons(Source::Ftrace).join("; ")
            )));
        }
    };

    let tracer_path = trace_root.join("current_tracer");
    let filter_path = trace_root.join("set_ftrace_filter");
    origins = vec![
        tracer_path.display().to_string(),
        filter_path.display().to_string(),
    ];

    let tracer = match read_trimmed(tracer_path) {
        Ok(value) => value,
        Err(err) => {
            errors.push(format!("failed to read current_tracer: {err}"));
            limitations.push("current_tracer=unreadable".to_string());
            String::new()
        }
    };

    let filter_content = match read_file(filter_path) {
        Ok(content) => content,
        Err(err) => {
            errors.push(format!("failed to read set_ftrace_filter: {err}"));
            limitations.push("set_ftrace_filter=unreadable".to_string());
            String::new()
        }
    };

    let sensitive_matches = collect_sensitive_matches(&filter_content);
    let redirected = !is_benign_tracer(&tracer);

    if redirected {
        findings.push(format!("tracer={tracer}"));
        limitations.push(format!("ftrace_tracer={tracer}"));
    }
    if !sensitive_matches.is_empty() {
        let matches = sensitive_matches.iter().cloned().collect::<Vec<_>>().join(",");
        findings.push(format!("sensitive_matches={matches}"));
        limitations.push("ftrace_sensitive_filter=true".to_string());
    }

    // A readable tracefs is a point-in-time state snapshot (zero-width
    // window).  Any read error removes the window so the transaction cannot
    // be marked clean.
    let window = if errors.is_empty() {
        Some(Window::new(0, 0))
    } else {
        None
    };

    TRANSACTION.record(
        Source::Ftrace,
        SourceEvidence {
            window,
            record_count: 1 + usize::from(!filter_content.is_empty()),
            origins,
            errors: errors.clone(),
            limitations: limitations.clone(),
        },
    );

    match crate::evidence::verdict_for(Source::Ftrace) {
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
                crate::evidence::inconclusive_reasons(Source::Ftrace).join("; ")
            ));
            Ok(Some(lines.join("\n")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benign_tracers_are_idle() {
        assert!(is_benign_tracer("nop"));
        assert!(is_benign_tracer(""));
        assert!(!is_benign_tracer("function"));
    }

    #[test]
    fn sensitive_filter_detection() {
        let matches = collect_sensitive_matches("sys_open\nvfs_read\nplain_idle\n");
        assert!(matches.contains("sys_open"));
        assert!(matches.contains("vfs_read"));
        assert!(!matches.contains("plain_idle"));
    }

    #[test]
    fn empty_filter_has_no_matches() {
        assert!(collect_sensitive_matches("").is_empty());
    }
}
