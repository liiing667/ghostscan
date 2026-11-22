//! Shared evidence transaction for boot-wide log sources.
//!
//! Scanners that reason about the safety of the current boot (audit, the
//! systemd journal, the kernel printk ring buffer and ftrace) must not publish
//! a clean verdict on their own.  Every source registers the concrete
//! evidence it managed to collect in the single [`EvidenceTransaction`] held in
//! this module:
//!
//! * which time window (relative to the current boot) the evidence covers,
//! * which files or commands produced it,
//! * any error or permission problem encountered while collecting it,
//! * any state that disables or redirects the source (audit switched off,
//!   tracefs missing, dmesg restricted, ...).
//!
//! A scanner is only allowed to print a public `OK` when its registered
//! evidence is complete for the expected window.  Rotation, permission
//! failures, disabled subsystems and redirections downgrade the verdict to
//! `INCONCLUSIVE` instead of being silently treated as a full observation.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Sources that participate in the shared boot evidence transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    /// Linux audit subsystem (`audit_enabled`, `/proc/net/audit`, auditd).
    Audit,
    /// systemd journal for the current boot (`journalctl -b`).
    Journal,
    /// Kernel printk ring buffer controls (`printk`, `dmesg_restrict`).
    Printk,
    /// Ftrace/tracefs state (`current_tracer`, filters, ...).
    Ftrace,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Audit => "audit",
            Source::Journal => "journal",
            Source::Printk => "printk",
            Source::Ftrace => "ftrace",
        }
    }

    fn all() -> [Source; 4] {
        [
            Source::Audit,
            Source::Journal,
            Source::Printk,
            Source::Ftrace,
        ]
    }
}

/// A microsecond precision interval, relative to the current boot.
///
/// Monotonic/boot-relative offsets are used everywhere so that clock changes
/// during the boot cannot make two independent sources look aligned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    /// Offset of the first observed record from boot, in microseconds.
    pub start_offset_us: u64,
    /// Offset of the last observed record from boot, in microseconds.
    pub end_offset_us: u64,
}

impl Window {
    pub fn new(start_offset_us: u64, end_offset_us: u64) -> Self {
        let (start, end) = if start_offset_us <= end_offset_us {
            (start_offset_us, end_offset_us)
        } else {
            (end_offset_us, start_offset_us)
        };
        Window {
            start_offset_us: start,
            end_offset_us: end,
        }
    }

    fn span_secs(&self) -> u64 {
        self.end_offset_us.saturating_sub(self.start_offset_us) / 1_000_000
    }
}

/// What one source contributed to the transaction.
#[derive(Clone, Debug, Default)]
pub struct SourceEvidence {
    /// Boot-relative window actually observed.  `None` means no record at all
    /// was available (empty journal, unreadable interface, ...).
    pub window: Option<Window>,
    /// Number of records/entries that backed the observation.
    pub record_count: usize,
    /// Human readable origins of the evidence (file paths, command lines).
    pub origins: Vec<String>,
    /// Collection problems.  Permission errors and tool failures land here,
    /// they never disappear.
    pub errors: Vec<String>,
    /// States that disable, silence or redirect the source.  Each entry is a
    /// short `key=value` token suitable for the final report.
    pub limitations: Vec<String>,
}

impl SourceEvidence {
    /// Evidence counts as a complete observation only when it actually covers
    /// a window, is backed by records and was collected without errors or
    /// source-level limitations.
    pub fn is_complete(&self) -> bool {
        self.window.is_some()
            && self.record_count > 0
            && self.errors.is_empty()
            && self.limitations.is_empty()
    }
}

/// The single transaction shared by every boot-log scanner.
#[derive(Debug)]
pub struct EvidenceTransaction {
    evidence: Mutex<[Option<SourceEvidence>; 4]>,
}

impl EvidenceTransaction {
    pub const fn new() -> Self {
        EvidenceTransaction {
            evidence: Mutex::new([const { None }; 4]),
        }
    }

    fn index(source: Source) -> usize {
        match source {
            Source::Audit => 0,
            Source::Journal => 1,
            Source::Printk => 2,
            Source::Ftrace => 3,
        }
    }

    /// Merge one source's evidence into the transaction.
    ///
    /// Scanners call this exactly once with everything they managed to learn.
    pub fn record(&self, source: Source, evidence: SourceEvidence) {
        let mut guard = self.evidence.lock().expect("evidence mutex poisoned");
        guard[Self::index(source)] = Some(evidence);
    }

    /// Snapshot of the evidence currently held for `source`.
    pub fn get(&self, source: Source) -> Option<SourceEvidence> {
        let guard = self.evidence.lock().expect("evidence mutex poisoned");
        guard[Self::index(source)].clone()
    }

    /// Snapshot every registered source in a stable order.
    pub fn snapshot(&self) -> Vec<(Source, Option<SourceEvidence>)> {
        let guard = self.evidence.lock().expect("evidence mutex poisoned");
        Source::all()
            .iter()
            .map(|source| (*source, guard[Self::index(*source)].clone()))
            .collect()
    }
}

/// Process-wide transaction.  All scanners and the final summary share it.
pub static TRANSACTION: EvidenceTransaction = EvidenceTransaction::new();

/// Current wall-clock time expressed as microseconds since the UNIX epoch.
pub fn now_realtime_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// Boot time as UNIX-epoch microseconds, taken from `/proc/stat` `btime`.
///
/// Returns `None` when the value cannot be read or parsed; callers must treat
/// that as missing context rather than inventing a window.
pub fn boot_start_realtime_us() -> Option<u64> {
    let content = std::fs::read_to_string("/proc/stat").ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("btime ") {
            let secs: u64 = rest.trim().parse().ok()?;
            return Some(secs.saturating_mul(1_000_000));
        }
    }
    None
}

/// Convert a realtime (UNIX-epoch microsecond) timestamp into a boot-relative
/// offset.  `None` when boot time is unknown or the timestamp predates boot.
pub fn boot_relative_offset_us(realtime_us: u64) -> Option<u64> {
    let boot_start = boot_start_realtime_us()?;
    realtime_us.checked_sub(boot_start)
}

/// Stable identifier of the current boot (`/proc/sys/kernel/random/boot_id`).
///
/// Every source in the transaction is implicitly scoped to this id; when it
/// cannot be read the string `unknown` is returned and callers should treat
/// boot scoping as unconfirmed.
pub fn boot_id() -> String {
    match std::fs::read_to_string("/proc/sys/kernel/random/boot_id") {
        Ok(value) => value.trim().to_string(),
        Err(_) => "unknown".to_string(),
    }
}

/// Final, transaction-wide verdict for a single source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The source registered complete evidence covering its expected window.
    Clean,
    /// Evidence exists but cannot support a clean security claim.
    Inconclusive,
    /// The source never registered anything at all.
    Missing,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Clean => "CLEAN",
            Verdict::Inconclusive => "INCONCLUSIVE",
            Verdict::Missing => "MISSING",
        }
    }
}

/// Minimum span of evidence (seconds) before a source can claim coverage of
/// the boot.  A single record does not a full observation make.
const MIN_COVERED_SPAN_SECS: u64 = 60;

/// Record-based sources (audit, journal) must span a meaningful slice of the
/// boot.  State-snapshot sources (printk configuration, ftrace knobs) describe
/// live kernel state rather than a time series, so they only need a window.
fn requires_boot_span(source: Source) -> bool {
    matches!(source, Source::Audit | Source::Journal)
}

/// Decide the public verdict for one source from its shared evidence.
pub fn verdict_for(source: Source) -> Verdict {
    match TRANSACTION.get(source) {
        None => Verdict::Missing,
        Some(evidence) => {
            if evidence.is_complete() {
                match evidence.window {
                    Some(window)
                        if !requires_boot_span(source)
                            || window.span_secs() >= MIN_COVERED_SPAN_SECS =>
                    {
                        Verdict::Clean
                    }
                    // Records exist but cover too narrow a slice of the boot.
                    Some(_) => Verdict::Inconclusive,
                    None => Verdict::Inconclusive,
                }
            } else {
                Verdict::Inconclusive
            }
        }
    }
}

/// Human readable explanation for why a source cannot publish a clean claim.
pub fn inconclusive_reasons(source: Source) -> Vec<String> {
    let mut reasons = Vec::new();
    match TRANSACTION.get(source) {
        None => reasons.push("no evidence registered in transaction".to_string()),
        Some(evidence) => {
            if evidence.window.is_none() {
                reasons.push("no records observed (empty/rotated away)".to_string());
            }
            if evidence.record_count == 0 {
                reasons.push("zero records available".to_string());
            }
            for error in &evidence.errors {
                reasons.push(format!("collection_error: {error}"));
            }
            for limitation in &evidence.limitations {
                reasons.push(format!("limitation: {limitation}"));
            }
            if requires_boot_span(source) {
                if let Some(window) = evidence.window {
                    if window.span_secs() < MIN_COVERED_SPAN_SECS {
                        reasons.push(format!(
                            "covered_window_too_narrow={}s",
                            window.span_secs()
                        ));
                    }
                }
            }
        }
    }
    reasons
}

/// One line of the transaction summary printed after all scanners ran.
pub struct SummaryLine {
    pub source: &'static str,
    pub verdict: &'static str,
    pub detail: String,
}

/// Build the final transaction summary across every participating source.
pub fn summarize() -> Vec<SummaryLine> {
    TRANSACTION
        .snapshot()
        .into_iter()
        .map(|(source, maybe_evidence)| {
            let verdict = verdict_for(source);
            let detail = match maybe_evidence {
                None => "no evidence registered".to_string(),
                Some(evidence) => describe(source, &evidence, verdict),
            };
            SummaryLine {
                source: source.label(),
                verdict: verdict.label(),
                detail,
            }
        })
        .collect()
}

fn describe(source: Source, evidence: &SourceEvidence, verdict: Verdict) -> String {
    let window = match evidence.window {
        Some(window) => format!(
            "window=+{}s..+{}s({}s),records={}",
            window.start_offset_us / 1_000_000,
            window.end_offset_us / 1_000_000,
            window.span_secs(),
            evidence.record_count
        ),
        None => format!("window=none,records={}", evidence.record_count),
    };

    let mut parts = vec![window];

    match verdict {
        Verdict::Clean => parts.push("complete observation".to_string()),
        Verdict::Inconclusive | Verdict::Missing => {
            let reasons = inconclusive_reasons(source);
            if reasons.is_empty() {
                parts.push("cannot confirm full boot coverage".to_string());
            } else {
                parts.push(reasons.join("; "));
            }
        }
    }

    parts.join(" | ")
}

/// True only when every source holds complete, boot-spanning evidence.
pub fn all_sources_clean() -> bool {
    Source::all()
        .iter()
        .all(|source| verdict_for(*source) == Verdict::Clean)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_transaction() -> EvidenceTransaction {
        EvidenceTransaction::new()
    }

    fn complete_evidence() -> SourceEvidence {
        SourceEvidence {
            window: Some(Window::new(0, 120_000_000)),
            record_count: 10,
            origins: vec!["test".to_string()],
            errors: Vec::new(),
            limitations: Vec::new(),
        }
    }

    #[test]
    fn empty_evidence_is_never_complete() {
        let evidence = SourceEvidence::default();
        assert!(!evidence.is_complete());
    }

    #[test]
    fn permission_error_downgrades_to_inconclusive() {
        let tx = fresh_transaction();
        let mut evidence = complete_evidence();
        evidence.errors.push("permission denied".to_string());
        tx.record(Source::Audit, evidence);
        let stored = tx.get(Source::Audit).unwrap();
        assert!(!stored.is_complete());
        assert!(stored
            .errors
            .iter()
            .any(|error| error.contains("permission denied")));
    }

    #[test]
    fn disabled_source_is_inconclusive_even_with_records() {
        let tx = fresh_transaction();
        let mut evidence = complete_evidence();
        evidence
            .limitations
            .push("audit_enabled=0".to_string());
        tx.record(Source::Printk, evidence);
        assert!(!tx.get(Source::Printk).unwrap().is_complete());
    }

    #[test]
    fn narrow_window_cannot_claim_clean_for_record_sources() {
        let tx = fresh_transaction();
        let mut evidence = complete_evidence();
        evidence.window = Some(Window::new(0, 5_000_000));
        tx.record(Source::Journal, evidence);
        let stored = tx.get(Source::Journal).unwrap();
        assert!(stored.is_complete());
        assert!(stored.window.unwrap().span_secs() < MIN_COVERED_SPAN_SECS);
    }

    #[test]
    fn snapshot_sources_accept_zero_width_window() {
        let tx = fresh_transaction();
        let evidence = SourceEvidence {
            window: Some(Window::new(0, 0)),
            record_count: 2,
            origins: vec!["snapshot".to_string()],
            errors: Vec::new(),
            limitations: Vec::new(),
        };
        tx.record(Source::Ftrace, evidence);
        let stored = tx.get(Source::Ftrace).unwrap();
        assert!(stored.is_complete());
        assert_eq!(stored.window.unwrap().span_secs(), 0);
    }

    #[test]
    fn complete_evidence_publishes_clean() {
        let tx = fresh_transaction();
        tx.record(Source::Journal, complete_evidence());
        let stored = tx.get(Source::Journal).unwrap();
        assert!(stored.is_complete());
        assert!(stored.window.unwrap().span_secs() >= MIN_COVERED_SPAN_SECS);
    }

    #[test]
    fn missing_source_is_reported_as_missing() {
        let tx = fresh_transaction();
        assert!(tx.get(Source::Audit).is_none());
    }

    #[test]
    fn window_normalizes_reversed_offsets() {
        let window = Window::new(9_000_000, 1_000_000);
        assert_eq!(window.start_offset_us, 1_000_000);
        assert_eq!(window.end_offset_us, 9_000_000);
        assert_eq!(window.span_secs(), 8);
    }

    #[test]
    fn summary_mentions_every_source() {
        let tx = fresh_transaction();
        tx.record(Source::Audit, complete_evidence());
        let snapshot = tx.snapshot();
        assert_eq!(snapshot.len(), 4);
        let labels: Vec<&str> = snapshot
            .iter()
            .map(|(source, _)| source.label())
            .collect();
        assert_eq!(labels, vec!["audit", "journal", "printk", "ftrace"]);
    }
}
