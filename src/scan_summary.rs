//! Single summary transaction for a whole scan run.
//!
//! Every collector outcome (the full `ScanOutcome` set), collector coverage,
//! the finding set, the failure list, the verdict and the process exit code
//! are derived from one [`ScanSummary`] instance, so the report and the exit
//! status can never disagree: there is no code path that prints a finding or
//! records a collector failure while still leaving a `CLEAN` round behind.

use crate::ScanOutcome;

/// What a single collector returned, kept as one discrete state instead of
/// collapsing errors onto either of the success states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollectorStatus {
    /// Collector ran and reported at least one finding.
    Finding,
    /// Collector ran and produced no findings (including empty scans).
    Clean,
    /// Collector could not complete its collection, e.g. a permission error.
    Failed,
}

impl CollectorStatus {
    /// Map one collector outcome onto the discrete coverage state.
    pub fn from_outcome(outcome: &ScanOutcome) -> Self {
        match outcome {
            Ok(Some(_)) => CollectorStatus::Finding,
            Ok(None) => CollectorStatus::Clean,
            Err(_) => CollectorStatus::Failed,
        }
    }
}

/// One row of the shared transaction: the collector, its coverage state and
/// (for findings/failures) the human-readable payload already shown inline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectorRecord {
    pub name: &'static str,
    pub status: CollectorStatus,
    pub detail: String,
}

/// Round-level verdict. `Clean` is reachable only when every registered
/// collector ran and none of them found anything or failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Full coverage, no findings, no failures.
    Clean,
    /// At least one finding; every collector still completed.
    Risk,
    /// At least one collector failed; no findings.
    Incomplete,
    /// At least one finding and at least one failure.
    RiskAndIncomplete,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Clean => "CLEAN",
            Verdict::Risk => "RISK",
            Verdict::Incomplete => "INCOMPLETE",
            Verdict::RiskAndIncomplete => "RISK+INCOMPLETE",
        }
    }

    /// Exit code mirrored by the verdict. Only `CLEAN` maps to zero.
    pub fn exit_code(self) -> u8 {
        match self {
            Verdict::Clean => 0,
            Verdict::Risk => 1,
            Verdict::Incomplete => 2,
            Verdict::RiskAndIncomplete => 3,
        }
    }
}

/// The one aggregate every part of the run shares.
///
/// The same struct instance owns the complete outcome set, coverage counters,
/// finding and failure lists, the verdict and the exit code. Nothing else in
/// the program computes a verdict or an exit code, so a report write or a
/// collector failure cannot leave behind a clean or mixed round.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanSummary {
    records: Vec<CollectorRecord>,
}

impl ScanSummary {
    pub fn new() -> Self {
        ScanSummary {
            records: Vec::new(),
        }
    }

    /// Record one collector outcome. Every registered collector is recorded
    /// exactly once; an `Err` is a coverage failure, never a silent clean.
    pub fn record(&mut self, name: &'static str, outcome: &ScanOutcome) {
        let status = CollectorStatus::from_outcome(outcome);
        let detail = match outcome {
            Ok(Some(finding)) => finding.clone(),
            Ok(None) => String::new(),
            Err(err) => err.clone(),
        };
        self.records.push(CollectorRecord {
            name,
            status,
            detail,
        });
    }

    /// Record a collector that aborted (for example a panic caught at the
    /// dispatch boundary). Aborted collectors count as failures, so they can
    /// never be mistaken for coverage.
    pub fn record_aborted(&mut self, name: &'static str, reason: String) {
        self.records.push(CollectorRecord {
            name,
            status: CollectorStatus::Failed,
            detail: reason,
        });
    }

    pub fn total(&self) -> usize {
        self.records.len()
    }

    pub fn findings(&self) -> impl Iterator<Item = &CollectorRecord> {
        self.records
            .iter()
            .filter(|record| record.status == CollectorStatus::Finding)
    }

    pub fn failures(&self) -> impl Iterator<Item = &CollectorRecord> {
        self.records
            .iter()
            .filter(|record| record.status == CollectorStatus::Failed)
    }

    pub fn finding_count(&self) -> usize {
        self.findings().count()
    }

    pub fn failure_count(&self) -> usize {
        self.failures().count()
    }

    /// Number of collectors that actually completed, i.e. had full coverage.
    pub fn covered(&self) -> usize {
        self.total() - self.failure_count()
    }

    /// Coverage is complete only when every registered collector ran without
    /// failing.
    pub fn is_fully_covered(&self) -> bool {
        self.failure_count() == 0
    }

    /// Single verdict derived once from the whole outcome set.
    pub fn verdict(&self) -> Verdict {
        let has_findings = self.finding_count() > 0;
        let has_failures = !self.is_fully_covered();
        match (has_findings, has_failures) {
            (false, false) => Verdict::Clean,
            (true, false) => Verdict::Risk,
            (false, true) => Verdict::Incomplete,
            (true, true) => Verdict::RiskAndIncomplete,
        }
    }

    /// Exit code derived from the same transaction as the verdict.
    pub fn exit_code(&self) -> u8 {
        self.verdict().exit_code()
    }

    /// Render the whole report into one buffer. Building it before any write
    /// makes the report itself transactional: a write error cannot leave a
    /// partial/clean-looking round on screen, and the process still exits with
    /// the code derived here.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("[Summary]\n");
        out.push_str(&format!(
            "collectors={} covered={} findings={} failures={}\n",
            self.total(),
            self.covered(),
            self.finding_count(),
            self.failure_count()
        ));

        let findings: Vec<&CollectorRecord> = self.findings().collect();
        if !findings.is_empty() {
            out.push_str("findings:\n");
            for record in &findings {
                for (idx, line) in record.detail.lines().enumerate() {
                    if idx == 0 {
                        out.push_str(&format!("- {}: {}\n", record.name, line));
                    } else {
                        out.push_str(&format!("    {}\n", line));
                    }
                }
            }
        }

        let failures: Vec<&CollectorRecord> = self.failures().collect();
        if !failures.is_empty() {
            out.push_str("failures:\n");
            for record in &failures {
                let reason = record.detail.lines().next().unwrap_or("unknown error");
                out.push_str(&format!("- {}: {}\n", record.name, reason));
            }
        }

        out.push_str(&format!("verdict: {}\n", self.verdict().label()));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_scan_with_full_coverage_is_clean_and_exits_zero() {
        let summary = ScanSummary::new();
        assert_eq!(summary.total(), 0);
        assert_eq!(summary.verdict(), Verdict::Clean);
        assert_eq!(summary.exit_code(), 0);
        assert!(summary.is_fully_covered());
    }

    #[test]
    fn clean_collectors_keep_a_clean_round() {
        let mut summary = ScanSummary::new();
        summary.record("a", &Ok(None));
        summary.record("b", &Ok(None));
        assert_eq!(summary.total(), 2);
        assert_eq!(summary.covered(), 2);
        assert_eq!(summary.finding_count(), 0);
        assert_eq!(summary.failure_count(), 0);
        assert_eq!(summary.verdict(), Verdict::Clean);
        assert_eq!(summary.exit_code(), 0);
    }

    #[test]
    fn any_finding_makes_the_round_risk_never_clean() {
        let mut summary = ScanSummary::new();
        summary.record("risky", &Ok(Some("evil=1".to_string())));
        summary.record("quiet", &Ok(None));
        assert_eq!(summary.finding_count(), 1);
        assert_eq!(summary.verdict(), Verdict::Risk);
        assert_eq!(summary.exit_code(), 1);
        assert_eq!(summary.covered(), 2);
    }

    #[test]
    fn permission_failure_is_incomplete_and_never_clean() {
        let mut summary = ScanSummary::new();
        summary.record(
            "locked",
            &Err("failed to read host pid ns: Permission denied".to_string()),
        );
        summary.record("quiet", &Ok(None));
        assert_eq!(summary.failure_count(), 1);
        assert_eq!(summary.covered(), 1);
        assert!(!summary.is_fully_covered());
        assert_eq!(summary.verdict(), Verdict::Incomplete);
        assert_eq!(summary.exit_code(), 2);
    }

    #[test]
    fn findings_and_failures_together_are_risk_and_incomplete() {
        let mut summary = ScanSummary::new();
        summary.record("risky", &Ok(Some("evil=1".to_string())));
        summary.record("locked", &Err("permission denied".to_string()));
        summary.record("quiet", &Ok(None));
        assert_eq!(summary.verdict(), Verdict::RiskAndIncomplete);
        assert_eq!(summary.exit_code(), 3);
        assert_eq!(summary.covered(), 2);
    }

    #[test]
    fn aborted_collector_counts_as_failure() {
        let mut summary = ScanSummary::new();
        summary.record_aborted("panic-scanner", "collector panicked".to_string());
        assert_eq!(summary.failure_count(), 1);
        assert_eq!(summary.verdict(), Verdict::Incomplete);
        assert_eq!(summary.exit_code(), 2);
    }

    #[test]
    fn rendered_report_matches_the_verdict_and_exit_code() {
        let mut summary = ScanSummary::new();
        summary.record("risky", &Ok(Some("evil=1".to_string())));
        let report = summary.render();
        assert!(report.contains("[Summary]"));
        assert!(report.contains("collectors=1 covered=1 findings=1 failures=0"));
        assert!(report.contains("- risky: evil=1"));
        assert!(report.contains("verdict: RISK"));
        assert!(!report.contains("verdict: CLEAN"));
    }

    #[test]
    fn failure_report_never_claims_clean() {
        let mut summary = ScanSummary::new();
        summary.record("locked", &Err("permission denied".to_string()));
        let report = summary.render();
        assert!(report.contains("failures=1"));
        assert!(report.contains("- locked: permission denied"));
        assert!(report.contains("verdict: INCOMPLETE"));
        assert!(!report.contains("CLEAN"));
    }
}
