//! One host observation generation per scan round.
//!
//! ghostscan has two host-wide collectors that feed several independent
//! scanners: the container inventory (`container_utils`) and the task snapshot
//! (`task_snapshot`).  Collecting them once per scanner allowed two scan
//! rounds, or two retries of the same round, to publish a report that merged
//! containers and task records observed at different times.
//!
//! [`HostObservation`] fixes that by making one round explicit:
//!
//! * [`ObservationGeneration`] creates a process-unique generation
//!   label (boot id + round + start time) before any scanner runs,
//! * every collector result carries a [`CollectorStamp`] with that generation,
//!   the collector kind and the attempt number,
//! * scanners receive the observation by reference and can only read the
//!   stamped results of this round,
//! * the final [`HostObservationReport`] rejects any stamp from a different
//!   generation instead of falling back to a cached previous round.
//!
//! A failed or cancelled collector leaves no usable value in the slot.  There
//! is deliberately no process-wide host cache: a later round, or a retry with
//! a failing collector, can never resurrect containers or tasks observed by an
//! earlier round.

use crate::scanners::container_utils::{
    collect_container_states_checked, ContainerInventory,
};
use crate::scanners::task_snapshot::{collect_bpf_tasks, collect_proc_tasks, BpfTaskSnapshot};
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Container state scan limit used by every container-aware scanner.
pub const CONTAINER_SCAN_LIMIT: usize = 1024;
/// BPF map scan limit used by the task snapshot collector.
pub const BPF_MAP_SCAN_LIMIT: usize = 64;
/// Per-map entry limit used by the task snapshot collector.
pub const BPF_ENTRY_SCAN_LIMIT: usize = 65536;

static NEXT_OBSERVATION_ROUND: AtomicU64 = AtomicU64::new(1);

/// Identity of one host observation round.
///
/// The label is unique even when two rounds start in the same process and in
/// the same nanosecond: the atomic round counter is part of the identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationGeneration {
    round: u64,
    boot_id: String,
    started_unix_ns: u128,
    pid: u32,
}

impl ObservationGeneration {
    fn start() -> Self {
        let round = NEXT_OBSERVATION_ROUND.fetch_add(1, Ordering::Relaxed);
        let started_unix_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|value| value.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        Self {
            round,
            boot_id,
            started_unix_ns,
            pid: std::process::id(),
        }
    }

    /// Monotonic in-process round number.
    pub fn round(&self) -> u64 {
        self.round
    }

    /// Current boot identity, or `unknown` when procfs is unavailable.
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    /// Wall-clock start of the observation, in nanoseconds since the epoch.
    pub fn started_unix_ns(&self) -> u128 {
        self.started_unix_ns
    }

    /// PID of the ghostscan process that owns this observation.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Stable, human-readable generation label used by reports and stamps.
    pub fn label(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.boot_id, self.round, self.started_unix_ns, self.pid
        )
    }
}

/// Error returned by a host collector.
///
/// Permission failures and tool failures keep their original text so the
/// existing scanner output remains unchanged.  A cancellation is represented
/// separately so a report can state that the collector did not produce
/// evidence instead of pretending it was a clean empty result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionFailure {
    pub reason: String,
    pub cancelled: bool,
}

impl CollectionFailure {
    pub fn failed(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            cancelled: false,
        }
    }

    pub fn cancelled(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            cancelled: true,
        }
    }
}

impl fmt::Display for CollectionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.reason)
    }
}

/// Host-wide collectors that participate in one observation generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CollectorKind {
    Containers,
    BpfTasks,
    ProcTasks,
}

impl CollectorKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Containers => "containers",
            Self::BpfTasks => "bpf_tasks",
            Self::ProcTasks => "proc_tasks",
        }
    }

    pub fn all() -> [Self; 3] {
        [Self::Containers, Self::BpfTasks, Self::ProcTasks]
    }
}

/// State of a collector result.  `Partial` means the collector returned
/// usable evidence but recorded read/permission errors; `Failed` and
/// `Cancelled` carry no evidence at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollectorStatus {
    Complete,
    Partial,
    Failed,
    Cancelled,
}

impl CollectorStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Complete => "COMPLETE",
            Self::Partial => "PARTIAL",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
        }
    }

    pub fn is_usable(self) -> bool {
        matches!(self, Self::Complete | Self::Partial)
    }

    pub fn needs_retry(self) -> bool {
        matches!(self, Self::Failed | Self::Cancelled)
    }
}

/// Stamp attached to every collector result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectorStamp {
    pub kind: CollectorKind,
    pub generation: ObservationGeneration,
    pub attempt: u64,
}

impl CollectorStamp {
    pub fn belongs_to(&self, generation: &ObservationGeneration) -> bool {
        &self.generation == generation
    }
}

/// Collector functions used by an observation.
///
/// The production default reads the real host.  Tests can substitute
/// deterministic collectors without touching procfs, bpffs or container
/// state files.
#[derive(Clone, Copy)]
pub struct CollectionBackend {
    pub containers: fn(usize) -> Result<ContainerInventory, CollectionFailure>,
    pub bpf_tasks: fn(usize, usize) -> Result<BpfTaskSnapshot, CollectionFailure>,
    pub proc_tasks: fn() -> Result<HashMap<i32, String>, CollectionFailure>,
}

impl Default for CollectionBackend {
    fn default() -> Self {
        Self {
            containers: collect_live_containers,
            bpf_tasks: collect_live_bpf_tasks,
            proc_tasks: collect_live_proc_tasks,
        }
    }
}

fn collect_live_containers(limit: usize) -> Result<ContainerInventory, CollectionFailure> {
    collect_container_states_checked(limit).map_err(|err| CollectionFailure::failed(err))
}

fn collect_live_bpf_tasks(
    map_limit: usize,
    entry_limit: usize,
) -> Result<BpfTaskSnapshot, CollectionFailure> {
    collect_bpf_tasks(map_limit, entry_limit)
        .map_err(|err| CollectionFailure::failed(err))
}

fn collect_live_proc_tasks() -> Result<HashMap<i32, String>, CollectionFailure> {
    collect_proc_tasks().map_err(|err| CollectionFailure::failed(err))
}

fn container_result_is_partial(inventory: &ContainerInventory) -> bool {
    !inventory.errors.is_empty()
}

fn bpf_result_is_partial(snapshot: &BpfTaskSnapshot) -> bool {
    !snapshot.errors.is_empty()
}

fn proc_result_is_partial(_tasks: &HashMap<i32, String>) -> bool {
    false
}

#[derive(Debug)]
enum CollectorState<T> {
    Complete(T),
    Partial(T),
    Failed(String),
    Cancelled(String),
}

#[derive(Debug)]
struct Collector<T> {
    stamp: CollectorStamp,
    state: CollectorState<T>,
}

impl<T> Collector<T> {
    fn collect(
        kind: CollectorKind,
        generation: &ObservationGeneration,
        attempt: u64,
        result: Result<T, CollectionFailure>,
        is_partial: fn(&T) -> bool,
    ) -> Self {
        let state = match result {
            Ok(value) if is_partial(&value) => CollectorState::Partial(value),
            Ok(value) => CollectorState::Complete(value),
            Err(failure) if failure.cancelled => CollectorState::Cancelled(failure.reason),
            Err(failure) => CollectorState::Failed(failure.reason),
        };

        Self {
            stamp: CollectorStamp {
                kind,
                generation: generation.clone(),
                attempt,
            },
            state,
        }
    }

    fn status(&self) -> CollectorStatus {
        match &self.state {
            CollectorState::Complete(_) => CollectorStatus::Complete,
            CollectorState::Partial(_) => CollectorStatus::Partial,
            CollectorState::Failed(_) => CollectorStatus::Failed,
            CollectorState::Cancelled(_) => CollectorStatus::Cancelled,
        }
    }

    fn value(&self) -> Option<&T> {
        match &self.state {
            CollectorState::Complete(value) | CollectorState::Partial(value) => Some(value),
            CollectorState::Failed(_) | CollectorState::Cancelled(_) => None,
        }
    }

    fn failure(&self) -> Option<CollectorFailure> {
        match &self.state {
            CollectorState::Failed(reason) => Some(CollectionFailure::failed(reason.clone())),
            CollectorState::Cancelled(reason) => Some(CollectionFailure::cancelled(reason.clone())),
            CollectorState::Complete(_) | CollectorState::Partial(_) => None,
        }
    }

    fn stamp(&self) -> &CollectorStamp {
        &self.stamp
    }

    fn cancel(&mut self, reason: String) {
        self.stamp.attempt = self.stamp.attempt.saturating_add(1);
        self.state = CollectorState::Cancelled(reason);
    }
}

fn require_value<'a, T>(
    collector: &'a Collector<T>,
    missing_reason: &'static str,
) -> Result<&'a T, CollectorFailure> {
    collector
        .value()
        .ok_or_else(|| collector.failure().unwrap_or_else(|| CollectionFailure::failed(missing_reason)))
}

/// One round of host observations shared by scan startup, collectors,
/// host-aware scanners and the final report.
pub struct HostObservation {
    generation: ObservationGeneration,
    backend: CollectionBackend,
    containers: Collector<ContainerInventory>,
    bpf_tasks: Collector<BpfTaskSnapshot>,
    proc_tasks: Collector<HashMap<i32, String>>,
}

impl HostObservation {
    /// Start a new generation and collect all host snapshots exactly once.
    pub fn start() -> Self {
        Self::start_with(CollectionBackend::default())
    }

    /// Start a new generation with explicit collector functions (tests or
    /// alternative front ends).
    pub fn start_with(backend: CollectionBackend) -> Self {
        let generation = ObservationGeneration::start();

        let containers = Collector::collect(
            CollectorKind::Containers,
            &generation,
            1,
            (backend.containers)(CONTAINER_SCAN_LIMIT),
            container_result_is_partial,
        );
        let bpf_tasks = Collector::collect(
            CollectorKind::BpfTasks,
            &generation,
            1,
            (backend.bpf_tasks)(BPF_MAP_SCAN_LIMIT, BPF_ENTRY_SCAN_LIMIT),
            bpf_result_is_partial,
        );
        let proc_tasks = Collector::collect(
            CollectorKind::ProcTasks,
            &generation,
            1,
            (backend.proc_tasks)(),
            proc_result_is_partial,
        );

        Self {
            generation,
            backend,
            containers,
            bpf_tasks,
            proc_tasks,
        }
    }

    pub fn generation(&self) -> &ObservationGeneration {
        &self.generation
    }

    /// Container inventory collected for this generation.
    ///
    /// A failed or cancelled collector returns the original error and never
    /// falls back to a previous round.
    pub fn containers(&self) -> Result<&ContainerInventory, CollectorFailure> {
        require_value(
            &self.containers,
            "container collector produced no evidence",
        )
    }

    /// BPF task snapshot collected for this generation.
    pub fn bpf_tasks(&self) -> Result<&BpfTaskSnapshot, CollectorFailure> {
        require_value(&self.bpf_tasks, "BPF task collector produced no evidence")
    }

    /// procfs task snapshot collected for this generation.
    pub fn proc_tasks(&self) -> Result<&HashMap<i32, String>, CollectorFailure> {
        require_value(&self.proc_tasks, "proc task collector produced no evidence")
    }

    pub fn collector_status(&self, kind: CollectorKind) -> Option<CollectorStatus> {
        Some(match kind {
            CollectorKind::Containers => self.containers.status(),
            CollectorKind::BpfTasks => self.bpf_tasks.status(),
            CollectorKind::ProcTasks => self.proc_tasks.status(),
        })
    }

    pub fn collector_stamp(&self, kind: CollectorKind) -> CollectorStamp {
        match kind {
            CollectorKind::Containers => self.containers.stamp().clone(),
            CollectorKind::BpfTasks => self.bpf_tasks.stamp().clone(),
            CollectorKind::ProcTasks => self.proc_tasks.stamp().clone(),
        }
    }

    /// Mark a collector as cancelled without exposing its previous value.
    ///
    /// This is the in-process equivalent of an operator cancel: any value held
    /// by the slot is dropped immediately, so a later read cannot silently use
    /// evidence that belonged to an abandoned attempt.
    pub fn cancel(&mut self, kind: CollectorKind, reason: impl Into<String>) {
        let reason = reason.into();
        match kind {
            CollectorKind::Containers => self.containers.cancel(reason),
            CollectorKind::BpfTasks => self.bpf_tasks.cancel(reason),
            CollectorKind::ProcTasks => self.proc_tasks.cancel(reason),
        }
    }

    /// Retry a failed or cancelled collector inside the same generation.
    ///
    /// Retrying a collector that already produced evidence is refused: that
    /// would silently replace the observations used by earlier scanners.  A
    /// new observation round must be started instead.
    pub fn retry_failed(&mut self, kind: CollectorKind) -> Result<CollectorStatus, String> {
        let current = self
            .collector_status(kind)
            .ok_or_else(|| format!("unknown collector {}", kind.label()))?;
        if !current.needs_retry() {
            return Err(format!(
                "collector {} is {}; refusing to replace evidence in generation {}",
                kind.label(),
                current.label(),
                self.generation.label()
            ));
        }

        let attempt = self.collector_stamp(kind).attempt.saturating_add(1);
        let generation = self.generation.clone();
        match kind {
            CollectorKind::Containers => {
                let collect = self.backend.containers;
                self.containers = Collector::collect(
                    kind,
                    &generation,
                    attempt,
                    collect(CONTAINER_SCAN_LIMIT),
                    container_result_is_partial,
                );
            }
            CollectorKind::BpfTasks => {
                let collect = self.backend.bpf_tasks;
                self.bpf_tasks = Collector::collect(
                    kind,
                    &generation,
                    attempt,
                    collect(BPF_MAP_SCAN_LIMIT, BPF_ENTRY_SCAN_LIMIT),
                    bpf_result_is_partial,
                );
            }
            CollectorKind::ProcTasks => {
                let collect = self.backend.proc_tasks;
                self.proc_tasks = Collector::collect(
                    kind,
                    &generation,
                    attempt,
                    collect(),
                    proc_result_is_partial,
                );
            }
        }

        Ok(self.collector_status(kind).unwrap_or(current))
    }

    /// Build the final report from this generation's collector stamps only.
    pub fn report(&self) -> HostObservationReport {
        let collectors = vec![
            self.container_report(),
            self.bpf_report(),
            self.proc_report(),
        ];
        let mut merge = GenerationMerge::new(&self.generation);
        for collector in &collectors {
            merge.offer(&collector.stamp);
        }

        HostObservationReport {
            generation: self.generation.clone(),
            collectors,
            merge,
        }
    }

    fn container_report(&self) -> CollectorReport {
        let (item_count, error_count) = self
            .containers
            .value()
            .map(|inventory| (inventory.states.len(), inventory.errors.len()))
            .unwrap_or((0, 0));
        CollectorReport {
            stamp: self.containers.stamp().clone(),
            status: self.containers.status(),
            item_count,
            error_count,
            detail: self.containers.failure().map(|failure| failure.reason),
        }
    }

    fn bpf_report(&self) -> CollectorReport {
        let (item_count, error_count) = self
            .bpf_tasks
            .value()
            .map(|snapshot| (snapshot.tasks.len(), snapshot.errors.len()))
            .unwrap_or((0, 0));
        CollectorReport {
            stamp: self.bpf_tasks.stamp().clone(),
            status: self.bpf_tasks.status(),
            item_count,
            error_count,
            detail: self.bpf_tasks.failure().map(|failure| failure.reason),
        }
    }

    fn proc_report(&self) -> CollectorReport {
        let item_count = self
            .proc_tasks
            .value()
            .map(|tasks| tasks.len())
            .unwrap_or(0);
        CollectorReport {
            stamp: self.proc_tasks.stamp().clone(),
            status: self.proc_tasks.status(),
            item_count,
            error_count: 0,
            detail: self.proc_tasks.failure().map(|failure| failure.reason),
        }
    }
}

/// One collector's contribution to the final host observation report.
#[derive(Clone, Debug)]
pub struct CollectorReport {
    stamp: CollectorStamp,
    status: CollectorStatus,
    item_count: usize,
    error_count: usize,
    detail: Option<String>,
}

impl CollectorReport {
    pub fn kind(&self) -> CollectorKind {
        self.stamp.kind
    }

    pub fn generation(&self) -> &ObservationGeneration {
        &self.stamp.generation
    }

    pub fn attempt(&self) -> u64 {
        self.stamp.attempt
    }

    pub fn status(&self) -> CollectorStatus {
        self.status
    }

    pub fn item_count(&self) -> usize {
        self.item_count
    }

    pub fn error_count(&self) -> usize {
        self.error_count
    }

    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

/// Coarse evidence verdict printed by the final report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostEvidenceStatus {
    Complete,
    Partial,
    Failed,
}

impl HostEvidenceStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Complete => "COMPLETE",
            Self::Partial => "PARTIAL",
            Self::Failed => "FAILED",
        }
    }
}

/// Checks that every offered collector stamp belongs to one generation.
#[derive(Clone, Debug)]
pub struct GenerationMerge {
    generation: ObservationGeneration,
    accepted: usize,
    rejected: usize,
}

impl GenerationMerge {
    pub fn new(generation: &ObservationGeneration) -> Self {
        Self {
            generation: generation.clone(),
            accepted: 0,
            rejected: 0,
        }
    }

    /// Accept a stamp only when it was produced by this generation.
    pub fn offer(&mut self, stamp: &CollectorStamp) -> bool {
        if stamp.belongs_to(&self.generation) {
            self.accepted += 1;
            true
        } else {
            self.rejected += 1;
            false
        }
    }

    pub fn accepted(&self) -> usize {
        self.accepted
    }

    pub fn rejected(&self) -> usize {
        self.rejected
    }

    pub fn same_generation(&self) -> bool {
        self.rejected == 0
    }
}

/// Final, immutable report shared with the host-aware scanner output.
#[derive(Clone, Debug)]
pub struct HostObservationReport {
    generation: ObservationGeneration,
    collectors: Vec<CollectorReport>,
    merge: GenerationMerge,
}

impl HostObservationReport {
    pub fn generation(&self) -> &ObservationGeneration {
        &self.generation
    }

    pub fn collector(&self, kind: CollectorKind) -> Option<&CollectorReport> {
        self.collectors
            .iter()
            .find(|collector| collector.kind() == kind)
    }

    pub fn same_generation(&self) -> bool {
        self.merge.same_generation()
    }

    pub fn rejected_stamps(&self) -> usize {
        self.merge.rejected()
    }

    /// Offer an additional collector stamp to the final report.
    ///
    /// This is the only merge entry point: a stamp from another observation
    /// round is counted as rejected, never added to the report's evidence.
    pub fn accept_stamp(&mut self, stamp: &CollectorStamp) -> bool {
        self.merge.offer(stamp)
    }

    /// Domains whose evidence can be merged into the current report.
    ///
    /// Task evidence requires both the BPF and procfs task collectors; a
    /// failed task collector must not be papered over by a container snapshot
    /// from any other round.
    pub fn merged_domains(&self) -> Vec<&'static str> {
        let container_ok = self
            .collector(CollectorKind::Containers)
            .map(|collector| collector.status().is_usable())
            .unwrap_or(false);
        let bpf_ok = self
            .collector(CollectorKind::BpfTasks)
            .map(|collector| collector.status().is_usable())
            .unwrap_or(false);
        let proc_ok = self
            .collector(CollectorKind::ProcTasks)
            .map(|collector| collector.status().is_usable())
            .unwrap_or(false);

        let mut domains = Vec::new();
        if container_ok {
            domains.push("container");
        }
        if bpf_ok && proc_ok {
            domains.push("tasks");
        }
        domains
    }

    pub fn evidence_status(&self) -> HostEvidenceStatus {
        let usable = self
            .collectors
            .iter()
            .any(|collector| collector.status().is_usable());
        let complete = self
            .collectors
            .iter()
            .all(|collector| collector.status() == CollectorStatus::Complete);

        if !usable {
            HostEvidenceStatus::Failed
        } else if complete && self.same_generation() {
            HostEvidenceStatus::Complete
        } else {
            HostEvidenceStatus::Partial
        }
    }

    /// Render the stable report block appended after all scanners.
    pub fn render_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("generation={}", self.generation.label()),
            format!("boot_id={}", self.generation.boot_id()),
            format!("round={}", self.generation.round()),
        ];

        for collector in &self.collectors {
            let mut line = format!(
                "{}={} attempt={}",
                collector.kind().label(),
                collector.status().label(),
                collector.attempt()
            );
            match collector.kind() {
                CollectorKind::Containers => line.push_str(&format!(
                    " states={} read_errors={}",
                    collector.item_count(),
                    collector.error_count()
                )),
                CollectorKind::BpfTasks => line.push_str(&format!(
                    " tasks={} collection_errors={}",
                    collector.item_count(),
                    collector.error_count()
                )),
                CollectorKind::ProcTasks => {
                    line.push_str(&format!(" tasks={}", collector.item_count()))
                }
            }
            if let Some(detail) = collector.detail() {
                line.push_str(&format!(" reason={}", detail.replace('\n', " ")));
            }
            lines.push(line);
        }

        let domains = self.merged_domains();
        lines.push(format!(
            "merged_evidence={}",
            if domains.is_empty() {
                "none".to_string()
            } else {
                domains.join("+")
            }
        ));
        lines.push(format!("same_generation={}", self.same_generation()));
        lines.push(format!(
            "cross_generation_evidence={}",
            self.rejected_stamps()
        ));
        lines.push(format!(
            "host_observation={}",
            self.evidence_status().label()
        ));
        lines
    }

    pub fn render(&self) -> String {
        self.render_lines().join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::container_utils::{ContainerMount, ContainerState};
    use crate::scanners::task_snapshot::BpfTaskRecord;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static RETRY_BPF_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn test_container() -> ContainerState {
        ContainerState {
            id: "container-a".to_string(),
            pid: Some(4242),
            mounts: vec![ContainerMount {
                destination: "/".to_string(),
                source: Some("/var/lib/docker/overlay2/a".to_string()),
                options: Vec::new(),
            }],
        }
    }

    fn ok_containers(_limit: usize) -> Result<ContainerInventory, CollectionFailure> {
        Ok(ContainerInventory {
            states: vec![test_container()],
            errors: Vec::new(),
        })
    }

    fn empty_containers(_limit: usize) -> Result<ContainerInventory, CollectionFailure> {
        Ok(ContainerInventory::default())
    }

    fn denied_containers(_limit: usize) -> Result<ContainerInventory, CollectionFailure> {
        Ok(ContainerInventory {
            states: Vec::new(),
            errors: vec!["failed to read /run/docker: Permission denied (os error 13)".to_string()],
        })
    }

    fn failed_containers(_limit: usize) -> Result<ContainerInventory, CollectionFailure> {
        Err(CollectionFailure::failed("container collector unavailable"))
    }

    fn ok_bpf(
        _map_limit: usize,
        _entry_limit: usize,
    ) -> Result<BpfTaskSnapshot, CollectionFailure> {
        let mut tasks = HashMap::new();
        tasks.insert(
            4242,
            BpfTaskRecord {
                comm: Some("test-task".to_string()),
                sources: vec!["mock".to_string()],
            },
        );
        Ok(BpfTaskSnapshot {
            tasks,
            errors: Vec::new(),
        })
    }

    fn failed_bpf(
        _map_limit: usize,
        _entry_limit: usize,
    ) -> Result<BpfTaskSnapshot, CollectionFailure> {
        Err(CollectionFailure::failed("bpftool is not available"))
    }

    fn retry_bpf(
        map_limit: usize,
        entry_limit: usize,
    ) -> Result<BpfTaskSnapshot, CollectionFailure> {
        if RETRY_BPF_CALLS.fetch_add(1, Ordering::SeqCst) == 0 {
            ok_bpf(map_limit, entry_limit)
        } else {
            Err(CollectionFailure::failed("retry failed"))
        }
    }

    fn ok_proc() -> Result<HashMap<i32, String>, CollectionFailure> {
        let mut tasks = HashMap::new();
        tasks.insert(4242, "test-task".to_string());
        Ok(tasks)
    }

    fn failed_proc() -> Result<HashMap<i32, String>, CollectionFailure> {
        Err(CollectionFailure::failed(
            "failed to read /proc: Permission denied (os error 13)",
        ))
    }

    fn good_backend() -> CollectionBackend {
        CollectionBackend {
            containers: ok_containers,
            bpf_tasks: ok_bpf,
            proc_tasks: ok_proc,
        }
    }

    #[test]
    fn every_round_gets_a_distinct_generation() {
        let first = HostObservation::start_with(good_backend());
        let second = HostObservation::start_with(good_backend());

        assert_ne!(first.generation().round(), second.generation().round());
        assert_ne!(first.generation().label(), second.generation().label());
        assert!(first.report().same_generation());
        assert!(second.report().same_generation());
    }

    #[test]
    fn failed_second_round_never_exposes_first_round_tasks() {
        let first = HostObservation::start_with(good_backend());
        assert!(first.bpf_tasks().is_ok());

        let second = HostObservation::start_with(CollectionBackend {
            containers: ok_containers,
            bpf_tasks: failed_bpf,
            proc_tasks: ok_proc,
        });
        assert!(second.bpf_tasks().is_err());

        let report = second.report();
        let bpf = report
            .collector(CollectorKind::BpfTasks)
            .expect("bpf report");
        assert_eq!(bpf.status(), CollectorStatus::Failed);
        assert_eq!(bpf.item_count(), 0);
        assert_eq!(bpf.detail(), Some("bpftool is not available"));
        assert!(report.merged_domains().contains(&"container"));
        assert!(!report.merged_domains().contains(&"tasks"));
        assert_eq!(report.evidence_status(), HostEvidenceStatus::Partial);
    }

    #[test]
    fn cross_generation_stamp_is_rejected() {
        let first = HostObservation::start_with(good_backend());
        let second = HostObservation::start_with(good_backend());
        let mut merge = GenerationMerge::new(second.generation());

        let stale = first.collector_stamp(CollectorKind::Containers);
        assert!(!merge.offer(&stale));
        assert_eq!(merge.rejected(), 1);
        assert!(!merge.same_generation());

        let current = second.collector_stamp(CollectorKind::Containers);
        assert!(merge.offer(&current));
        assert_eq!(merge.accepted(), 1);

        let mut report = second.report();
        assert!(!report.accept_stamp(&stale));
        assert_eq!(report.rejected_stamps(), 1);
        assert!(!report.same_generation());
        assert_eq!(report.evidence_status(), HostEvidenceStatus::Partial);
    }

    #[test]
    fn cancelled_collector_drops_previous_value_and_retry_cannot_revive_it() {
        RETRY_BPF_CALLS.store(0, Ordering::SeqCst);
        let mut observation = HostObservation::start_with(CollectionBackend {
            containers: ok_containers,
            bpf_tasks: retry_bpf,
            proc_tasks: ok_proc,
        });
        assert!(observation.bpf_tasks().is_ok());

        observation.cancel(CollectorKind::BpfTasks, "operator cancelled the scan");
        assert!(observation.bpf_tasks().is_err());
        assert_eq!(
            observation.collector_status(CollectorKind::BpfTasks),
            Some(CollectorStatus::Cancelled)
        );

        let status = observation
            .retry_failed(CollectorKind::BpfTasks)
            .expect("retry result");
        assert_eq!(status, CollectorStatus::Failed);
        assert!(observation.bpf_tasks().is_err());

        let report = observation.report();
        let bpf = report
            .collector(CollectorKind::BpfTasks)
            .expect("bpf report");
        assert_eq!(bpf.status(), CollectorStatus::Failed);
        assert_eq!(bpf.attempt(), 3);
        assert_eq!(bpf.item_count(), 0);
        assert!(!report.merged_domains().contains(&"tasks"));
    }

    #[test]
    fn successful_collector_cannot_be_replaced_by_a_retry() {
        let mut observation = HostObservation::start_with(good_backend());
        assert!(observation
            .retry_failed(CollectorKind::Containers)
            .is_err());
        assert_eq!(
            observation.collector_status(CollectorKind::Containers),
            Some(CollectorStatus::Complete)
        );
    }

    #[test]
    fn empty_container_inventory_is_complete_evidence() {
        let observation = HostObservation::start_with(CollectionBackend {
            containers: empty_containers,
            bpf_tasks: ok_bpf,
            proc_tasks: ok_proc,
        });

        let inventory = observation.containers().expect("empty inventory is usable");
        assert!(inventory.states.is_empty());
        assert!(inventory.errors.is_empty());
        assert_eq!(
            observation.collector_status(CollectorKind::Containers),
            Some(CollectorStatus::Complete)
        );
        assert!(observation
            .report()
            .merged_domains()
            .contains(&"container"));
    }

    #[test]
    fn permission_errors_are_partial_evidence_not_a_fallback() {
        let observation = HostObservation::start_with(CollectionBackend {
            containers: denied_containers,
            bpf_tasks: ok_bpf,
            proc_tasks: ok_proc,
        });

        let inventory = observation.containers().expect("partial inventory");
        assert_eq!(inventory.errors.len(), 1);
        assert!(inventory.errors[0].contains("Permission denied"));
        assert_eq!(
            observation.collector_status(CollectorKind::Containers),
            Some(CollectorStatus::Partial)
        );
        let report = observation.report();
        assert_eq!(report.evidence_status(), HostEvidenceStatus::Partial);
        assert!(report.merged_domains().contains(&"container"));
        assert!(report.render().contains("read_errors=1"));
    }

    #[test]
    fn failed_task_collector_is_reported_and_keeps_original_text() {
        let observation = HostObservation::start_with(CollectionBackend {
            containers: ok_containers,
            bpf_tasks: ok_bpf,
            proc_tasks: failed_proc,
        });

        let failure = observation.proc_tasks().expect_err("proc collector failed");
        assert_eq!(
            failure.to_string(),
            "failed to read /proc: Permission denied (os error 13)"
        );
        let report = observation.report();
        assert!(!report.merged_domains().contains(&"tasks"));
        assert!(report.render().contains("proc_tasks=FAILED"));
    }

    #[test]
    fn report_stamps_every_collector_with_the_same_generation() {
        let observation = HostObservation::start_with(good_backend());
        let report = observation.report();

        assert!(report.same_generation());
        assert_eq!(report.rejected_stamps(), 0);
        for kind in CollectorKind::all() {
            let collector = report.collector(kind).expect("collector present");
            assert_eq!(collector.generation(), observation.generation());
        }
        assert_eq!(report.evidence_status(), HostEvidenceStatus::Complete);
        assert_eq!(
            report.merged_domains(),
            vec!["container", "tasks"]
        );
        let label = observation.generation().label();
        assert!(report.render().contains(label.as_str()));
        assert!(report.render().contains("host_observation=COMPLETE"));
    }

    #[test]
    fn failed_container_collector_does_not_fall_back_to_another_round() {
        let first = HostObservation::start_with(good_backend());
        assert!(first.containers().is_ok());
        let second = HostObservation::start_with(CollectionBackend {
            containers: failed_containers,
            bpf_tasks: ok_bpf,
            proc_tasks: ok_proc,
        });

        assert!(second.containers().is_err());
        let report = second.report();
        assert!(!report.merged_domains().contains(&"container"));
        assert!(report.merged_domains().contains(&"tasks"));
        assert_eq!(report.evidence_status(), HostEvidenceStatus::Partial);
    }
}
