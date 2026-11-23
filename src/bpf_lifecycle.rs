//! One lifecycle transaction for every BPF object scanner.
//!
//! BPF programs, maps, links (attachments) and pins are not independent
//! observations.  A program can be detached and a new program can reuse its
//! numeric id between two `bpftool` invocations, and a pin can be moved while a
//! scan is running.  If every scanner collects its own copy, ghostscan can
//! print a kprobe link from one generation next to an ownerless program from a
//! different generation.
//!
//! This module makes the scan round explicit:
//!
//! * one [`LifecycleStamp`] (boot id + process-local generation + start time)
//!   is created before any object is read,
//! * programs, maps, links and pins are collected once and stamped with that
//!   generation,
//! * a second identity fence is read after the first pass; if an object id
//!   changes tag/name/attachment/pin state between the two reads, the whole
//!   generation is discarded and retried,
//! * the final snapshot only ever contains records from the last successful
//!   generation.  A failed retry never resurrects records from an earlier one,
//! * a link or pin that points at a program/map with a different identity is a
//!   generation conflict, not extra evidence,
//! * the final report prints the same boot/generation label as the scanners.
//!
//! Legitimate bpffs pins, anonymous (ownerless) programs, kprobe/kretprobe and
//! other distinct attach types, and permission failures are kept as explicit
//! observations instead of being collapsed into a synthetic clean result.

use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

/// How many complete generations may be collected before the transaction is
/// declared unstable.  Each retry starts from an empty generation; no partial
/// records are carried across attempts.
pub const MAX_GENERATION_ATTEMPTS: u32 = 4;

/// Stable identity shared by every object record in one lifecycle generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LifecycleStamp {
    /// `/proc/sys/kernel/random/boot_id`, or `unknown` when unreadable.
    pub boot_id: String,
    /// Process-local monotonic generation number.
    pub generation: u64,
    /// Attempt within this generation slot (starts at one).
    pub attempt: u32,
    /// Wall clock start of this generation in nanoseconds since the epoch.
    pub started_unix_ns: u128,
    /// PID of the ghostscan process that observed the objects.
    pub pid: u32,
}

impl LifecycleStamp {
    /// Stable label printed by scanners and the final report.
    pub fn label(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.boot_id, self.generation, self.started_unix_ns, self.pid
        )
    }

    /// Two stamps belong to the same generation only when both the boot and
    /// the process-local generation agree.
    pub fn same_generation(&self, other: &Self) -> bool {
        self.boot_id == other.boot_id && self.generation == other.generation
    }
}

/// Object families covered by the transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ObjectKind {
    Program,
    Map,
    Link,
    Pin,
}

impl ObjectKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Program => "prog",
            Self::Map => "map",
            Self::Link => "link",
            Self::Pin => "pin",
        }
    }
}

/// The four `bpftool` collectors plus the mount table used to classify pins.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CollectorKind {
    Programs,
    Maps,
    Links,
    Net,
    MountInfo,
    Pins,
}

impl CollectorKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Programs => "programs",
            Self::Maps => "maps",
            Self::Links => "links",
            Self::Net => "net",
            Self::MountInfo => "mountinfo",
            Self::Pins => "pins",
        }
    }
}

/// Why a collector did not produce a usable inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    /// The executable is absent.
    NotAvailable,
    /// The kernel or filesystem denied the read.
    PermissionDenied,
    /// The command ran but exited non-zero.
    CommandFailed,
    /// Output could not be parsed as the expected JSON document.
    ParseFailed,
    /// The object changed while the transaction was being collected.
    Unstable,
}

/// One collector failure, kept verbatim for the scanner compatibility surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LifecycleError {
    pub collector: CollectorKind,
    pub kind: FailureKind,
    pub message: String,
}

impl LifecycleError {
    pub fn not_available(collector: CollectorKind, message: impl Into<String>) -> Self {
        Self {
            collector,
            kind: FailureKind::NotAvailable,
            message: message.into(),
        }
    }

    pub fn permission_denied(collector: CollectorKind, message: impl Into<String>) -> Self {
        Self {
            collector,
            kind: FailureKind::PermissionDenied,
            message: message.into(),
        }
    }

    pub fn command_failed(collector: CollectorKind, message: impl Into<String>) -> Self {
        Self {
            collector,
            kind: FailureKind::CommandFailed,
            message: message.into(),
        }
    }

    pub fn parse_failed(collector: CollectorKind, message: impl Into<String>) -> Self {
        Self {
            collector,
            kind: FailureKind::ParseFailed,
            message: message.into(),
        }
    }
}

/// BPF program identity.  `id` alone is not an identity: the kernel may reuse a
/// numeric id after a detach, so `tag`, `name` and the program/attach types are
/// part of the record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramRecord {
    pub id: u64,
    pub name: String,
    pub tag: String,
    pub prog_type: String,
    pub attach_type: String,
    pub owner_pids: Vec<u64>,
    pub pinned: Vec<String>,
    pub pinned_flag: bool,
    pub stamp: LifecycleStamp,
}

/// BPF map identity, including the program referenced by sockmap/sockhash
/// verdict maps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapRecord {
    pub id: u64,
    pub name: String,
    pub map_type: String,
    pub owner_pids: Vec<u64>,
    pub pinned: Vec<String>,
    pub pinned_flag: bool,
    pub verdict_prog_id: Option<u64>,
    pub verdict_prog_tag: Option<String>,
    pub stamp: LifecycleStamp,
}

/// Attachment identity.  The link id and attach kind are kept next to the
/// program id and (when bpftool exposes it) the program tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkRecord {
    pub id: u64,
    pub prog_id: Option<u64>,
    pub prog_tag: Option<String>,
    pub link_type: String,
    pub attach_type: String,
    pub target: String,
    pub pinned: Vec<String>,
    pub pinned_flag: bool,
    pub stamp: LifecycleStamp,
}

/// Filesystem identity of a pin, in addition to the pinned object identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileIdentity {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime_ns: i64,
}

/// A pin path plus the object and filesystem identity observed in the same
/// generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinRecord {
    pub path: String,
    pub object_kind: ObjectKind,
    pub object_id: u64,
    pub object_tag: Option<String>,
    pub mount_fstype: String,
    pub file_identity: Option<FileIdentity>,
    pub stamp: LifecycleStamp,
}

impl PinRecord {
    pub fn on_bpffs(&self) -> bool {
        self.mount_fstype == "bpf"
    }
}

/// Immutable result of one complete (or explicitly partial) lifecycle pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BpfSnapshot {
    pub stamp: LifecycleStamp,
    pub programs: Vec<ProgramRecord>,
    pub maps: Vec<MapRecord>,
    pub links: Vec<LinkRecord>,
    pub pins: Vec<PinRecord>,
    pub errors: Vec<LifecycleError>,
    pub mount_errors: Vec<String>,
    pub conflicts: Vec<String>,
    pub limitations: Vec<String>,
    pub cross_generation: usize,
    pub net_list: Option<String>,
}

impl BpfSnapshot {
    pub fn new(stamp: LifecycleStamp) -> Self {
        Self {
            stamp,
            programs: Vec::new(),
            maps: Vec::new(),
            links: Vec::new(),
            pins: Vec::new(),
            errors: Vec::new(),
            mount_errors: Vec::new(),
            conflicts: Vec::new(),
            limitations: Vec::new(),
            cross_generation: 0,
            net_list: None,
        }
    }

    pub fn generation_label(&self) -> String {
        self.stamp.label()
    }

    pub fn same_generation(&self, other: &Self) -> bool {
        self.stamp.same_generation(&other.stamp)
    }

    pub fn program(&self, id: u64) -> Option<&ProgramRecord> {
        self.programs.iter().find(|program| program.id == id)
    }

    pub fn map(&self, id: u64) -> Option<&MapRecord> {
        self.maps.iter().find(|map| map.id == id)
    }

    pub fn link(&self, id: u64) -> Option<&LinkRecord> {
        self.links.iter().find(|link| link.id == id)
    }

    pub fn error_for(&self, collector: CollectorKind) -> Option<&LifecycleError> {
        self.errors.iter().find(|error| error.collector == collector)
    }

    pub fn errors_for(&self, collector: CollectorKind) -> Vec<&LifecycleError> {
        self.errors
            .iter()
            .filter(|error| error.collector == collector)
            .collect()
    }

    pub fn has_error(&self, collector: CollectorKind) -> bool {
        self.error_for(collector).is_some()
    }

    pub fn is_complete(&self) -> bool {
        self.errors.is_empty() && self.mount_errors.is_empty() && self.conflicts.is_empty()
    }

    /// Re-run lifecycle identity validation and fold the result into this
    /// snapshot.  A conflict is never converted into a finding.
    pub fn validate(&mut self) {
        let (conflicts, cross_generation) = validate_identities(&*self);
        self.conflicts.extend(conflicts);
        self.cross_generation = self.cross_generation.saturating_add(cross_generation);
    }

    /// Programs that no task owns and no pin keeps alive.  These are the
    /// legitimate "anonymous" programs the ownerless scanner is meant to
    /// surface; they are not discarded just because the transaction is shared.
    pub fn ownerless_programs(&self) -> impl Iterator<Item = &ProgramRecord> + '_ {
        self.programs
            .iter()
            .filter(|program| {
                program.owner_pids.is_empty()
                    && !program.pinned_flag
                    && program.pinned.is_empty()
            })
    }

    /// The program a link refers to, but only when the tag (when available)
    /// agrees with the program record.  A mismatched or missing program means
    /// the caller must not publish the link as current evidence.
    pub fn link_program(&self, link: &LinkRecord) -> Option<&ProgramRecord> {
        let id = link.prog_id?;
        let program = self.program(id)?;
        match link.prog_tag.as_deref() {
            Some(tag) if !tag.is_empty() && tag != "unknown" && tag != program.tag.as_str() => None,
            _ => Some(program),
        }
    }

    /// Public summary line shared with the final `ScanOutcome` output.
    pub fn summary_line(&self) -> String {
        let object_identity = if self.conflicts.is_empty() {
            self.object_identity()
        } else {
            "unstable".to_string()
        };
        let retries = self
            .limitations
            .iter()
            .filter(|limitation| limitation.starts_with("generation="))
            .count();
        let status = if !self.conflicts.is_empty() {
            "UNSTABLE"
        } else if !self.errors.is_empty() || !self.mount_errors.is_empty() {
            "PARTIAL"
        } else {
            "COMPLETE"
        };
        let verdict = if !self.conflicts.is_empty() {
            "INCONCLUSIVE"
        } else if !self.errors.is_empty() || !self.mount_errors.is_empty() {
            "INCONCLUSIVE"
        } else {
            "CONSISTENT"
        };
        format!(
            "BPF_LIFECYCLE boot_id={} generation={} round={} attempt={} retries={} programs={} maps={} links={} pins={} cross_generation={} conflicts={} errors={} status={} BPF_VERDICT={} object_identity={}",
            self.stamp.boot_id,
            self.stamp.label(),
            self.stamp.generation,
            self.stamp.attempt,
            retries,
            self.programs.len(),
            self.maps.len(),
            self.links.len(),
            self.pins.len(),
            self.cross_generation,
            self.conflicts.len(),
            self.errors.len() + self.mount_errors.len(),
            status,
            verdict,
            object_identity
        )
    }

    /// Compact identity list used by the final report to check that the three
    /// public scanners and the summary refer to the same objects.
    pub fn object_identity(&self) -> String {
        let mut parts = Vec::new();
        for program in &self.programs {
            parts.push(format!("prog:{}@{}", program.id, program.tag));
        }
        for map in &self.maps {
            parts.push(format!("map:{}@{}", map.id, map.name));
        }
        for link in &self.links {
            parts.push(format!(
                "link:{}@{}",
                link.id,
                link.prog_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "none".to_string())
            ));
        }
        for pin in &self.pins {
            parts.push(format!(
                "pin:{}@{}:{}",
                pin.path,
                pin.object_kind.label(),
                pin.object_id
            ));
        }
        if parts.is_empty() {
            "-".to_string()
        } else {
            parts.join("|")
        }
    }
}

/// Collector backend.  Production uses `bpftool`; tests can provide function
/// pointers that return deterministic JSON values without touching the host.
#[derive(Clone, Copy)]
pub struct BpfBackend {
    pub prog_show: fn() -> Result<Vec<Value>, LifecycleError>,
    pub map_show: fn() -> Result<Vec<Value>, LifecycleError>,
    pub link_show: fn() -> Result<Vec<Value>, LifecycleError>,
    pub net_list: fn() -> Result<String, LifecycleError>,
}

impl BpfBackend {
    pub const fn live() -> Self {
        Self {
            prog_show: live_prog_show,
            map_show: live_map_show,
            link_show: live_link_show,
            net_list: live_net_list,
        }
    }
}

#[derive(Debug)]
struct TransactionState {
    next_generation: u64,
    scan_sequence: u64,
    snapshot: Option<Arc<BpfSnapshot>>,
    retry_reasons: Vec<String>,
}

impl TransactionState {
    const fn new() -> Self {
        Self {
            next_generation: 0,
            scan_sequence: 0,
            snapshot: None,
            retry_reasons: Vec::new(),
        }
    }
}

/// The single process-wide BPF lifecycle transaction.
pub struct BpfTransaction {
    backend: BpfBackend,
    state: Mutex<TransactionState>,
}

impl BpfTransaction {
    pub const fn with_backend(backend: BpfBackend) -> Self {
        Self {
            backend,
            state: Mutex::new(TransactionState::new()),
        }
    }

    pub const fn live() -> Self {
        Self::with_backend(BpfBackend::live())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, TransactionState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Start one scan generation.  Any records from an earlier scan are
    /// dropped before the scanner loop runs; they are never reused as a cache.
    pub fn begin_scan(&self) {
        let mut state = self.lock();
        state.scan_sequence = state.scan_sequence.saturating_add(1);
        state.snapshot = None;
        state.retry_reasons.clear();
    }

    /// Alias for [`begin_scan`](Self::begin_scan).
    pub fn start_scan(&self) {
        self.begin_scan();
    }

    /// Explicitly discard the current generation.  The next [`snapshot`]
    /// call collects all four object families again under a new stamp.
    pub fn retry(&self, reason: impl Into<String>) {
        let mut state = self.lock();
        state.retry_reasons.push(reason.into());
        state.snapshot = None;
    }

    /// Alias for [`begin_scan`](Self::begin_scan): start a fresh generation
    /// without carrying any earlier records.
    pub fn begin_round(&self) {
        self.begin_scan();
    }

    /// Alias for [`retry`](Self::retry): discard the current generation.
    pub fn retry_generation(&self, reason: impl Into<String>) {
        self.retry(reason);
    }

    /// Stamp of the current generation, if one has been collected.
    pub fn current_stamp(&self) -> Option<LifecycleStamp> {
        self.lock()
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.stamp.clone())
    }

    pub fn scan_sequence(&self) -> u64 {
        self.lock().scan_sequence
    }

    pub fn retry_reasons(&self) -> Vec<String> {
        self.lock().retry_reasons.clone()
    }

    /// Snapshot for the current generation.  The first BPF scanner pays for
    /// collection; every later BPF scanner receives the exact same records.
    pub fn snapshot(&self) -> Arc<BpfSnapshot> {
        let mut state = self.lock();
        if let Some(snapshot) = &state.snapshot {
            return Arc::clone(snapshot);
        }

        let mut snapshot = self.collect_stable_generation(&mut *state);
        if !state.retry_reasons.is_empty() {
            snapshot
                .limitations
                .extend(state.retry_reasons.iter().cloned());
        }
        let snapshot = Arc::new(snapshot);
        state.snapshot = Some(Arc::clone(&snapshot));
        snapshot
    }

    fn collect_stable_generation(&self, state: &mut TransactionState) -> BpfSnapshot {
        let mut last: Option<BpfSnapshot> = None;

        for attempt in 1..=MAX_GENERATION_ATTEMPTS {
            state.next_generation = state.next_generation.saturating_add(1);
            let stamp = LifecycleStamp {
                boot_id: read_boot_id(),
                generation: state.next_generation,
                attempt,
                started_unix_ns: now_unix_ns(),
                pid: std::process::id(),
            };

            let snapshot = self.collect_once(stamp);
            if snapshot.conflicts.is_empty() {
                return snapshot;
            }
            // The whole generation is dropped.  `last` is only used to report
            // the final failure; its records are never merged with an earlier
            // attempt.
            state.retry_reasons.push(format!(
                "generation={} discarded: {}",
                snapshot.stamp.generation,
                snapshot.conflicts.join("; ")
            ));
            last = Some(snapshot);
        }

        let mut snapshot = last.unwrap_or_else(|| {
            let stamp = LifecycleStamp {
                boot_id: read_boot_id(),
                generation: state.next_generation.saturating_add(1),
                attempt: MAX_GENERATION_ATTEMPTS,
                started_unix_ns: now_unix_ns(),
                pid: std::process::id(),
            };
            BpfSnapshot::new(stamp)
        });
        snapshot.conflicts.push(format!(
            "no stable BPF generation after {} attempts",
            MAX_GENERATION_ATTEMPTS
        ));
        snapshot.cross_generation = snapshot.cross_generation.saturating_add(1);
        snapshot
    }

    fn collect_once(&self, stamp: LifecycleStamp) -> BpfSnapshot {
        let mut snapshot = BpfSnapshot::new(stamp.clone());

        let mounts = match parse_mountinfo() {
            Ok(mut mounts) => {
                mounts.sort_by_key(|entry| std::cmp::Reverse(entry.mount_point.components().count()));
                mounts
            }
            Err(error) => {
                snapshot
                    .mount_errors
                    .push(format!("failed to parse /proc/self/mountinfo: {error}"));
                Vec::new()
            }
        };

        // First observation of every object family.
        let prog_values = match (self.backend.prog_show)() {
            Ok(values) => values,
            Err(error) => {
                push_error(&mut snapshot, error);
                Vec::new()
            }
        };
        let map_values = match (self.backend.map_show)() {
            Ok(values) => values,
            Err(error) => {
                push_error(&mut snapshot, error);
                Vec::new()
            }
        };
        let link_values = match (self.backend.link_show)() {
            Ok(values) => values,
            Err(error) => {
                push_error(&mut snapshot, error);
                Vec::new()
            }
        };
        match (self.backend.net_list)() {
            Ok(payload) => {
                if !payload.trim().is_empty() {
                    snapshot.net_list = Some(payload);
                }
            }
            Err(error) => push_error(&mut snapshot, error),
        }

        let programs = build_programs(&prog_values, &stamp);
        let maps = build_maps(&map_values, &stamp);
        let links = build_links(&link_values, &stamp);

        // Identity fence: read the same families again after the first pass.
        // Only identity fields participate; volatile counters in bpftool
        // output must not cause spurious retries.
        let fence_programs = match (self.backend.prog_show)() {
            Ok(values) => Some(build_programs(&values, &stamp)),
            Err(error) => {
                push_error(&mut snapshot, error);
                None
            }
        };
        let fence_maps = match (self.backend.map_show)() {
            Ok(values) => Some(build_maps(&values, &stamp)),
            Err(error) => {
                push_error(&mut snapshot, error);
                None
            }
        };
        let fence_links = match (self.backend.link_show)() {
            Ok(values) => Some(build_links(&values, &stamp)),
            Err(error) => {
                push_error(&mut snapshot, error);
                None
            }
        };

        if let Some(fence) = fence_programs {
            compare_identity_sets(
                ObjectKind::Program,
                &program_fingerprints(&programs),
                &program_fingerprints(&fence),
                &mut snapshot.conflicts,
                &mut snapshot.cross_generation,
            );
        }
        if let Some(fence) = fence_maps {
            compare_identity_sets(
                ObjectKind::Map,
                &map_fingerprints(&maps),
                &map_fingerprints(&fence),
                &mut snapshot.conflicts,
                &mut snapshot.cross_generation,
            );
        }
        if let Some(fence) = fence_links {
            compare_identity_sets(
                ObjectKind::Link,
                &link_fingerprints(&links),
                &link_fingerprints(&fence),
                &mut snapshot.conflicts,
                &mut snapshot.cross_generation,
            );
        }

        snapshot.pins = build_pins(&programs, &maps, &links, &mounts);
        snapshot.programs = programs;
        snapshot.maps = maps;
        snapshot.links = links;

        let pin_conflicts = verify_pin_identities(&snapshot.pins);
        snapshot.cross_generation = snapshot
            .cross_generation
            .saturating_add(pin_conflicts.len());
        snapshot.conflicts.extend(pin_conflicts);

        let (conflicts, cross_generation) = validate_identities(&snapshot);
        snapshot.conflicts.extend(conflicts);
        snapshot.cross_generation = snapshot
            .cross_generation
            .saturating_add(cross_generation);
        snapshot
    }
}

/// Process-wide transaction shared by every BPF scanner and `main`.
pub static BPF_TRANSACTION: BpfTransaction = BpfTransaction::live();

/// Alias used by callers that prefer the shorter name.
pub use self::BPF_TRANSACTION as BPF_LIFECYCLE;

/// Convenience wrapper used by `main` to render the final ScanOutcome summary.
pub fn summarize(transaction: &BpfTransaction) -> String {
    transaction.snapshot().summary_line()
}

/// Final ScanOutcome for the whole BPF lifecycle.  A partial or unstable
/// generation is an error outcome so it can never be mistaken for a complete
/// observation; the summary text still carries the boot/generation identity.
pub fn final_scan_outcome(transaction: &BpfTransaction) -> crate::ScanOutcome {
    let snapshot = transaction.snapshot();
    let summary = snapshot.summary_line();
    if snapshot.is_complete() {
        Ok(Some(summary))
    } else {
        Err(summary)
    }
}

/// Validate an independently constructed snapshot (useful to callers that
/// supply records from a deterministic backend).
pub fn validate_snapshot(snapshot: &BpfSnapshot) -> (Vec<String>, usize) {
    validate_identities(snapshot)
}

fn now_unix_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}


/// Read the translated instruction stream for one program id.
///
/// The caller keeps the program's lifecycle stamp and must verify the tag after
/// the dump before publishing any symbol evidence.
pub fn dump_program_xlated(id: u64) -> Result<String, String> {
    let id_str = id.to_string();
    let output = Command::new("bpftool")
        .args(["prog", "dump", "xlated", "id", &id_str])
        .output()
        .map_err(|err| format!("failed to dump program: {err}"))?;

    if !output.status.success() {
        return Err(format!("dump failed with status {}", output.status));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Re-read one program id and check that its tag is still the tag captured by
/// the lifecycle snapshot.  A different tag means the id was detached and
/// reused; the caller must discard the dump instead of attaching it to the
/// earlier program record.
pub fn verify_program_tag(id: u64, expected_tag: &str) -> Result<(), String> {
    let id_str = id.to_string();
    let output = Command::new("bpftool")
        .args(["-j", "prog", "show", "id", &id_str])
        .output()
        .map_err(|err| format!("failed to re-read program identity: {err}"))?;

    if !output.status.success() {
        return Err(format!(
            "program identity re-read exited with {}",
            output.status
        ));
    }

    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("failed to parse program identity: {err}"))?;
    let entries = match value {
        Value::Array(items) => items,
        other => vec![other],
    };
    if entries.is_empty() {
        return Err(format!(
            "program id={} disappeared during dump",
            id
        ));
    }
    let current_tag = entries
        .first()
        .and_then(|entry| entry.get("tag"))
        .and_then(|tag| tag.as_str())
        .unwrap_or("");

    if !current_tag.is_empty() && current_tag != expected_tag {
        return Err(format!(
            "program id={} tag changed during dump ({} -> {})",
            id, expected_tag, current_tag
        ));
    }
    Ok(())
}

/// Read the current boot id.  A missing procfs entry is reported as `unknown`
/// instead of being replaced by a guessed value.
pub fn read_boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn live_prog_show() -> Result<Vec<Value>, LifecycleError> {
    collect_bpftool_json(&["-j", "prog", "show"], CollectorKind::Programs)
}

fn live_map_show() -> Result<Vec<Value>, LifecycleError> {
    collect_bpftool_json(&["-j", "map", "show"], CollectorKind::Maps)
}

fn live_link_show() -> Result<Vec<Value>, LifecycleError> {
    collect_bpftool_json(&["-j", "link", "show"], CollectorKind::Links)
}

fn live_net_list() -> Result<String, LifecycleError> {
    let output = Command::new("bpftool")
        .args(["-j", "net", "list"])
        .output()
        .map_err(|error| command_spawn_error(CollectorKind::Net, error))?;

    if !output.status.success() {
        return Err(command_status_error(
            CollectorKind::Net,
            "bpftool net list",
            &output.status,
            &output.stderr,
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn collect_bpftool_json(
    args: &[&str],
    collector: CollectorKind,
) -> Result<Vec<Value>, LifecycleError> {
    let output = Command::new("bpftool")
        .args(args)
        .output()
        .map_err(|error| command_spawn_error(collector, error))?;

    if !output.status.success() {
        let command = format!("bpftool {}", args.join(" "));
        return Err(command_status_error(
            collector,
            &command,
            &output.status,
            &output.stderr,
        ));
    }

    let value: Value = serde_json::from_slice(&output.stdout).map_err(|error| {
        LifecycleError::parse_failed(
            collector,
            format!(
                "failed to parse bpftool {} output: {error}",
                collector.label()
            ),
        )
    })?;

    let values = match value {
        Value::Array(items) => items,
        Value::Null => Vec::new(),
        other => vec![other],
    };
    Ok(values)
}

fn command_spawn_error(collector: CollectorKind, error: io::Error) -> LifecycleError {
    if error.kind() == io::ErrorKind::NotFound {
        LifecycleError::not_available(
            collector,
            format!("bpftool not available to inspect {}", collector.label()),
        )
    } else if error.kind() == io::ErrorKind::PermissionDenied {
        LifecycleError::permission_denied(
            collector,
            format!(
                "failed to execute bpftool {}: permission denied ({error})",
                collector.label()
            ),
        )
    } else {
        LifecycleError::command_failed(
            collector,
            format!(
                "failed to execute bpftool {}: {error}",
                collector.label()
            ),
        )
    }
}

fn command_status_error(
    collector: CollectorKind,
    command: &str,
    status: &std::process::ExitStatus,
    stderr: &[u8],
) -> LifecycleError {
    let detail = String::from_utf8_lossy(stderr);
    let detail = detail.trim();
    let message = if detail.is_empty() {
        format!("{command} exited with {status}")
    } else {
        format!("{command} exited with {status}: {detail}")
    };
    let lower = detail.to_ascii_lowercase();
    if lower.contains("permission")
        || lower.contains("operation not permitted")
        || lower.contains("not permitted")
    {
        LifecycleError::permission_denied(collector, message)
    } else {
        LifecycleError::command_failed(collector, message)
    }
}

fn number_field(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(|field| {
        field
            .as_u64()
            .or_else(|| field.as_str().and_then(|text| text.parse::<u64>().ok()))
    })
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(|field| {
        field
            .as_str()
            .map(|text| text.trim().to_string())
            .filter(|text| !text.is_empty())
    })
}

fn owner_pids(value: &Value) -> Vec<u64> {
    let mut pids = BTreeSet::new();
    if let Some(field) = value.get("pids") {
        match field {
            Value::Array(items) => {
                for item in items {
                    if let Some(pid) = item.as_u64() {
                        pids.insert(pid);
                    } else if let Some(pid) = number_field(item, "pid") {
                        pids.insert(pid);
                    }
                }
            }
            Value::Number(number) => {
                if let Some(pid) = number.as_u64() {
                    pids.insert(pid);
                }
            }
            Value::String(text) => {
                for token in text.split(|character: char| !character.is_ascii_digit()) {
                    if let Ok(pid) = token.parse::<u64>() {
                        pids.insert(pid);
                    }
                }
            }
            _ => {}
        }
    }
    pids.into_iter().collect()
}

fn pin_fields(value: &Value) -> (Vec<String>, bool) {
    let mut paths = BTreeSet::new();
    let mut flag = false;

    if let Some(pinned) = value.get("pinned") {
        match pinned {
            Value::Bool(value) => flag = *value,
            other => {
                flag = value_has_pin(other);
                collect_paths(other, &mut paths);
            }
        }
    }
    if let Some(pins) = value.get("pins") {
        flag = flag || value_has_pin(pins);
        collect_paths(pins, &mut paths);
    }

    let paths = paths.into_iter().collect::<Vec<_>>();
    (paths, flag || !paths.is_empty())
}

fn value_has_pin(value: &Value) -> bool {
    match value {
        Value::Bool(value) => *value,
        Value::String(text) => !text.trim().is_empty(),
        Value::Array(items) => items.iter().any(value_has_pin),
        Value::Object(map) => map.values().any(value_has_pin),
        _ => false,
    }
}

fn collect_paths(value: &Value, set: &mut BTreeSet<String>) {
    match value {
        Value::String(text) => {
            let text = text.trim();
            if !text.is_empty() {
                set.insert(text.to_string());
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_paths(item, set);
            }
        }
        Value::Object(map) => {
            for item in map.values() {
                collect_paths(item, set);
            }
        }
        _ => {}
    }
}

fn extract_verdict_program(value: &Value) -> (Option<u64>, Option<String>) {
    let mut id = number_field(value, "verdict_prog_id")
        .or_else(|| number_field(value, "verdict_prog"))
        .filter(|id| *id != 0);
    let mut tag = string_field(value, "verdict_prog_tag");

    for key in ["verdict_prog", "prog", "owner_prog"] {
        if let Some(nested) = value.get(key) {
            id = id.or_else(|| number_field(nested, "id"));
            tag = tag.or_else(|| string_field(nested, "tag"));
        }
    }

    (id.filter(|id| *id != 0), tag)
}

fn extract_target_symbol(value: &Value) -> Option<String> {
    const CANDIDATES: [&str; 6] = [
        "target_name",
        "target",
        "func",
        "function",
        "kprobe",
        "attach_name",
    ];
    for key in &CANDIDATES {
        if let Some(symbol) = string_field(value, key) {
            return Some(symbol);
        }
    }

    if let Some(map) = value.as_object() {
        for (key, field) in map {
            if key.contains("func") || key.contains("symbol") {
                if let Some(symbol) = field.as_str().map(str::trim).filter(|s| !s.is_empty()) {
                    return Some(symbol.to_string());
                }
            }
        }
    }
    None
}

fn build_programs(values: &[Value], stamp: &LifecycleStamp) -> Vec<ProgramRecord> {
    let mut programs = values
        .iter()
        .filter_map(|value| {
            let id = number_field(value, "id")?;
            let (pinned, pinned_flag) = pin_fields(value);
            Some(ProgramRecord {
                id,
                name: string_field(value, "name").unwrap_or_else(|| "unknown".to_string()),
                tag: string_field(value, "tag").unwrap_or_else(|| "unknown".to_string()),
                prog_type: string_field(value, "type")
                    .unwrap_or_else(|| "unknown".to_string()),
                attach_type: string_field(value, "attach_type")
                    .unwrap_or_else(|| "unknown".to_string()),
                owner_pids: owner_pids(value),
                pinned,
                pinned_flag,
                stamp: stamp.clone(),
            })
        })
        .collect::<Vec<_>>();
    programs.sort_by_key(|program| program.id);
    programs
}

fn build_maps(values: &[Value], stamp: &LifecycleStamp) -> Vec<MapRecord> {
    let mut maps = values
        .iter()
        .filter_map(|value| {
            let id = number_field(value, "id")?;
            let (pinned, pinned_flag) = pin_fields(value);
            let map_type = string_field(value, "type").unwrap_or_else(|| "unknown".to_string());
            let lower_type = map_type.to_ascii_lowercase();
            let (verdict_prog_id, verdict_prog_tag) =
                if lower_type == "sockmap" || lower_type == "sockhash" {
                    extract_verdict_program(value)
                } else {
                    (None, None)
                };
            Some(MapRecord {
                id,
                name: string_field(value, "name").unwrap_or_else(|| "unknown".to_string()),
                map_type,
                owner_pids: owner_pids(value),
                pinned,
                pinned_flag,
                verdict_prog_id,
                verdict_prog_tag,
                stamp: stamp.clone(),
            })
        })
        .collect::<Vec<_>>();
    maps.sort_by_key(|map| map.id);
    maps
}

fn build_links(values: &[Value], stamp: &LifecycleStamp) -> Vec<LinkRecord> {
    let mut links = values
        .iter()
        .filter_map(|value| {
            let id = number_field(value, "id")?;
            let (pinned, pinned_flag) = pin_fields(value);
            let mut prog_id = number_field(value, "prog_id").filter(|id| *id != 0);
            let mut prog_tag = string_field(value, "prog_tag");
            for key in ["prog", "program"] {
                if let Some(nested) = value.get(key) {
                    prog_id = prog_id
                        .or_else(|| number_field(nested, "id").filter(|id| *id != 0));
                    prog_tag = prog_tag.or_else(|| string_field(nested, "tag"));
                }
            }
            Some(LinkRecord {
                id,
                prog_id,
                prog_tag,
                link_type: string_field(value, "type")
                    .unwrap_or_else(|| "unknown".to_string()),
                attach_type: string_field(value, "attach_type")
                    .unwrap_or_else(|| "unknown".to_string()),
                target: extract_target_symbol(value).unwrap_or_else(|| "unknown".to_string()),
                pinned,
                pinned_flag,
                stamp: stamp.clone(),
            })
        })
        .collect::<Vec<_>>();
    links.sort_by_key(|link| link.id);
    links
}

fn build_pins(
    programs: &[ProgramRecord],
    maps: &[MapRecord],
    links: &[LinkRecord],
    mounts: &[MountEntry],
) -> Vec<PinRecord> {
    let mut pins = Vec::new();

    for program in programs {
        for path in &program.pinned {
            pins.push(make_pin(
                path,
                ObjectKind::Program,
                program.id,
                Some(program.tag.clone()),
                mounts,
                &program.stamp,
            ));
        }
    }
    for map in maps {
        for path in &map.pinned {
            pins.push(make_pin(
                path,
                ObjectKind::Map,
                map.id,
                None,
                mounts,
                &map.stamp,
            ));
        }
    }
    for link in links {
        for path in &link.pinned {
            pins.push(make_pin(
                path,
                ObjectKind::Link,
                link.id,
                link.prog_tag.clone(),
                mounts,
                &link.stamp,
            ));
        }
    }

    pins.sort_by(|left, right| {
        left.object_kind
            .cmp(&right.object_kind)
            .then_with(|| left.path.cmp(&right.path))
    });
    pins.dedup_by(|left, right| {
        left.object_kind == right.object_kind
            && left.object_id == right.object_id
            && left.path == right.path
    });
    pins
}

fn make_pin(
    path: &str,
    object_kind: ObjectKind,
    object_id: u64,
    object_tag: Option<String>,
    mounts: &[MountEntry],
    stamp: &LifecycleStamp,
) -> PinRecord {
    PinRecord {
        path: path.to_string(),
        object_kind,
        object_id,
        object_tag,
        mount_fstype: mount_type_for(Path::new(path), mounts)
            .unwrap_or("unknown")
            .to_string(),
        file_identity: file_identity(path),
        stamp: stamp.clone(),
    }
}

fn push_error(snapshot: &mut BpfSnapshot, error: LifecycleError) {
    let duplicate = snapshot.errors.iter().any(|existing| {
        existing.collector == error.collector && existing.message == error.message
    });
    if !duplicate {
        snapshot.errors.push(error);
    }
}

fn verify_pin_identities(pins: &[PinRecord]) -> Vec<String> {
    let mut conflicts = Vec::new();
    for pin in pins {
        let current = file_identity(&pin.path);
        if current != pin.file_identity {
            conflicts.push(format!(
                "pin path={} changed filesystem identity during the transaction",
                pin.path
            ));
        }
    }
    conflicts
}

fn file_identity(path: &str) -> Option<FileIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(path).ok()?;
        Some(FileIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: metadata.size(),
            mtime_ns: metadata
                .mtime()
                .saturating_mul(1_000_000_000)
                .saturating_add(metadata.mtime_nsec()),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

fn program_fingerprints(programs: &[ProgramRecord]) -> BTreeMap<u64, String> {
    programs
        .iter()
        .map(|program| {
            (
                program.id,
                format!(
                    "name={};tag={};type={};attach_type={};pinned={:?};pinned_flag={}",
                    program.name,
                    program.tag,
                    program.prog_type,
                    program.attach_type,
                    program.pinned,
                    program.pinned_flag
                ),
            )
        })
        .collect()
}

fn map_fingerprints(maps: &[MapRecord]) -> BTreeMap<u64, String> {
    maps.iter()
        .map(|map| {
            (
                map.id,
                format!(
                    "name={};type={};pinned={:?};pinned_flag={};verdict_prog_id={:?};verdict_prog_tag={:?}",
                    map.name,
                    map.map_type,
                    map.pinned,
                    map.pinned_flag,
                    map.verdict_prog_id,
                    map.verdict_prog_tag
                ),
            )
        })
        .collect()
}

fn link_fingerprints(links: &[LinkRecord]) -> BTreeMap<u64, String> {
    links
        .iter()
        .map(|link| {
            (
                link.id,
                format!(
                    "prog_id={:?};prog_tag={:?};type={};attach_type={};target={};pinned={:?};pinned_flag={}",
                    link.prog_id,
                    link.prog_tag,
                    link.link_type,
                    link.attach_type,
                    link.target,
                    link.pinned,
                    link.pinned_flag
                ),
            )
        })
        .collect()
}

fn compare_identity_sets(
    kind: ObjectKind,
    first: &BTreeMap<u64, String>,
    second: &BTreeMap<u64, String>,
    conflicts: &mut Vec<String>,
    cross_generation: &mut usize,
) {
    let ids = first
        .keys()
        .chain(second.keys())
        .copied()
        .collect::<BTreeSet<_>>();

    for id in ids {
        match (first.get(&id), second.get(&id)) {
            (Some(left), Some(right)) if left != right => {
                conflicts.push(format!(
                    "{} id={} changed identity between collectors ({} != {})",
                    kind.label(),
                    id,
                    left,
                    right
                ));
                *cross_generation = (*cross_generation).saturating_add(1);
            }
            (Some(_), None) => {
                conflicts.push(format!(
                    "{} id={} disappeared between collectors",
                    kind.label(),
                    id
                ));
                *cross_generation = (*cross_generation).saturating_add(1);
            }
            (None, Some(_)) => {
                conflicts.push(format!(
                    "{} id={} appeared between collectors",
                    kind.label(),
                    id
                ));
                *cross_generation = (*cross_generation).saturating_add(1);
            }
            _ => {}
        }
    }
}

fn validate_identities(snapshot: &BpfSnapshot) -> (Vec<String>, usize) {
    let mut conflicts = Vec::new();
    let mut cross_generation = 0usize;

    let mut program_identities: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    for program in &snapshot.programs {
        program_identities
            .entry(program.id)
            .or_default()
            .insert(format!(
                "{}:{}:{}:{}",
                program.name, program.tag, program.prog_type, program.attach_type
            ));
    }
    for (id, identities) in program_identities {
        if identities.len() > 1 {
            conflicts.push(format!(
                "program id={} was reused with different identities within one generation: {:?}",
                id, identities
            ));
            cross_generation = cross_generation.saturating_add(1);
        }
    }

    let mut map_identities: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    for map in &snapshot.maps {
        map_identities
            .entry(map.id)
            .or_default()
            .insert(format!("{}:{}", map.name, map.map_type));
    }
    for (id, identities) in map_identities {
        if identities.len() > 1 {
            conflicts.push(format!(
                "map id={} was reused with different identities within one generation: {:?}",
                id, identities
            ));
            cross_generation = cross_generation.saturating_add(1);
        }
    }

    let mut link_identities: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    for link in &snapshot.links {
        link_identities
            .entry(link.id)
            .or_default()
            .insert(format!(
                "{:?}:{}:{}",
                link.prog_id, link.link_type, link.attach_type
            ));
    }
    for (id, identities) in link_identities {
        if identities.len() > 1 {
            conflicts.push(format!(
                "link id={} was reused with different identities within one generation: {:?}",
                id, identities
            ));
            cross_generation = cross_generation.saturating_add(1);
        }
    }

    // A link must point at the same program identity observed in this
    // generation.  Missing programs and tag mismatches are the signature of a
    // detach + id-reuse race, so they invalidate the generation.
    if !snapshot.has_error(CollectorKind::Programs) {
        let programs_available = !snapshot.programs.is_empty();
        for link in &snapshot.links {
            let Some(program_id) = link.prog_id else {
                continue;
            };
            match snapshot.program(program_id) {
                None => {
                    // If the program collector returned no programs at all,
                    // there is no program identity to mix with; callers can
                    // still publish the link with an unknown tag.  Once a
                    // program set exists, a missing referenced id is a real
                    // generation conflict.
                    if programs_available || link.prog_tag.is_some() {
                        conflicts.push(format!(
                            "link id={} references program id={} missing from the same generation",
                            link.id, program_id
                        ));
                        cross_generation = cross_generation.saturating_add(1);
                    }
                }
                Some(program) => {
                    if let Some(tag) = link.prog_tag.as_deref() {
                        if !tag.is_empty() && tag != "unknown" && tag != program.tag.as_str() {
                            conflicts.push(format!(
                                "link id={} references program id={} tag={} but program tag={}",
                                link.id, program_id, tag, program.tag
                            ));
                            cross_generation = cross_generation.saturating_add(1);
                        }
                    }
                }
            }
        }

        for map in &snapshot.maps {
            let Some(program_id) = map.verdict_prog_id else {
                continue;
            };
            match snapshot.program(program_id) {
                None => {
                    if programs_available || map.verdict_prog_tag.is_some() {
                        conflicts.push(format!(
                            "map id={} references verdict program id={} missing from the same generation",
                            map.id, program_id
                        ));
                        cross_generation = cross_generation.saturating_add(1);
                    }
                }
                Some(program) => {
                    if let Some(tag) = map.verdict_prog_tag.as_deref() {
                        if !tag.is_empty() && tag != "unknown" && tag != program.tag.as_str() {
                            conflicts.push(format!(
                                "map id={} references verdict program id={} tag={} but program tag={}",
                                map.id, program_id, tag, program.tag
                            ));
                            cross_generation = cross_generation.saturating_add(1);
                        }
                    }
                }
            }
        }
    }

    (conflicts, cross_generation)
}

struct MountEntry {
    mount_point: PathBuf,
    fstype: String,
}

fn parse_mountinfo() -> io::Result<Vec<MountEntry>> {
    let content = fs::read_to_string("/proc/self/mountinfo")?;
    let mut mounts = Vec::new();

    for line in content.lines() {
        if let Some((pre, post)) = line.split_once(" - ") {
            let mut post_fields = post.split_whitespace();
            let fstype = post_fields.next().unwrap_or("").to_string();

            let fields: Vec<&str> = pre.split_whitespace().collect();
            if fields.len() < 5 {
                continue;
            }
            let mount_point = decode_mount_field(fields[4]);
            mounts.push(MountEntry {
                mount_point: PathBuf::from(mount_point),
                fstype,
            });
        }
    }

    Ok(mounts)
}

fn decode_mount_field(field: &str) -> String {
    let mut result = String::new();
    let mut chars = field.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '\\' {
            if let (Some(a), Some(b), Some(c)) = (chars.next(), chars.next(), chars.next()) {
                let code = [a, b, c];
                let decoded = match &code {
                    ['0', '4', '0'] => ' ',
                    ['0', '1', '1'] => '\t',
                    ['0', '1', '2'] => '\n',
                    ['0', '1', '3'] => '\r',
                    ['0', '1', '4'] => 0x0c as char,
                    ['0', '1', '5'] => 0x0b as char,
                    ['0', '1', '6'] => 0x0e as char,
                    ['0', '1', '7'] => 0x0f as char,
                    ['0', '1', '0'] => 0x08 as char,
                    ['1', '3', '4'] => '\\',
                    _ => {
                        result.push('\\');
                        result.push(a);
                        result.push(b);
                        result.push(c);
                        continue;
                    }
                };
                result.push(decoded);
            }
        } else {
            result.push(character);
        }
    }
    result
}

fn mount_type_for<'a>(path: &Path, mounts: &'a [MountEntry]) -> Option<&'a str> {
    for entry in mounts {
        if path.starts_with(&entry.mount_point) {
            return Some(entry.fstype.as_str());
        }
    }
    None
}

/// Map a collector failure onto the wording used by the original scanner so
/// the public error surface does not change when the shared transaction is in
/// use.
pub fn scanner_error(
    snapshot: &BpfSnapshot,
    collector: CollectorKind,
    not_available: &str,
) -> Option<String> {
    snapshot.error_for(collector).map(|error| {
        if error.kind == FailureKind::NotAvailable {
            not_available.to_string()
        } else {
            error.message.clone()
        }
    })
}

/// Error text used when a generation could not be made internally consistent.
pub fn conflict_error(snapshot: &BpfSnapshot) -> Option<String> {
    // Re-check the identities even when the snapshot was constructed by a
    // caller rather than by the transaction, so a link/program/pin mismatch
    // can never be published as a finding.
    let (derived, _) = validate_identities(snapshot);
    let mut all = snapshot.conflicts.iter().cloned().collect::<BTreeSet<_>>();
    all.extend(derived);

    if all.is_empty() {
        None
    } else {
        Some(format!(
            "bpf lifecycle generation unstable: {}",
            all.into_iter().collect::<Vec<_>>().join(", ")
        ))
    }
}

/// True when every record in `snapshot` belongs to `stamp`.  Scanners use this
/// before publishing object identities; a false result is a cross-generation
/// observation, never a finding.
pub fn records_match_stamp(snapshot: &BpfSnapshot, stamp: &LifecycleStamp) -> bool {
    snapshot.stamp.same_generation(stamp)
        && snapshot
            .programs
            .iter()
            .all(|program| program.stamp.same_generation(stamp))
        && snapshot.maps.iter().all(|map| map.stamp.same_generation(stamp))
        && snapshot
            .links
            .iter()
            .all(|link| link.stamp.same_generation(stamp))
        && snapshot.pins.iter().all(|pin| pin.stamp.same_generation(stamp))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamp() -> LifecycleStamp {
        LifecycleStamp {
            boot_id: "boot-test".to_string(),
            generation: 1,
            attempt: 1,
            started_unix_ns: 10,
            pid: 42,
        }
    }

    fn program(id: u64, tag: &str, pinned: Vec<String>) -> ProgramRecord {
        ProgramRecord {
            id,
            name: "probe".to_string(),
            tag: tag.to_string(),
            prog_type: "tracing".to_string(),
            attach_type: "kprobe".to_string(),
            owner_pids: Vec::new(),
            pinned_flag: !pinned.is_empty(),
            pinned,
            stamp: stamp(),
        }
    }

    fn link(id: u64, prog_id: u64, prog_tag: &str) -> LinkRecord {
        LinkRecord {
            id,
            prog_id: Some(prog_id),
            prog_tag: Some(prog_tag.to_string()),
            link_type: "kprobe".to_string(),
            attach_type: "kprobe".to_string(),
            target: "vfs_read".to_string(),
            pinned: Vec::new(),
            pinned_flag: false,
            stamp: stamp(),
        }
    }

    #[test]
    fn ownerless_program_is_preserved() {
        let mut snapshot = BpfSnapshot::new(stamp());
        snapshot.programs.push(program(7, "tag-a", Vec::new()));
        let ownerless = snapshot.ownerless_programs().collect::<Vec<_>>();
        assert_eq!(ownerless.len(), 1);
        assert_eq!(ownerless[0].id, 7);
    }

    #[test]
    fn detached_and_reused_program_id_is_a_cross_generation_conflict() {
        let mut snapshot = BpfSnapshot::new(stamp());
        snapshot.programs.push(program(9, "new-tag", Vec::new()));
        snapshot.links.push(link(3, 9, "old-tag"));

        let (conflicts, cross_generation) = validate_identities(&snapshot);
        assert!(!conflicts.is_empty());
        assert!(cross_generation >= 1);
        assert!(conflicts.iter().any(|conflict| conflict.contains("tag")));
    }

    #[test]
    fn repin_between_collectors_is_detected_by_the_identity_fence() {
        let first = program(4, "tag-a", Vec::new());
        let second = program(
            4,
            "tag-a",
            vec!["/sys/fs/bpf/repinned".to_string()],
        );

        let mut conflicts = Vec::new();
        let mut cross_generation = 0;
        compare_identity_sets(
            ObjectKind::Program,
            &program_fingerprints(&[first]),
            &program_fingerprints(&[second]),
            &mut conflicts,
            &mut cross_generation,
        );

        assert_eq!(cross_generation, 1);
        assert!(conflicts[0].contains("changed identity"));
    }

    #[test]
    fn legal_bpffs_pin_keeps_its_identity() {
        let pin = PinRecord {
            path: "/sys/fs/bpf/prog".to_string(),
            object_kind: ObjectKind::Program,
            object_id: 1,
            object_tag: Some("tag-a".to_string()),
            mount_fstype: "bpf".to_string(),
            file_identity: None,
            stamp: stamp(),
        };
        assert!(pin.on_bpffs());
        assert!(pin.stamp.same_generation(&stamp()));
    }

    #[test]
    fn records_from_another_generation_do_not_match() {
        let snapshot = BpfSnapshot::new(stamp());
        let mut other = stamp();
        other.generation = 2;
        assert!(records_match_stamp(&snapshot, &stamp()));
        assert!(!records_match_stamp(&snapshot, &other));
    }
}
