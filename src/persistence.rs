//! One host persistence observation for the file-backed config scanners.
//!
//! SSH authorized keys, sudoers (including its `#include`/`#includedir`
//! chain), PAM/NSS configuration and systemd units used to be read by four
//! independent scanners at four different moments.  A sudoers include file
//! could be replaced between two of those reads, so an old SSH foothold and a
//! new PAM module could be published as one "host persistence" story even
//! though they never existed on the host at the same time.
//!
//! This module makes the round explicit:
//!
//! * one [`ObservationStamp`] is created before any scanner runs,
//! * every source file, symlink, directory and include edge is captured once
//!   into a [`Snapshot`] that is stamped with that generation,
//! * the include closure is resolved from that same snapshot, so an include
//!   can never be read from a different generation than the file that names
//!   it,
//! * an identity fence re-reads the whole file set; if a file, symlink,
//!   directory or include edge changed, the entire generation is discarded and
//!   retried from an empty snapshot - evidence from the failed generation is
//!   never merged with the retry,
//! * a symlink is resolved once and both the link itself and its target are
//!   fenced, so re-pointing a link cannot splice two generations together,
//! * an unreadable include is kept as an explicit error on its own generation
//!   instead of silently falling back to an older copy,
//! * scanners and the final `[Persistence evidence]` block render findings with
//!   the same generation label, source file and include chain.
//!
//! Legitimate SSH/sudo/PAM/systemd configuration, masked units, permission
//! errors and genuinely empty results remain observations instead of being
//! collapsed into a synthetic clean result.

use crate::ScanOutcome;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{self, Metadata};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// How many complete generations may be captured before the observation is
/// declared unstable.  Every retry starts from an empty snapshot.
pub const MAX_GENERATION_ATTEMPTS: u32 = 4;
/// Maximum number of symlink hops followed for one logical path.
pub const MAX_SYMLINK_HOPS: usize = 40;
/// Maximum include nesting depth tracked in one chain.
pub const MAX_INCLUDE_DEPTH: usize = 32;
/// Optional test/analysis root.  Displayed paths always stay logical (`/etc/...`).
pub const ROOT_ENV: &str = "GHOSTSCAN_ROOT";

pub const PASSWD: &str = "/etc/passwd";
pub const SUDOERS_ROOT: &str = "/etc/sudoers";
pub const SUDOERS_DIR: &str = "/etc/sudoers.d";
pub const PAM_DIR: &str = "/etc/pam.d";
pub const NSSWITCH: &str = "/etc/nsswitch.conf";
pub const UNIT_DIRS: [&str; 3] = [
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
];
/// Drop-in directories are consulted in systemd precedence order.
pub const DROPIN_ROOTS: [&str; 4] = [
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
];
pub const SYSTEM_LIB_DIRS: [&str; 4] = ["/lib", "/lib64", "/usr/lib", "/usr/lib64"];

/// File-backed sources that take part in the persistence observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PersistenceSource {
    Ssh,
    Sudo,
    Pam,
    Nss,
    Systemd,
}

impl PersistenceSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Sudo => "sudo",
            Self::Pam => "pam",
            Self::Nss => "nss",
            Self::Systemd => "systemd",
        }
    }

    fn all() -> [Self; 5] {
        [Self::Ssh, Self::Sudo, Self::Pam, Self::Nss, Self::Systemd]
    }
}

/// Identity shared by every record and finding in one observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationStamp {
    /// `/proc/sys/kernel/random/boot_id`, or `unknown` when unreadable.
    pub boot_id: String,
    /// Process-local monotonic generation number.  A retry is a new generation.
    pub generation: u64,
    /// Attempt within the current scan round (starts at one).
    pub attempt: u32,
    /// Wall clock start of this generation, in nanoseconds since the epoch.
    pub started_unix_ns: u128,
    /// PID of the ghostscan process that observed the files.
    pub pid: u32,
}

impl ObservationStamp {
    fn start(generation: u64, attempt: u32) -> Self {
        let started_unix_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|value| value.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        Self {
            boot_id,
            generation,
            attempt,
            started_unix_ns,
            pid: std::process::id(),
        }
    }

    /// Stable label printed by every scanner finding and the final report.
    pub fn label(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.boot_id, self.generation, self.started_unix_ns, self.pid
        )
    }

    /// Two stamps belong to the same generation only when boot and round agree.
    pub fn same_generation(&self, other: &Self) -> bool {
        self.boot_id == other.boot_id && self.generation == other.generation
    }
}

/// Stable identity of one regular file or symlink target.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileIdentity {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub size: u64,
    pub mtime: i64,
    pub mtime_nsec: i64,
}

impl FileIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            mode: metadata.mode(),
            size: metadata.size(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
        }
    }
}

/// One file (or directory) as it was observed in this generation.
#[derive(Clone, Debug, Default)]
pub struct FileRecord {
    /// Logical path, always rooted at `/`, independent of `GHOSTSCAN_ROOT`.
    pub path: PathBuf,
    /// Logical path after all symlinks were resolved.
    pub resolved: PathBuf,
    /// Raw target of the final symlink, when the requested path was a link.
    pub symlink_target: Option<PathBuf>,
    /// Identity of the resolved regular file.
    pub identity: Option<FileIdentity>,
    /// Identity of the symlink inode itself, when applicable.
    pub link_identity: Option<FileIdentity>,
    /// SHA-256 of the bytes read from the resolved file.
    pub digest: Option<String>,
    /// UTF-8 lossy content of the resolved file.
    pub content: Option<String>,
    pub is_dir: bool,
    pub missing: bool,
    /// Permission and I/O errors.  A missing optional file is not an error.
    pub errors: Vec<String>,
}

/// One item of final persistence evidence.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PersistenceFinding {
    pub source: &'static str,
    pub file: PathBuf,
    pub include_chain: Vec<PathBuf>,
    /// Legacy scanner detail (`user=...`, `entry=...`, ...).
    pub detail: String,
}

impl PersistenceFinding {
    /// Render a finding with the traceability fields acceptance compares.
    pub fn render(&self, generation: &str) -> String {
        format!(
            "{}, source={}, source_file={}, include_chain={}, generation={}",
            self.detail,
            self.source,
            self.file.display(),
            render_chain(&self.include_chain),
            generation
        )
    }
}

/// Per-source slice of the shared observation.
#[derive(Clone, Debug, Default)]
pub struct SourceObservation {
    pub stamp: Option<ObservationStamp>,
    pub origins: Vec<String>,
    pub include_chains: Vec<String>,
    pub findings: Vec<PersistenceFinding>,
    pub errors: Vec<String>,
    pub limitations: Vec<String>,
}

impl SourceObservation {
    pub fn status(&self) -> &'static str {
        if self.errors.is_empty() {
            "COMPLETE"
        } else {
            "PARTIAL"
        }
    }
}

/// Overall snapshot verdict.  `Partial` means at least one file or include was
/// unreadable in this generation; it never means "fall back to a previous one".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationStatus {
    Complete,
    Partial,
    Failed,
}

/// Public aliases matching the "one host observation" wording: the snapshot is
/// the host observation and the stamp is its generation identity.
pub type HostObservation = Snapshot;
pub type ObservationGeneration = ObservationStamp;

impl ObservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "COMPLETE",
            Self::Partial => "PARTIAL",
            Self::Failed => "FAILED",
        }
    }
}

/// The single snapshot every persistence scanner and the final report read.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub stamp: ObservationStamp,
    pub attempts: u32,
    pub status: ObservationStatus,
    pub files: BTreeMap<PathBuf, FileRecord>,
    pub dirs: BTreeMap<PathBuf, Vec<PathBuf>>,
    pub chains: BTreeMap<PathBuf, Vec<Vec<PathBuf>>>,
    pub include_errors: Vec<String>,
    pub generation_conflicts: Vec<String>,
    pub sources: BTreeMap<PersistenceSource, SourceObservation>,
    pub failure: Option<String>,
}

impl Snapshot {
    pub fn generation_label(&self) -> String {
        self.stamp.label()
    }

    pub fn same_generation(&self) -> bool {
        if self.status == ObservationStatus::Failed {
            return false;
        }
        self.sources.values().all(|source| {
            source
                .stamp
                .as_ref()
                .map(|stamp| stamp.same_generation(&self.stamp))
                .unwrap_or(true)
        })
    }

    pub fn file(&self, path: &Path) -> Option<&FileRecord> {
        self.files.get(path)
    }

    pub fn content(&self, path: &Path) -> Option<&str> {
        self.files.get(path).and_then(|record| record.content.as_deref())
    }

    pub fn entries(&self, path: &Path) -> Option<&Vec<PathBuf>> {
        self.dirs.get(path)
    }

    /// Deterministic final report lines.  The last line is the explicit
    /// `persistence_observation=COMPLETE|PARTIAL|FAILED` verdict.
    pub fn report_lines(&self) -> Vec<String> {
        let generation = self.generation_label();
        let mut lines = Vec::new();
        lines.push(format!("boot_id={}", self.stamp.boot_id));
        lines.push(format!("generation={generation}"));
        lines.push(format!("attempts={}", self.attempts));
        lines.push(format!("same_generation={}", self.same_generation()));
        lines.push(format!(
            "snapshot_files={} snapshot_dirs={} include_errors={}",
            self.files.len(),
            self.dirs.len(),
            self.include_errors.len()
        ));

        for source in PersistenceSource::all() {
            match self.sources.get(&source) {
                Some(observation) => {
                    lines.push(format!(
                        "source={} status={} origins={} include_chains={} findings={} errors={}",
                        source.label(),
                        observation.status(),
                        observation.origins.len(),
                        observation.include_chains.len(),
                        observation.findings.len(),
                        observation.errors.len()
                    ));
                    for origin in &observation.origins {
                        lines.push(format!("source_file={} path={origin}", source.label()));
                    }
                    for chain in &observation.include_chains {
                        lines.push(format!("source_chain={} chain={chain}", source.label()));
                    }
                }
                None => lines.push(format!("source={} status=MISSING", source.label())),
            }
        }

        for error in &self.include_errors {
            lines.push(format!("include_error={error}"));
        }
        for conflict in &self.generation_conflicts {
            lines.push(format!("generation_conflict={conflict}"));
        }
        for source in PersistenceSource::all() {
            if let Some(observation) = self.sources.get(&source) {
                for error in &observation.errors {
                    lines.push(format!("source_error={} {}", source.label(), error));
                }
                for limitation in &observation.limitations {
                    lines.push(format!("source_limitation={} {}", source.label(), limitation));
                }
            }
        }

        let mut findings: Vec<&PersistenceFinding> = self
            .sources
            .values()
            .flat_map(|observation| observation.findings.iter())
            .collect();
        findings.sort();
        for finding in findings {
            lines.push(format!("persistence_finding={}", finding.render(&generation)));
        }

        if let Some(failure) = &self.failure {
            lines.push(format!("error={failure}"));
        }
        lines.push(format!("host_observation={}", self.status.as_str()));
        lines.push(format!("persistence_observation={}", self.status.as_str()));
        lines
    }
}

/// Process-wide observation.  `main` calls [`PersistenceTransaction::begin_scan`]
/// before the scanner loop; standalone scanner calls start it lazily once.
pub struct PersistenceTransaction {
    current: Mutex<Option<Arc<Snapshot>>>,
    initialization: Mutex<()>,
    next_generation: AtomicU64,
}

impl PersistenceTransaction {
    pub const fn new() -> Self {
        Self {
            current: Mutex::new(None),
            initialization: Mutex::new(()),
            next_generation: AtomicU64::new(0),
        }
    }

    /// Capture one generation.  Failed fenced attempts are discarded in full;
    /// the published snapshot only contains the last complete attempt.
    pub fn begin_scan(&self) -> Arc<Snapshot> {
        let mut last_failure: Option<Snapshot> = None;
        for attempt in 1..=MAX_GENERATION_ATTEMPTS {
            let generation = self.next_generation.fetch_add(1, Ordering::SeqCst) + 1;
            let stamp = ObservationStamp::start(generation, attempt);
            match capture_generation(&stamp) {
                Ok(mut snapshot) => {
                    snapshot.attempts = attempt;
                    let snapshot = Arc::new(snapshot);
                    {
                        let mut guard = self.current.lock().expect("persistence mutex poisoned");
                        *guard = Some(snapshot.clone());
                    }
                    return snapshot;
                }
                Err(conflicts) => {
                    last_failure = Some(failed_snapshot(stamp, attempt, conflicts));
                }
            }
        }

        let snapshot = Arc::new(last_failure.unwrap_or_else(|| {
            failed_snapshot(
                ObservationStamp::start(1, 1),
                1,
                vec!["persistence observation did not start".to_string()],
            )
        }));
        {
            let mut guard = self.current.lock().expect("persistence mutex poisoned");
            *guard = Some(snapshot.clone());
        }
        snapshot
    }

    /// Return the observation for this round, capturing it if `main` has not
    /// done so yet.  There is deliberately no cross-round cache.
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.ensure_started()
    }

    pub fn ensure_started(&self) -> Arc<Snapshot> {
        {
            let guard = self.current.lock().expect("persistence mutex poisoned");
            if let Some(snapshot) = guard.as_ref() {
                return snapshot.clone();
            }
        }
        let _initializing = self
            .initialization
            .lock()
            .expect("persistence initialization mutex poisoned");
        {
            let guard = self.current.lock().expect("persistence mutex poisoned");
            if let Some(snapshot) = guard.as_ref() {
                return snapshot.clone();
            }
        }
        self.begin_scan()
    }
}

impl Default for PersistenceTransaction {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared process-wide transaction.
pub static PERSISTENCE: PersistenceTransaction = PersistenceTransaction::new();

/// Convenience accessor used by tests and external callers.
pub fn transaction() -> &'static PersistenceTransaction {
    &PERSISTENCE
}

/// Capture a fresh generation for a new scan round.
pub fn begin_scan() -> Arc<Snapshot> {
    PERSISTENCE.begin_scan()
}

/// Read the generation shared by the current scan round.
pub fn current_snapshot() -> Arc<Snapshot> {
    PERSISTENCE.snapshot()
}

/// Render an include chain for reports.  `a -> b -> c`.
pub fn render_chain(chain: &[PathBuf]) -> String {
    if chain.is_empty() {
        return "<empty>".to_string();
    }
    chain
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join("->")
}

#[derive(Clone, Debug)]
struct IncludeError {
    source: Option<PersistenceSource>,
    message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceTag {
    None,
    Sudo,
    Pam,
    Systemd,
    Ssh,
    Nss,
}

fn tag_source(tag: SourceTag) -> Option<PersistenceSource> {
    match tag {
        SourceTag::Sudo => Some(PersistenceSource::Sudo),
        SourceTag::Pam => Some(PersistenceSource::Pam),
        SourceTag::Systemd => Some(PersistenceSource::Systemd),
        SourceTag::Ssh => Some(PersistenceSource::Ssh),
        SourceTag::Nss => Some(PersistenceSource::Nss),
        SourceTag::None => None,
    }
}

#[derive(Clone, Debug, Default)]
struct CapturedData {
    files: BTreeMap<PathBuf, FileRecord>,
    dirs: BTreeMap<PathBuf, Vec<PathBuf>>,
    chains: BTreeMap<PathBuf, Vec<Vec<PathBuf>>>,
    include_errors: Vec<IncludeError>,
    sudo_files: BTreeSet<PathBuf>,
    pam_files: BTreeSet<PathBuf>,
    systemd_files: BTreeSet<PathBuf>,
    ssh_files: BTreeSet<PathBuf>,
    nss_files: BTreeSet<PathBuf>,
}

impl CapturedData {
    fn record(&self, path: &Path) -> Option<&FileRecord> {
        self.files.get(path)
    }

    fn content(&self, path: &Path) -> Option<&str> {
        self.files.get(path).and_then(|record| record.content.as_deref())
    }

    fn fingerprint(&self) -> String {
        let mut out = String::new();
        for (path, record) in &self.files {
            let _ = writeln!(
                out,
                "file={}|resolved={}|missing={}|dir={}|digest={}|link={}|errors={}",
                path.display(),
                record.resolved.display(),
                record.missing,
                record.is_dir,
                record.digest.as_deref().unwrap_or(""),
                record
                    .symlink_target
                    .as_ref()
                    .map(|target| target.display().to_string())
                    .unwrap_or_default(),
                record.errors.join(";")
            );
            if let Some(identity) = &record.identity {
                let _ = writeln!(
                    out,
                    "identity={}:{}:{}:{}:{}:{}",
                    identity.dev,
                    identity.ino,
                    identity.mode,
                    identity.size,
                    identity.mtime,
                    identity.mtime_nsec
                );
            }
            if let Some(identity) = &record.link_identity {
                let _ = writeln!(
                    out,
                    "link_identity={}:{}:{}:{}:{}:{}",
                    identity.dev,
                    identity.ino,
                    identity.mode,
                    identity.size,
                    identity.mtime,
                    identity.mtime_nsec
                );
            }
        }
        for (path, entries) in &self.dirs {
            let _ = writeln!(
                out,
                "dir={}|{}",
                path.display(),
                entries
                    .iter()
                    .map(|entry| entry.display().to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }
        for error in &self.include_errors {
            let _ = writeln!(
                out,
                "include_error={:?}|{}",
                error.source, error.message
            );
        }
        out
    }
}

struct Capture {
    root: PathBuf,
    files: BTreeMap<PathBuf, FileRecord>,
    dirs: BTreeMap<PathBuf, Vec<PathBuf>>,
    chains: BTreeMap<PathBuf, Vec<Vec<PathBuf>>>,
    include_errors: Vec<IncludeError>,
    sudo_files: BTreeSet<PathBuf>,
    pam_files: BTreeSet<PathBuf>,
    systemd_files: BTreeSet<PathBuf>,
    systemd_units: BTreeSet<PathBuf>,
    ssh_files: BTreeSet<PathBuf>,
    nss_files: BTreeSet<PathBuf>,
    processed_passwd: bool,
}

impl Capture {
    fn new() -> Self {
        Self {
            root: host_root(),
            files: BTreeMap::new(),
            dirs: BTreeMap::new(),
            chains: BTreeMap::new(),
            include_errors: Vec::new(),
            sudo_files: BTreeSet::new(),
            pam_files: BTreeSet::new(),
            systemd_files: BTreeSet::new(),
            systemd_units: BTreeSet::new(),
            ssh_files: BTreeSet::new(),
            nss_files: BTreeSet::new(),
            processed_passwd: false,
        }
    }

    fn host_path(&self, logical: &Path) -> PathBuf {
        let relative = logical.strip_prefix(Path::new("/")).unwrap_or(logical);
        self.root.join(relative)
    }

    fn seed(&mut self) {
        self.add_file(
            Path::new(PASSWD),
            vec![PathBuf::from(PASSWD)],
            SourceTag::None,
        );
        self.add_file(
            Path::new(SUDOERS_ROOT),
            vec![PathBuf::from(SUDOERS_ROOT)],
            SourceTag::Sudo,
        );
        self.add_file(
            Path::new(NSSWITCH),
            vec![PathBuf::from(NSSWITCH)],
            SourceTag::Nss,
        );

        let pam_entries = self.list_entries(Path::new(PAM_DIR), Some(PersistenceSource::Pam));
        for entry in pam_entries {
            self.add_file(&entry, vec![entry.clone()], SourceTag::Pam);
        }

        for dir in UNIT_DIRS {
            let entries = self.list_entries(Path::new(dir), Some(PersistenceSource::Systemd));
            for entry in entries {
                if is_service_file(&entry) {
                    self.systemd_units.insert(entry.clone());
                    self.add_file(&entry, vec![entry.clone()], SourceTag::Systemd);
                }
            }
        }
    }

    fn expand(&mut self) {
        for _ in 0..64 {
            let before = self.files.len();
            self.expand_closure();
            self.seed_sudoers_dir_fallback();
            if self.files.len() == before {
                break;
            }
        }
        self.expand_systemd_exec_paths();
    }

    fn expand_closure(&mut self) {
        let mut processed_sudo = BTreeSet::new();
        let mut processed_pam = BTreeSet::new();
        let mut processed_systemd = BTreeSet::new();

        for _ in 0..512 {
            let mut progressed = false;

            if !self.processed_passwd {
                self.processed_passwd = true;
                if self.expand_ssh() {
                    progressed = true;
                }
            }

            for file in self.sudo_files.clone() {
                if !processed_sudo.insert(file.clone()) {
                    continue;
                }
                if self.expand_sudo_includes(&file) {
                    progressed = true;
                }
            }

            for file in self.pam_files.clone() {
                if !processed_pam.insert(file.clone()) {
                    continue;
                }
                if self.expand_pam_includes(&file) {
                    progressed = true;
                }
            }

            for unit in self.systemd_units.clone() {
                if !processed_systemd.insert(unit.clone()) {
                    continue;
                }
                if self.expand_systemd_dropins(&unit) {
                    progressed = true;
                }
            }

            if !progressed {
                break;
            }
        }
    }

    fn finish(self) -> CapturedData {
        CapturedData {
            files: self.files,
            dirs: self.dirs,
            chains: self.chains,
            include_errors: self.include_errors,
            sudo_files: self.sudo_files,
            pam_files: self.pam_files,
            systemd_files: self.systemd_files,
            ssh_files: self.ssh_files,
            nss_files: self.nss_files,
        }
    }

    fn expand_ssh(&mut self) -> bool {
        let Some(content) = self.content_owned(Path::new(PASSWD)) else {
            return false;
        };
        let mut changed = false;
        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 6 {
                continue;
            }
            let home = parts[5];
            if !home.starts_with('/') {
                continue;
            }
            let auth = normalize(&Path::new(home).join(".ssh").join("authorized_keys"));
            if self.add_file(&auth, vec![auth.clone()], SourceTag::Ssh) {
                changed = true;
            }
        }
        changed
    }

    fn expand_sudo_includes(&mut self, file: &Path) -> bool {
        let Some(content) = self.content_owned(file) else {
            return false;
        };
        let base = file.parent().unwrap_or(Path::new("/")).to_path_buf();
        let directives = sudo_includes(&content);
        let chains = self.chains.get(file).cloned().unwrap_or_default();
        let mut changed = false;

        for directive in directives {
            let target = if directive.path.is_absolute() {
                normalize(&directive.path)
            } else {
                normalize(&base.join(&directive.path))
            };
            for chain in &chains {
                if chain.len() >= MAX_INCLUDE_DEPTH {
                    self.include_errors.push(IncludeError {
                        source: Some(PersistenceSource::Sudo),
                        message: format!(
                            "include_depth_limit={} chain={}",
                            MAX_INCLUDE_DEPTH,
                            render_chain(chain)
                        ),
                    });
                    continue;
                }
                if chain.iter().any(|entry| entry == &target) {
                    self.include_errors.push(IncludeError {
                        source: Some(PersistenceSource::Sudo),
                        message: format!(
                            "include_cycle={} chain={}",
                            target.display(),
                            render_chain(chain)
                        ),
                    });
                    continue;
                }
                let mut next = chain.clone();
                next.push(target.clone());
                if directive.directory {
                    let entries =
                        self.add_dir(&target, next.clone(), Some(PersistenceSource::Sudo));
                    for entry in entries {
                        if !sudoers_dir_accepts(&entry) {
                            continue;
                        }
                        let mut child_chain = next.clone();
                        child_chain.push(entry.clone());
                        if self.add_file(&entry, child_chain, SourceTag::Sudo) {
                            changed = true;
                        }
                    }
                } else if self.add_file(&target, next, SourceTag::Sudo) {
                    changed = true;
                }
            }
        }
        changed
    }

    fn expand_pam_includes(&mut self, file: &Path) -> bool {
        let Some(content) = self.content_owned(file) else {
            return false;
        };
        let base = file.parent().unwrap_or(Path::new("/")).to_path_buf();
        let chains = self.chains.get(file).cloned().unwrap_or_default();
        let mut changed = false;

        for include in pam_includes(&content) {
            let target = if include.is_absolute() {
                normalize(&include)
            } else {
                normalize(&base.join(&include))
            };
            for chain in &chains {
                if chain.len() >= MAX_INCLUDE_DEPTH {
                    self.include_errors.push(IncludeError {
                        source: Some(PersistenceSource::Pam),
                        message: format!(
                            "include_depth_limit={} chain={}",
                            MAX_INCLUDE_DEPTH,
                            render_chain(chain)
                        ),
                    });
                    continue;
                }
                if chain.iter().any(|entry| entry == &target) {
                    self.include_errors.push(IncludeError {
                        source: Some(PersistenceSource::Pam),
                        message: format!(
                            "include_cycle={} chain={}",
                            target.display(),
                            render_chain(chain)
                        ),
                    });
                    continue;
                }
                let mut next = chain.clone();
                next.push(target.clone());
                if self.add_file(&target, next, SourceTag::Pam) {
                    changed = true;
                }
            }
        }
        changed
    }

    fn expand_systemd_dropins(&mut self, unit: &Path) -> bool {
        let chains = self.chains.get(unit).cloned().unwrap_or_default();
        let mut changed = false;

        for chain in &chains {
            if chain.len() >= MAX_INCLUDE_DEPTH {
                self.include_errors.push(IncludeError {
                    source: Some(PersistenceSource::Systemd),
                    message: format!(
                        "include_depth_limit={} chain={}",
                        MAX_INCLUDE_DEPTH,
                        render_chain(chain)
                    ),
                });
                continue;
            }
            for dir in dropin_dirs(unit) {
                let entries =
                    self.add_dir(&dir, chain.clone(), Some(PersistenceSource::Systemd));
                for entry in entries {
                    if entry.extension().and_then(|value| value.to_str()) != Some("conf") {
                        continue;
                    }
                    let mut next = chain.clone();
                    next.push(entry.clone());
                    if self.add_file(&entry, next, SourceTag::Systemd) {
                        changed = true;
                    }
                }
            }
        }
        changed
    }

    /// Capture the executables referenced by effective systemd commands so the
    /// final `exec_missing`/`exec_in_tmp` verdict is decided against the same
    /// snapshot as the unit file.  This deliberately stats the executable
    /// only; it never reads binary content into the snapshot.
    fn expand_systemd_exec_paths(&mut self) {
        let units: Vec<PathBuf> = self.systemd_units.iter().cloned().collect();
        for unit in units {
            for command in effective_exec_commands(&self.files, &self.dirs, &unit) {
                if let Some(logical) = executable_logical(&command) {
                    self.add_probe(&logical, vec![unit.clone()]);
                }
            }
        }
    }

    fn seed_sudoers_dir_fallback(&mut self) {
        let dir = PathBuf::from(SUDOERS_DIR);
        if let Some(entries) = self.dirs.get(&dir).cloned() {
            for entry in entries {
                if !sudoers_dir_accepts(&entry) || self.files.contains_key(&entry) {
                    continue;
                }
                let chain = vec![dir.clone(), entry.clone()];
                self.add_file(&entry, chain, SourceTag::Sudo);
            }
            return;
        }
        let entries = self.list_entries(&dir, Some(PersistenceSource::Sudo));
        for entry in entries {
            if !sudoers_dir_accepts(&entry) || self.files.contains_key(&entry) {
                continue;
            }
            let chain = vec![dir.clone(), entry.clone()];
            self.add_file(&entry, chain, SourceTag::Sudo);
        }
    }

    fn add_file(&mut self, logical: &Path, chain: Vec<PathBuf>, tag: SourceTag) -> bool {
        let path = normalize(logical);
        self.add_chain(&path, chain);
        self.tag(&path, tag);
        if self.files.contains_key(&path) {
            return false;
        }
        let record = self.read_path(&path);
        let is_dir = record.is_dir;
        self.files.insert(path.clone(), record);
        if is_dir {
            self.list_entries(&path, tag_source(tag));
        }
        true
    }

    fn add_probe(&mut self, logical: &Path, chain: Vec<PathBuf>) -> bool {
        let path = normalize(logical);
        self.add_chain(&path, chain);
        if self.files.contains_key(&path) {
            return false;
        }
        let mut record = FileRecord {
            path: path.clone(),
            resolved: path.clone(),
            ..Default::default()
        };
        match self.resolve(&path) {
            Err(failure) => {
                record.resolved = failure.resolved;
                record.missing = failure.missing;
                record.symlink_target = failure.link_target;
                if !failure.missing {
                    record.errors.push(failure.message);
                }
            }
            Ok(resolved) => {
                record.resolved = resolved.logical;
                record.symlink_target = resolved.link_target;
                record.link_identity = resolved.link_identity;
                record.is_dir = resolved.metadata.is_dir();
                record.identity = Some(FileIdentity::from_metadata(&resolved.metadata));
            }
        }
        self.files.insert(path, record);
        true
    }

    fn add_dir(
        &mut self,
        logical: &Path,
        chain: Vec<PathBuf>,
        source: Option<PersistenceSource>,
    ) -> Vec<PathBuf> {
        let path = normalize(logical);
        self.add_chain(&path, chain);
        self.list_entries(&path, source)
    }

    fn add_chain(&mut self, path: &Path, chain: Vec<PathBuf>) {
        if chain.is_empty() {
            return;
        }
        let entry = self.chains.entry(path.to_path_buf()).or_default();
        if !entry.iter().any(|existing| existing == &chain) {
            entry.push(chain);
            entry.sort();
        }
    }

    fn tag(&mut self, path: &Path, tag: SourceTag) {
        let path = path.to_path_buf();
        match tag {
            SourceTag::Sudo => {
                self.sudo_files.insert(path);
            }
            SourceTag::Pam => {
                self.pam_files.insert(path);
            }
            SourceTag::Systemd => {
                self.systemd_files.insert(path);
            }
            SourceTag::Ssh => {
                self.ssh_files.insert(path);
            }
            SourceTag::Nss => {
                self.nss_files.insert(path);
            }
            SourceTag::None => {}
        }
    }

    fn list_entries(
        &mut self,
        logical: &Path,
        source: Option<PersistenceSource>,
    ) -> Vec<PathBuf> {
        let path = normalize(logical);
        if let Some(entries) = self.dirs.get(&path) {
            return entries.clone();
        }
        let real = self.host_path(&path);
        let entries = match fs::read_dir(&real) {
            Ok(read) => {
                let root = self.root.clone();
                let mut entries: Vec<PathBuf> = read
                    .flatten()
                    .map(|entry| logical_from_host(&root, &entry.path()))
                    .collect();
                entries.sort();
                entries.dedup();
                entries
            }
            Err(error) => {
                if error.kind() != std::io::ErrorKind::NotFound {
                    self.include_errors.push(IncludeError {
                        source,
                        message: format!("failed to read {}: {error}", path.display()),
                    });
                }
                Vec::new()
            }
        };
        self.dirs.insert(path, entries.clone());
        entries
    }

    fn content_owned(&self, path: &Path) -> Option<String> {
        self.files
            .get(path)
            .and_then(|record| record.content.clone())
    }

    fn read_path(&self, logical: &Path) -> FileRecord {
        let mut record = FileRecord {
            path: logical.to_path_buf(),
            resolved: logical.to_path_buf(),
            ..Default::default()
        };
        match self.resolve(logical) {
            Err(failure) => {
                record.resolved = failure.resolved;
                record.missing = failure.missing;
                record.symlink_target = failure.link_target;
                if !failure.missing {
                    record.errors.push(failure.message);
                }
                record
            }
            Ok(resolved) => {
                record.resolved = resolved.logical;
                record.symlink_target = resolved.link_target;
                record.link_identity = resolved.link_identity;
                record.identity = Some(FileIdentity::from_metadata(&resolved.metadata));
                if resolved.metadata.is_dir() {
                    record.is_dir = true;
                    return record;
                }
                match fs::read(&resolved.real) {
                    Ok(bytes) => {
                        record.digest = Some(hex_digest(&bytes));
                        match String::from_utf8(bytes) {
                            Ok(text) => record.content = Some(text),
                            Err(error) => record.errors.push(format!(
                                "failed to read {}: {error}",
                                logical.display()
                            )),
                        }
                    }
                    Err(error) => record.errors.push(format!(
                        "failed to read {}: {error}",
                        logical.display()
                    )),
                }
                record
            }
        }
    }

    fn resolve(&self, logical: &Path) -> Result<Resolved, ResolveFailure> {
        let mut current = normalize(logical);
        let mut link_target: Option<PathBuf> = None;
        let mut link_identity: Option<FileIdentity> = None;
        let mut seen = BTreeSet::new();
        let mut hops = 0usize;

        loop {
            if !seen.insert(current.clone()) {
                return Err(ResolveFailure {
                    missing: false,
                    message: format!("symlink cycle at {}", current.display()),
                    resolved: current,
                    link_target,
                });
            }
            hops += 1;
            if hops > MAX_SYMLINK_HOPS {
                return Err(ResolveFailure {
                    missing: false,
                    message: format!(
                        "too many symlink hops (>{MAX_SYMLINK_HOPS}) at {}",
                        logical.display()
                    ),
                    resolved: current,
                    link_target,
                });
            }

            let real = self.host_path(&current);
            let link_metadata = match fs::symlink_metadata(&real) {
                Ok(metadata) => metadata,
                Err(error) => {
                    return Err(ResolveFailure {
                        missing: error.kind() == std::io::ErrorKind::NotFound,
                        message: format!("failed to stat {}: {error}", current.display()),
                        resolved: current,
                        link_target,
                    });
                }
            };

            if link_metadata.file_type().is_symlink() {
                let target = match fs::read_link(&real) {
                    Ok(target) => target,
                    Err(error) => {
                        return Err(ResolveFailure {
                            missing: false,
                            message: format!(
                                "failed to read symlink {}: {error}",
                                current.display()
                            ),
                            resolved: current,
                            link_target,
                        });
                    }
                };
                let next = if target.is_absolute() {
                    normalize(&target)
                } else {
                    normalize(
                        &current
                            .parent()
                            .unwrap_or(Path::new("/"))
                            .join(&target),
                    )
                };
                link_target = Some(target);
                link_identity = Some(FileIdentity::from_metadata(&link_metadata));
                current = next;
                continue;
            }

            return Ok(Resolved {
                logical: current,
                real,
                metadata: link_metadata,
                link_target,
                link_identity,
            });
        }
    }
}

struct Resolved {
    logical: PathBuf,
    real: PathBuf,
    metadata: Metadata,
    link_target: Option<PathBuf>,
    link_identity: Option<FileIdentity>,
}

struct ResolveFailure {
    missing: bool,
    message: String,
    resolved: PathBuf,
    link_target: Option<PathBuf>,
}

fn capture_pass() -> CapturedData {
    let mut capture = Capture::new();
    capture.seed();
    capture.expand();
    capture.finish()
}

fn capture_generation(stamp: &ObservationStamp) -> Result<Snapshot, Vec<String>> {
    let first = capture_pass();
    let second = capture_pass();
    if first.fingerprint() == second.fingerprint() {
        Ok(build_snapshot(stamp, second))
    } else {
        Err(diff_paths(&first, &second))
    }
}

fn diff_paths(first: &CapturedData, second: &CapturedData) -> Vec<String> {
    let mut differences = Vec::new();
    for (path, record) in &first.files {
        match second.files.get(path) {
            Some(other) => {
                if record_fingerprint(record) != record_fingerprint(other) {
                    differences.push(format!("file={} changed", path.display()));
                }
            }
            None => differences.push(format!("file={} disappeared", path.display())),
        }
    }
    for path in second.files.keys() {
        if !first.files.contains_key(path) {
            differences.push(format!("file={} appeared", path.display()));
        }
    }
    for (path, entries) in &first.dirs {
        if second.dirs.get(path) != Some(entries) {
            differences.push(format!("dir={} changed", path.display()));
        }
    }
    if first.include_errors.len() != second.include_errors.len() {
        differences.push("include chain changed".to_string());
    }
    if differences.is_empty() {
        differences.push("snapshot fingerprint changed".to_string());
    }
    differences
}

fn record_fingerprint(record: &FileRecord) -> String {
    format!(
        "{}|{}|{}|{}|{}|{:?}|{:?}|{}",
        record.resolved.display(),
        record.missing,
        record.is_dir,
        record.digest.as_deref().unwrap_or(""),
        record
            .symlink_target
            .as_ref()
            .map(|target| target.display().to_string())
            .unwrap_or_default(),
        record.identity,
        record.link_identity,
        record.errors.join(";")
    )
}

fn failed_snapshot(
    stamp: ObservationStamp,
    attempts: u32,
    conflicts: Vec<String>,
) -> Snapshot {
    Snapshot {
        stamp,
        attempts,
        status: ObservationStatus::Failed,
        files: BTreeMap::new(),
        dirs: BTreeMap::new(),
        chains: BTreeMap::new(),
        include_errors: Vec::new(),
        generation_conflicts: conflicts.clone(),
        sources: BTreeMap::new(),
        failure: Some(format!("generation_conflicts={}", conflicts.join("; "))),
    }
}

fn build_snapshot(stamp: &ObservationStamp, data: CapturedData) -> Snapshot {
    let mut sources = BTreeMap::new();
    for source in PersistenceSource::all() {
        let mut observation = analyze(source, &data);
        observation.stamp = Some(stamp.clone());
        finalize_observation(&mut observation);
        sources.insert(source, observation);
    }

    let include_errors: Vec<String> = data
        .include_errors
        .iter()
        .map(|error| error.message.clone())
        .collect();
    let partial = !include_errors.is_empty()
        || data.files.values().any(|record| !record.errors.is_empty())
        || sources.values().any(|source| !source.errors.is_empty());
    let status = if partial {
        ObservationStatus::Partial
    } else {
        ObservationStatus::Complete
    };

    Snapshot {
        stamp: stamp.clone(),
        attempts: 0,
        status,
        files: data.files,
        dirs: data.dirs,
        chains: data.chains,
        include_errors,
        generation_conflicts: Vec::new(),
        sources,
        failure: None,
    }
}

fn finalize_observation(observation: &mut SourceObservation) {
    observation.findings.sort();
    observation.findings.dedup();
    observation.origins.sort();
    observation.origins.dedup();
    observation.include_chains.sort();
    observation.include_chains.dedup();
    observation.limitations.sort();
    observation.limitations.dedup();
}

fn empty_observation(_source: PersistenceSource) -> SourceObservation {
    SourceObservation {
        stamp: None,
        origins: Vec::new(),
        include_chains: Vec::new(),
        findings: Vec::new(),
        errors: Vec::new(),
        limitations: Vec::new(),
    }
}

fn analyze(source: PersistenceSource, data: &CapturedData) -> SourceObservation {
    match source {
        PersistenceSource::Ssh => analyze_ssh(data),
        PersistenceSource::Sudo => analyze_sudo(data),
        PersistenceSource::Pam => analyze_pam(data),
        PersistenceSource::Nss => analyze_nss(data),
        PersistenceSource::Systemd => analyze_systemd(data),
    }
}

fn analyze_ssh(data: &CapturedData) -> SourceObservation {
    let mut observation = empty_observation(PersistenceSource::Ssh);
    collect_include_errors(PersistenceSource::Ssh, data, &mut observation);

    let passwd_path = Path::new(PASSWD);
    let Some(passwd) = data.content(passwd_path) else {
        if let Some(record) = data.record(passwd_path) {
            if !record.missing {
                for error in &record.errors {
                    observation
                        .errors
                        .push(format!("failed to read {PASSWD}: {error}"));
                }
            }
        }
        return observation;
    };

    for line in passwd.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 6 {
            continue;
        }
        let user = parts[0];
        let home = parts[5];
        if !home.starts_with('/') {
            continue;
        }
        let auth_path = normalize(&Path::new(home).join(".ssh").join("authorized_keys"));
        let Some(record) = data.record(&auth_path) else {
            continue;
        };
        if record.missing {
            continue;
        }
        if record.is_dir {
            observation.errors.push(format!(
                "user={user}, file={}, error=is a directory",
                auth_path.display()
            ));
            continue;
        }
        if !record.errors.is_empty() {
            observation.errors.push(format!(
                "user={user}, file={}, error={}",
                auth_path.display(),
                record.errors.join("; ")
            ));
            continue;
        }
        let Some(content) = record.content.as_deref() else {
            continue;
        };

        let chain = vec![auth_path.clone()];
        record_origin(&mut observation, &auth_path);
        record_chain(&mut observation, &chain);
        if let Some(identity) = &record.identity {
            if identity.mode & 0o077 != 0 {
                push_finding(
                    &mut observation,
                    PersistenceSource::Ssh,
                    &auth_path,
                    &chain,
                    format!("user={user}, file={}, perms_insecure=true", auth_path.display()),
                );
            }
        }
        if let Some(target) = &record.symlink_target {
            observation.limitations.push(format!(
                "symlink={} -> {}",
                auth_path.display(),
                target.display()
            ));
        }

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let mut tokens = trimmed.split_whitespace();
            let first = tokens.next().unwrap_or("");
            let (options, key_tokens): (Option<&str>, Vec<&str>) = if first.starts_with("ssh-") {
                (None, std::iter::once(first).chain(tokens).collect())
            } else {
                (Some(first), tokens.collect())
            };

            if let Some(options) = options {
                let comment = key_tokens.get(2).copied().unwrap_or("");
                for option in options.split(',') {
                    let option = option.trim();
                    if option.is_empty() {
                        continue;
                    }
                    if option.starts_with("command=")
                        || option.starts_with("permitopen=")
                        || (option.starts_with("from=") && option.contains('*'))
                    {
                        push_finding(
                            &mut observation,
                            PersistenceSource::Ssh,
                            &auth_path,
                            &chain,
                            format!(
                                "user={user}, file={}, key_comment={comment}, option={option}",
                                auth_path.display()
                            ),
                        );
                    }
                }
            }
        }
    }
    observation
}

fn analyze_sudo(data: &CapturedData) -> SourceObservation {
    let mut observation = empty_observation(PersistenceSource::Sudo);
    collect_include_errors(PersistenceSource::Sudo, data, &mut observation);

    let mut files: Vec<PathBuf> = data.sudo_files.iter().cloned().collect();
    files.sort();
    for file in files {
        let Some(record) = data.record(&file) else {
            continue;
        };
        if record.missing {
            continue;
        }
        if record.is_dir {
            observation
                .errors
                .push(format!("failed to read {}: is a directory", file.display()));
            continue;
        }
        if !record.errors.is_empty() {
            observation.errors.push(format!(
                "failed to read {}: {}",
                file.display(),
                record.errors.join("; ")
            ));
            continue;
        }
        let Some(content) = record.content.as_deref() else {
            continue;
        };
        let chain = chain_starting_with(data, &file, Path::new(SUDOERS_ROOT));
        record_origin(&mut observation, &file);
        record_chain(&mut observation, &chain);

        for (index, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if trimmed.contains("NOPASSWD: ALL") {
                push_finding(
                    &mut observation,
                    PersistenceSource::Sudo,
                    &file,
                    &chain,
                    format!(
                        "file={}, line_no={}, entry='{}'",
                        file.display(),
                        index + 1,
                        trimmed
                    ),
                );
            }
            if trimmed.contains("ALL=(ALL) ALL") && trimmed.contains("!authenticate") {
                push_finding(
                    &mut observation,
                    PersistenceSource::Sudo,
                    &file,
                    &chain,
                    format!(
                        "file={}, line_no={}, entry='{}'",
                        file.display(),
                        index + 1,
                        trimmed
                    ),
                );
            }
        }
    }
    observation
}

fn analyze_pam(data: &CapturedData) -> SourceObservation {
    let mut observation = empty_observation(PersistenceSource::Pam);
    collect_include_errors(PersistenceSource::Pam, data, &mut observation);

    let mut files: Vec<PathBuf> = data.pam_files.iter().cloned().collect();
    files.sort();
    for file in files {
        let Some(record) = data.record(&file) else {
            continue;
        };
        if record.missing {
            continue;
        }
        if record.is_dir {
            observation
                .errors
                .push(format!("failed to read {}: is a directory", file.display()));
            continue;
        }
        if !record.errors.is_empty() {
            observation.errors.push(format!(
                "failed to read {}: {}",
                file.display(),
                record.errors.join("; ")
            ));
            continue;
        }
        let Some(content) = record.content.as_deref() else {
            continue;
        };
        let chain = longest_chain(data, &file);
        record_origin(&mut observation, &file);
        record_chain(&mut observation, &chain);

        for (index, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.is_empty() || parts[0].starts_with('@') {
                continue;
            }
            if parts.len() < 3 {
                continue;
            }
            let module_path = parts[2];
            if module_path.starts_with('/') && !is_system_lib(module_path) {
                push_finding(
                    &mut observation,
                    PersistenceSource::Pam,
                    &file,
                    &chain,
                    format!(
                        "file={}, line_no={}, line={}, anomaly=module_outside_system_libdirs",
                        file.display(),
                        index + 1,
                        line.trim()
                    ),
                );
            }
        }
    }
    observation
}

fn analyze_nss(data: &CapturedData) -> SourceObservation {
    let mut observation = empty_observation(PersistenceSource::Nss);
    collect_include_errors(PersistenceSource::Nss, data, &mut observation);

    let path = Path::new(NSSWITCH);
    let Some(record) = data.record(path) else {
        return observation;
    };
    if record.missing {
        return observation;
    }
    if record.is_dir {
        observation
            .errors
            .push(format!("failed to read {NSSWITCH}: is a directory"));
        return observation;
    }
    if !record.errors.is_empty() {
        observation
            .errors
            .push(format!("failed to read {NSSWITCH}: {}", record.errors.join("; ")));
        return observation;
    }
    let Some(content) = record.content.as_deref() else {
        return observation;
    };
    let chain = vec![path.to_path_buf()];
    record_origin(&mut observation, path);
    record_chain(&mut observation, &chain);

    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(fields) = trimmed.split_once(':') {
            let services = fields.1.trim().split_whitespace();
            for service in services {
                if service.starts_with('/') && !is_system_lib(service) {
                    push_finding(
                        &mut observation,
                        PersistenceSource::Nss,
                        path,
                        &chain,
                        format!(
                            "file={}, line_no={}, line={}, anomaly=module_outside_system_libdirs",
                            NSSWITCH,
                            index + 1,
                            line.trim()
                        ),
                    );
                }
            }
        }
    }
    observation
}

fn analyze_systemd(data: &CapturedData) -> SourceObservation {
    let mut observation = empty_observation(PersistenceSource::Systemd);
    collect_include_errors(PersistenceSource::Systemd, data, &mut observation);

    let mut units: Vec<PathBuf> = data
        .systemd_files
        .iter()
        .filter(|path| is_service_file(path))
        .cloned()
        .collect();
    units.sort();

    for unit in units {
        let Some(record) = data.record(&unit) else {
            continue;
        };
        if record.missing {
            continue;
        }
        if record.is_dir {
            observation
                .errors
                .push(format!("failed to read {}: is a directory", unit.display()));
            continue;
        }
        if is_masked(record) {
            record_origin(&mut observation, &unit);
            observation
                .limitations
                .push(format!("masked={}", unit.display()));
            continue;
        }
        if !record.errors.is_empty() {
            observation.errors.push(format!(
                "failed to read {}: {}",
                unit.display(),
                record.errors.join("; ")
            ));
            continue;
        }

        let mut chain = vec![unit.clone()];
        for dir in dropin_dirs(&unit) {
            if let Some(entries) = data.dirs.get(&dir) {
                let mut dropins: Vec<PathBuf> = entries
                    .iter()
                    .filter(|entry| {
                        entry.extension().and_then(|value| value.to_str()) == Some("conf")
                    })
                    .cloned()
                    .collect();
                dropins.sort();
                for dropin in dropins {
                    chain.push(dropin);
                }
            }
        }
        record_origin(&mut observation, &unit);
        record_chain(&mut observation, &chain);

        for command in effective_exec_commands(&data.files, &data.dirs, &unit) {
            if let Some(anomaly) = evaluate_exec_snapshot(&command, &data.files) {
                push_finding(
                    &mut observation,
                    PersistenceSource::Systemd,
                    &unit,
                    &chain,
                    format!(
                        "unit={}, exec={}, anomaly={anomaly}",
                        unit.display(),
                        command.trim()
                    ),
                );
            }
        }
    }
    observation
}

fn collect_include_errors(
    source: PersistenceSource,
    data: &CapturedData,
    observation: &mut SourceObservation,
) {
    for error in &data.include_errors {
        if error.source == Some(source) {
            observation.errors.push(error.message.clone());
        }
    }
}

fn push_finding(
    observation: &mut SourceObservation,
    source: PersistenceSource,
    file: &Path,
    chain: &[PathBuf],
    detail: String,
) {
    observation.findings.push(PersistenceFinding {
        source: source.label(),
        file: file.to_path_buf(),
        include_chain: chain.to_vec(),
        detail,
    });
}

fn record_origin(observation: &mut SourceObservation, file: &Path) {
    let rendered = file.display().to_string();
    if !observation.origins.contains(&rendered) {
        observation.origins.push(rendered);
    }
}

fn record_chain(observation: &mut SourceObservation, chain: &[PathBuf]) {
    let rendered = render_chain(chain);
    if !observation.include_chains.contains(&rendered) {
        observation.include_chains.push(rendered);
    }
}

fn chain_starting_with(data: &CapturedData, file: &Path, root: &Path) -> Vec<PathBuf> {
    let mut best: Option<Vec<PathBuf>> = None;
    if let Some(chains) = data.chains.get(file) {
        for chain in chains {
            let starts_at_root = chain
                .first()
                .map(|entry| entry.as_path() == root)
                .unwrap_or(false);
            let better = match &best {
                None => true,
                Some(current) => {
                    let current_starts_at_root = current
                        .first()
                        .map(|entry| entry.as_path() == root)
                        .unwrap_or(false);
                    if starts_at_root != current_starts_at_root {
                        starts_at_root
                    } else {
                        chain.len() > current.len()
                    }
                }
            };
            if better {
                best = Some(chain.clone());
            }
        }
    }
    best.unwrap_or_else(|| vec![file.to_path_buf()])
}

fn longest_chain(data: &CapturedData, file: &Path) -> Vec<PathBuf> {
    data.chains
        .get(file)
        .and_then(|chains| chains.iter().max_by_key(|chain| chain.len()).cloned())
        .unwrap_or_else(|| vec![file.to_path_buf()])
}

fn host_root() -> PathBuf {
    match std::env::var_os(ROOT_ENV) {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => PathBuf::from("/"),
    }
}

fn logical_from_host(root: &Path, host: &Path) -> PathBuf {
    match host.strip_prefix(root) {
        Ok(relative) => normalize(&Path::new("/").join(relative)),
        Err(_) => host.to_path_buf(),
    }
}

fn normalize(path: &Path) -> PathBuf {
    let mut output = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => output.push("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                output.pop();
            }
            Component::Normal(value) => output.push(value),
            Component::Prefix(_) => {}
        }
    }
    if output.as_os_str().is_empty() {
        output.push("/");
    }
    output
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for &byte in digest.iter() {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[derive(Clone, Debug)]
struct IncludeDirective {
    path: PathBuf,
    directory: bool,
}

fn sudo_includes(content: &str) -> Vec<IncludeDirective> {
    let mut directives = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        for (keyword, directory) in [
            ("#includedir", true),
            ("@includedir", true),
            ("#include", false),
            ("@include", false),
        ] {
            let Some(rest) = trimmed.strip_prefix(keyword) else {
                continue;
            };
            if !matches!(rest.chars().next(), Some(value) if value.is_whitespace()) {
                continue;
            }
            let argument = rest
                .trim()
                .trim_matches(|value: char| value == '"' || value == '\'');
            if argument.is_empty() {
                continue;
            }
            directives.push(IncludeDirective {
                path: PathBuf::from(argument),
                directory,
            });
            break;
        }
    }
    directives
}

fn pam_includes(content: &str) -> Vec<PathBuf> {
    let mut includes = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut tokens = trimmed.split_whitespace();
        let Some(keyword) = tokens.next() else {
            continue;
        };
        if keyword != "@include" && keyword != "include" {
            continue;
        }
        let Some(argument) = tokens.next() else {
            continue;
        };
        let argument = argument.trim_matches(|value: char| value == '"' || value == '\'');
        if !argument.is_empty() {
            includes.push(PathBuf::from(argument));
        }
    }
    includes
}

fn sudoers_dir_accepts(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    !name.ends_with('~') && !name.contains('.')
}

fn is_service_file(path: &Path) -> bool {
    path.extension().and_then(|value| value.to_str()) == Some("service")
}

fn dropin_dirs(unit: &Path) -> Vec<PathBuf> {
    let name = unit
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("unit");
    let mut dirs = Vec::new();
    for root in DROPIN_ROOTS {
        let dir = normalize(&Path::new(root).join(format!("{name}.d")));
        if !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    dirs
}

fn is_masked(record: &FileRecord) -> bool {
    record
        .symlink_target
        .as_deref()
        .map(|target| target == Path::new("/dev/null"))
        .unwrap_or(false)
        || record.resolved.as_path() == Path::new("/dev/null")
}

fn is_system_lib(path: &str) -> bool {
    SYSTEM_LIB_DIRS.iter().any(|dir| path.starts_with(dir))
}

fn logical_lines(content: &str) -> Vec<String> {
    let mut output = Vec::new();
    let mut current = String::new();
    for raw in content.lines() {
        let line = raw.trim_end();
        if let Some(prefix) = line.strip_suffix('\\') {
            current.push_str(prefix);
            current.push(' ');
        } else {
            current.push_str(line);
            output.push(std::mem::take(&mut current));
        }
    }
    if !current.trim().is_empty() {
        output.push(current);
    }
    output
}

fn executable_logical(command: &str) -> Option<PathBuf> {
    let token = command.split_whitespace().next()?;
    let token = token.trim_matches(|value: char| value == '"' || value == '\'');
    let token = token.trim_start_matches(|value: char| {
        value == '-' || value == '@' || value == ':' || value == '+' || value == '!'
    });
    if !token.starts_with('/') {
        return None;
    }
    let relative = token.strip_prefix('/').unwrap_or(token);
    Some(normalize(&Path::new("/").join(relative)))
}

fn effective_exec_commands(
    files: &BTreeMap<PathBuf, FileRecord>,
    dirs: &BTreeMap<PathBuf, Vec<PathBuf>>,
    unit: &Path,
) -> Vec<String> {
    let mut unit_files = vec![unit.to_path_buf()];
    for dir in dropin_dirs(unit) {
        if let Some(entries) = dirs.get(&dir) {
            let mut dropins: Vec<PathBuf> = entries
                .iter()
                .filter(|entry| entry.extension().and_then(|value| value.to_str()) == Some("conf"))
                .cloned()
                .collect();
            dropins.sort();
            unit_files.extend(dropins);
        }
    }

    // systemd accumulates ExecStart/ExecStartPre/ExecStop entries across the
    // unit and its drop-ins.  An empty assignment resets that list; a later
    // non-empty assignment appends instead of replacing.
    let mut assignments: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    for file in &unit_files {
        let Some(content) = files.get(file).and_then(|record| record.content.as_deref()) else {
            continue;
        };
        for line in logical_lines(content) {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim();
            for candidate in ["ExecStart", "ExecStartPre", "ExecStop"] {
                if key == candidate {
                    let entries = assignments.entry(candidate).or_default();
                    if value.is_empty() {
                        entries.clear();
                    } else {
                        entries.push(value.to_string());
                    }
                }
            }
        }
    }

    let mut commands = Vec::new();
    for key in ["ExecStart", "ExecStartPre", "ExecStop"] {
        if let Some(entries) = assignments.get(key) {
            commands.extend(entries.iter().cloned());
        }
    }
    commands
}

fn evaluate_exec_snapshot(
    command: &str,
    files: &BTreeMap<PathBuf, FileRecord>,
) -> Option<&'static str> {
    let token = command.split_whitespace().next()?;
    let token = token.trim_matches(|value: char| value == '"' || value == '\'');
    let token = token.trim_start_matches(|value: char| {
        value == '-' || value == '@' || value == ':' || value == '+' || value == '!'
    });
    if token.starts_with('/') {
        let logical = executable_logical(token)?;
        let exists = files
            .get(&logical)
            .map(|record| !record.missing && !record.is_dir && record.errors.is_empty())
            .unwrap_or(false);
        if !exists {
            if token.contains("(deleted)") {
                return Some("exec_deleted");
            }
            return Some("exec_missing");
        }
        if token.starts_with("/tmp/") || token.starts_with("/var/tmp/") {
            return Some("exec_in_tmp");
        }
    } else if token.contains("/tmp/") {
        return Some("exec_in_tmp");
    }
    None
}

/// Scanner outcome for one persistence source, preserving the legacy finding
/// text and appending `source=`, `include_chain=` and `generation=`.
pub fn outcome(snapshot: &Snapshot, source: PersistenceSource) -> ScanOutcome {
    outcome_many(snapshot, &[source])
}

/// Combined outcome for the PAM + NSS scanner.
pub fn pam_nss_outcome(snapshot: &Snapshot) -> ScanOutcome {
    outcome_many(snapshot, &[PersistenceSource::Pam, PersistenceSource::Nss])
}

fn outcome_many(snapshot: &Snapshot, sources: &[PersistenceSource]) -> ScanOutcome {
    if snapshot.status == ObservationStatus::Failed {
        return Err(snapshot.failure.clone().unwrap_or_else(|| {
            "persistence observation failed without a captured generation".to_string()
        }));
    }

    let generation = snapshot.generation_label();
    let mut findings = Vec::new();
    let mut errors = Vec::new();
    let mut missing = false;

    for source in sources {
        match snapshot.sources.get(source) {
            Some(observation) => {
                findings.extend(
                    observation
                        .findings
                        .iter()
                        .map(|finding| finding.render(&generation)),
                );
                errors.extend(observation.errors.iter().cloned());
            }
            None => missing = true,
        }
    }

    if missing {
        return Err("persistence observation is missing a source".to_string());
    }

    findings.sort();
    findings.dedup();

    if findings.is_empty() {
        if errors.is_empty() {
            Ok(None)
        } else {
            Ok(Some(format!("collection_errors={}", errors.join(", "))))
        }
    } else {
        if !errors.is_empty() {
            findings.push(format!("collection_errors={}", errors.join(", ")));
        }
        Ok(Some(findings.join("\n")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sudo_include_syntaxes_are_recognized() {
        let content =
            "#includedir /etc/sudoers.d\n@include /etc/sudoers.extra\n#include \"relative.conf\"\n";
        let directives = sudo_includes(content);
        assert_eq!(directives.len(), 3);
        assert!(directives[0].directory);
        assert_eq!(directives[0].path, PathBuf::from("/etc/sudoers.d"));
        assert!(!directives[1].directory);
        assert_eq!(directives[1].path, PathBuf::from("/etc/sudoers.extra"));
        assert_eq!(directives[2].path, PathBuf::from("relative.conf"));
    }

    #[test]
    fn include_keyword_requires_a_separator() {
        assert!(sudo_includes("#includedirx /tmp/no\n#include\n").is_empty());
    }

    #[test]
    fn pam_include_is_recognized() {
        let includes = pam_includes("@include common-auth\nauth required pam_unix.so\n");
        assert_eq!(includes, vec![PathBuf::from("common-auth")]);
    }

    #[test]
    fn path_normalization_stays_absolute() {
        assert_eq!(
            normalize(Path::new("/etc/../etc/sudoers")),
            PathBuf::from("/etc/sudoers")
        );
        assert_eq!(normalize(Path::new("/../..")), PathBuf::from("/"));
    }

    #[test]
    fn continuation_lines_are_joined() {
        let lines = logical_lines("[Service]\nExecStart=/bin/foo \\\n  --bar\n");
        assert_eq!(lines.len(), 2);
        assert!(lines[1].starts_with("ExecStart=/bin/foo"));
        assert!(lines[1].contains("--bar"));
    }

    #[test]
    fn sudoers_includedir_filter_matches_sudo() {
        assert!(sudoers_dir_accepts(Path::new("/etc/sudoers.d/90-users")));
        assert!(!sudoers_dir_accepts(Path::new("/etc/sudoers.d/90.conf")));
        assert!(!sudoers_dir_accepts(Path::new("/etc/sudoers.d/90-users~")));
    }

    #[test]
    fn chain_rendering_is_stable() {
        let chain = vec![
            PathBuf::from("/etc/sudoers"),
            PathBuf::from("/etc/sudoers.d/x"),
        ];
        assert_eq!(render_chain(&chain), "/etc/sudoers->/etc/sudoers.d/x");
    }
}
