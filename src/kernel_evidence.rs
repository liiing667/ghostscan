//! One boot-scoped collection generation for kernel integrity evidence.
//!
//! `hidden_lkm`, `module_list_linkage_tamper`, `kernel_taint` and
//! `syscall_table` all read from `/proc`, `/sys` and kernel symbol maps.  Those
//! sources only make sense together when they describe the same running boot:
//! a module set collected before a reboot cannot be paired with a syscall table
//! read after the reboot, and a `System.map` for another kernel release cannot
//! be mixed with the live module inventory.
//!
//! This module freezes one [`CollectionGeneration`] before the scanner loop.
//! The generation carries the boot id, kernel release, module-set fingerprint
//! and symbol-source fingerprint.  Every module list, taint record and symbol
//! lookup is stamped with that generation.  A scanner that is handed evidence
//! from a superseded generation returns an explicit `unknown` state instead of
//! publishing the old modules or addresses as current.
//!
//! Compatibility choices:
//!
//! * every configured symbol source is still collected; a source for the same
//!   kernel release is compared with the other sources as before,
//! * a source for another kernel release is retained as an explicit finding but
//!   is never joined to the current boot's modules or addresses,
//! * permission errors keep their original text,
//! * a successfully read empty module set is complete evidence (`module_count`
//!   is `Some(0)`), not a collection failure.

use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, File},
    io::{self, BufRead},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

/// Placeholder used when a host identity or source cannot be read.
pub const UNKNOWN: &str = "unknown";

static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
static KERNEL_EVIDENCE: Mutex<Option<Arc<KernelEvidence>>> = Mutex::new(None);
static SCAN_PINNED: AtomicBool = AtomicBool::new(false);

fn evidence_lock() -> std::sync::MutexGuard<'static, Option<Arc<KernelEvidence>>> {
    KERNEL_EVIDENCE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Begin a new collection generation for the whole scanner loop.
///
/// The previous generation is replaced, never merged.  The returned handle and
/// any scanner result derived from it are the only evidence that may be
/// published for this round.
pub fn begin_scan() -> Arc<KernelEvidence> {
    begin_scan_pinned(EvidencePaths::from_env())
}

/// Begin a generation and pin it for the lifetime of a full scan loop.
pub fn begin_scan_pinned(paths: EvidencePaths) -> Arc<KernelEvidence> {
    let evidence = begin_scan_with(paths);
    SCAN_PINNED.store(true, Ordering::SeqCst);
    evidence
}

/// Alias for [`begin_scan`].
pub fn start_scan() -> Arc<KernelEvidence> {
    begin_scan()
}

/// End-of-loop hook: release a generation pinned by [`begin_scan`].
pub fn finish_scan() {
    SCAN_PINNED.store(false, Ordering::SeqCst);
}

/// Begin a generation using explicit paths (tests or a fake proc/sys tree).
pub fn begin_scan_with(paths: EvidencePaths) -> Arc<KernelEvidence> {
    let mut evidence = KernelEvidence::collect(paths);
    evidence.installed = true;
    let evidence = Arc::new(evidence);
    SCAN_PINNED.store(false, Ordering::SeqCst);
    *evidence_lock() = Some(Arc::clone(&evidence));
    evidence
}

/// The generation currently serving the scanner loop, if one was started.
pub fn current() -> Option<Arc<KernelEvidence>> {
    evidence_lock().as_ref().map(Arc::clone)
}

/// Alias for [`current`].
pub fn current_generation() -> Option<Arc<KernelEvidence>> {
    current()
}

/// Fetch the active generation, or collect a standalone one for a scanner
/// invoked directly.
///
/// A standalone collection is not installed as the active generation, so two
/// independent scanner calls cannot silently share one another's evidence.
pub fn current_or_collect() -> Arc<KernelEvidence> {
    match current() {
        Some(evidence) => {
            if SCAN_PINNED.load(Ordering::SeqCst) {
                return evidence;
            }
            // A one-shot process can outlive a reboot when it is driven by a
            // long-running front end.  Revalidate the cheap host identity
            // before handing the cached generation to another scanner; a
            // changed boot starts a fresh generation from the same roots.
            if evidence.boot_identity_matches(&evidence.paths)
                && evidence.module_lists_match(&evidence.paths)
                && evidence.taint_value_matches(&evidence.paths)
            {
                evidence
            } else {
                begin_scan_with(evidence.paths.clone())
            }
        }
        None => Arc::new(KernelEvidence::collect(EvidencePaths::from_env())),
    }
}

/// Drop the active generation.  Primarily for tests and one-shot front ends.
pub fn clear() {
    SCAN_PINNED.store(false, Ordering::SeqCst);
    *evidence_lock() = None;
}

fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name).map(PathBuf::from)
}

/// Filesystem roots used by the kernel evidence collectors.
#[derive(Clone, Debug)]
pub struct EvidencePaths {
    pub proc_root: PathBuf,
    pub sys_root: PathBuf,
    pub lib_module_roots: Vec<PathBuf>,
    pub boot_root: PathBuf,
    /// Exact `System.map` candidates.  When present this replaces the standard
    /// release-derived search list (used by tests and fake proc/sys trees).
    pub system_map_override: Option<Vec<PathBuf>>,
}

impl Default for EvidencePaths {
    fn default() -> Self {
        Self::from_env()
    }
}

impl EvidencePaths {
    pub fn from_env() -> Self {
        let root = env_path("GHOSTSCAN_ROOT");

        let proc_root = env_path("GHOSTSCAN_PROC_ROOT")
            .or_else(|| root.as_ref().map(|root| root.join("proc")))
            .unwrap_or_else(|| PathBuf::from("/proc"));
        let sys_root = env_path("GHOSTSCAN_SYS_ROOT")
            .or_else(|| root.as_ref().map(|root| root.join("sys")))
            .unwrap_or_else(|| PathBuf::from("/sys"));
        let inferred_root = root.clone().or_else(|| {
            if proc_root.as_path() != Path::new("/proc") {
                proc_root.parent().map(PathBuf::from)
            } else if sys_root.as_path() != Path::new("/sys") {
                sys_root.parent().map(PathBuf::from)
            } else {
                None
            }
        });
        let boot_root = env_path("GHOSTSCAN_BOOT_ROOT")
            .or_else(|| inferred_root.as_ref().map(|root| root.join("boot")))
            .unwrap_or_else(|| PathBuf::from("/boot"));
        let lib_module_roots = match env_path("GHOSTSCAN_LIB_MODULES_ROOT") {
            Some(path) => vec![path],
            None => match inferred_root.as_ref() {
                Some(root) => vec![
                    root.join("usr/lib/modules"),
                    root.join("lib/modules"),
                ],
                None => vec![
                    PathBuf::from("/usr/lib/modules"),
                    PathBuf::from("/lib/modules"),
                ],
            },
        };
        let system_map_override = env::var_os("GHOSTSCAN_SYSTEM_MAP")
            .map(|value| env::split_paths(&value).collect::<Vec<_>>());

        Self {
            proc_root,
            sys_root,
            lib_module_roots,
            boot_root,
            system_map_override,
        }
    }

    /// Build paths for a fake proc/sys tree.  The caller should normally also
    /// call [`Self::with_system_maps`] so the host's real `System.map` files
    /// are not consulted.
    pub fn new(proc_root: impl Into<PathBuf>, sys_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
            sys_root: sys_root.into(),
            lib_module_roots: vec![
                PathBuf::from("/usr/lib/modules"),
                PathBuf::from("/lib/modules"),
            ],
            boot_root: PathBuf::from("/boot"),
            system_map_override: None,
        }
    }

    /// Build paths for a fake tree rooted at `root` (`root/proc`, `root/sys`,
    /// `root/boot` and `root/lib/modules`).
    pub fn for_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let mut paths = Self::new(root.join("proc"), root.join("sys"));
        paths.boot_root = root.join("boot");
        paths.lib_module_roots = vec![
            root.join("usr/lib/modules"),
            root.join("lib/modules"),
        ];
        paths
    }

    pub fn with_system_maps(mut self, maps: Vec<PathBuf>) -> Self {
        self.system_map_override = Some(maps);
        self
    }

    pub fn boot_id_path(&self) -> PathBuf {
        self.proc_root.join("sys/kernel/random/boot_id")
    }

    pub fn osrelease_path(&self) -> PathBuf {
        self.proc_root.join("sys/kernel/osrelease")
    }

    pub fn tainted_path(&self) -> PathBuf {
        self.proc_root.join("sys/kernel/tainted")
    }

    pub fn proc_modules_path(&self) -> PathBuf {
        self.proc_root.join("modules")
    }

    pub fn kallsyms_path(&self) -> PathBuf {
        self.proc_root.join("kallsyms")
    }

    pub fn stat_path(&self) -> PathBuf {
        self.proc_root.join("stat")
    }

    pub fn sys_module_path(&self) -> PathBuf {
        self.sys_root.join("module")
    }

    pub fn module_holders_path(&self, module: &str) -> PathBuf {
        self.sys_module_path().join(module).join("holders")
    }

    /// `System.map` candidates in the same order as the original scanner.
    pub fn system_map_candidates(&self, release: &str) -> Vec<PathBuf> {
        if let Some(override_paths) = &self.system_map_override {
            return override_paths.clone();
        }

        let mut candidates = Vec::new();
        for root in &self.lib_module_roots {
            let release_dir = root.join(release);
            candidates.push(release_dir.join("System.map"));
            candidates.push(release_dir.join("build").join("System.map"));
        }
        candidates.push(self.boot_root.join(format!("System.map-{release}")));
        candidates.push(self.boot_root.join("System.map"));
        candidates
    }
}

/// Stable identity of one collection round.
///
/// `round` distinguishes attempts inside a process.  Cross-boot checks use
/// [`Self::same_boot`] or [`Self::same_collection`]; an exact generation check
/// also includes the round and process id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionGeneration {
    /// `/proc/sys/kernel/random/boot_id` (or `unknown`).
    pub boot_id: String,
    /// Normalised `/proc/sys/kernel/osrelease` (or `unknown`).
    pub kernel_release: String,
    /// `/proc/stat` `btime`, used when boot ids are unavailable.
    pub boot_time_unix_secs: Option<u64>,
    /// SHA-256 over the sorted union of every successfully collected module
    /// name.  `unknown` means the module set itself is unknown.
    pub module_fingerprint: String,
    /// `Some(0)` is a complete, empty module set.
    pub module_count: Option<usize>,
    /// SHA-256 over the sorted symbol source labels.
    pub symbol_source_fingerprint: String,
    /// Human-readable labels of the symbol sources considered this round.
    pub symbol_sources: Vec<String>,
    /// Kernel taint value observed in the same generation, when readable.
    pub taint_value: Option<u64>,
    /// Process-local monotonic round number.
    pub round: u64,
    pub started_unix_ns: u128,
    pub pid: u32,
}

impl CollectionGeneration {
    pub fn label(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}",
            self.boot_id,
            self.kernel_release,
            self.module_fingerprint,
            self.symbol_source_fingerprint,
            self.taint_value
                .map(|value| value.to_string())
                .unwrap_or_else(|| UNKNOWN.to_string()),
            self.round
        )
    }

    pub fn boot_identity_known(&self) -> bool {
        self.boot_id != UNKNOWN && self.kernel_release != UNKNOWN
    }

    /// Same running boot and kernel release.
    pub fn same_boot(&self, other: &Self) -> bool {
        let known_boot = self.boot_id != UNKNOWN && other.boot_id != UNKNOWN;
        let boot_matches = if known_boot {
            self.boot_id == other.boot_id
        } else {
            self.boot_id == other.boot_id
                && self.boot_time_unix_secs == other.boot_time_unix_secs
        };
        boot_matches
            && self.kernel_release == other.kernel_release
            && (known_boot || self.boot_time_unix_secs.is_some() || self.round == other.round)
    }

    /// Same boot, module set and symbol-source set.  This is the boundary for
    /// accepting evidence in a later retry of the same observation.
    pub fn same_collection(&self, other: &Self) -> bool {
        self.same_boot(other)
            && self.module_fingerprint == other.module_fingerprint
            && self.module_count == other.module_count
            && self.symbol_source_fingerprint == other.symbol_source_fingerprint
            && self.taint_value == other.taint_value
    }

    /// Two observations describe the same boot generation when boot, release,
    /// module set and symbol-source set agree.  A retry of the same host is
    /// therefore compatible evidence; a reboot or source switch is not.
    pub fn same_generation(&self, other: &Self) -> bool {
        self.same_collection(other)
    }

    /// Exact attempt identity, including round, process and start time.
    pub fn same_attempt(&self, other: &Self) -> bool {
        self.same_generation(other)
            && self.round == other.round
            && self.pid == other.pid
            && self.started_unix_ns == other.started_unix_ns
    }
}

fn normalize_release(value: &str) -> String {
    value.trim().to_string()
}

fn fingerprint_labels(labels: &mut Vec<String>) -> String {
    labels.sort();
    labels.dedup();
    let mut hasher = Sha256::new();
    for label in labels {
        hasher.update(label.as_bytes());
        hasher.update(b"\n");
    }
    format!("{:x}", hasher.finalize())
}

fn fingerprint_module_set(
    names: &BTreeSet<String>,
    proc_ok: bool,
    sysfs_ok: bool,
    kallsyms_ok: bool,
) -> String {
    let mut hasher = Sha256::new();
    let status = format!(
        "proc_modules={}|sysfs={}|kallsyms={}\n",
        proc_ok, sysfs_ok, kallsyms_ok
    );
    hasher.update(status.as_bytes());
    for name in names {
        hasher.update(name.as_bytes());
        hasher.update(b"\n");
    }
    format!("{:x}", hasher.finalize())
}

fn read_trim(path: &Path) -> io::Result<String> {
    Ok(fs::read_to_string(path)?.trim().to_string())
}

fn read_boot_time(path: &Path) -> Option<u64> {
    let content = fs::read_to_string(path).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("btime ") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Module inventories and `/proc/modules` taint letters from one generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleSources {
    /// Generation that produced these inventories.  `None` only exists for
    /// compatibility with callers that construct evidence by hand.
    pub generation: Option<CollectionGeneration>,
    pub proc_modules: Result<BTreeSet<String>, String>,
    pub proc_module_taints: Result<BTreeMap<char, Vec<String>>, String>,
    pub sysfs_modules: Result<BTreeSet<String>, String>,
    /// `/sys/module/<name>/holders` entries observed in this generation.
    pub sysfs_holders: BTreeMap<String, BTreeSet<String>>,
    /// Holder read failures other than a missing `holders` directory.
    pub holder_errors: Vec<String>,
    pub kallsyms_modules: Result<BTreeSet<String>, String>,
    /// The exact `/proc/kallsyms` read used for both module tags and symbol
    /// lookup, so the two cannot come from different reads of the file.
    pub kallsyms_raw: Result<String, String>,
}

/// Alias used by callers that describe the module inventory as one record.
pub type ModuleEvidence = ModuleSources;

impl ModuleSources {
    pub fn collect(paths: &EvidencePaths) -> Self {
        let (proc_modules, proc_module_taints) =
            match fs::read_to_string(paths.proc_modules_path()) {
                Ok(content) => parse_proc_modules(&content),
                Err(err) => {
                    let error = err.to_string();
                    (Err(error.clone()), Err(error))
                }
            };

        let sysfs_modules = match read_sysfs_modules(&paths.sys_module_path()) {
            Ok(set) => Ok(set),
            Err(err) => Err(err.to_string()),
        };

        let kallsyms_raw = match fs::read_to_string(paths.kallsyms_path()) {
            Ok(content) => Ok(content),
            Err(err) => Err(err.to_string()),
        };
        let kallsyms_modules = match &kallsyms_raw {
            Ok(content) => Ok(parse_kallsyms_modules(content)),
            Err(err) => Err(err.clone()),
        };

        let mut sysfs_holders = BTreeMap::new();
        let mut holder_errors = Vec::new();
        if let Ok(modules) = &sysfs_modules {
            for module in modules {
                let holders_path = paths.module_holders_path(module);
                match fs::read_dir(&holders_path) {
                    Ok(entries) => {
                        let holders = sysfs_holders.entry(module.clone()).or_default();
                        for entry in entries.flatten() {
                            holders.insert(entry.file_name().to_string_lossy().into_owned());
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                    Err(err) => holder_errors.push(format!("{}: {}", holders_path.display(), err)),
                }
            }
        }

        Self {
            generation: None,
            proc_modules,
            proc_module_taints,
            sysfs_modules,
            sysfs_holders,
            holder_errors,
            kallsyms_modules,
            kallsyms_raw,
        }
    }

    pub fn all_names(&self) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        for source in [
            self.proc_modules.as_ref(),
            self.sysfs_modules.as_ref(),
            self.kallsyms_modules.as_ref(),
        ] {
            if let Ok(set) = source {
                names.extend(set.iter().cloned());
            }
        }
        names
    }

    pub fn successful_source_count(&self) -> usize {
        [
            self.proc_modules.is_ok(),
            self.sysfs_modules.is_ok(),
            self.kallsyms_modules.is_ok(),
        ]
        .into_iter()
        .filter(|ok| *ok)
        .count()
    }

    /// `(None, None)` means no module source was readable.  An empty but
    /// completely readable inventory returns `(Some(fingerprint), Some(0))`.
    /// A partial inventory is unknown rather than a smaller "complete" set.
    pub fn module_fingerprint(&self) -> (Option<String>, Option<usize>) {
        if self.successful_source_count() != 3 {
            return (None, None);
        }
        let names = self.all_names();
        (
            Some(fingerprint_module_set(
                &names,
                self.proc_modules.is_ok(),
                self.sysfs_modules.is_ok(),
                self.kallsyms_modules.is_ok(),
            )),
            Some(names.len()),
        )
    }

    pub fn proc_names(&self) -> Option<&BTreeSet<String>> {
        self.proc_modules.as_ref().ok()
    }

    pub fn sysfs_names(&self) -> Option<&BTreeSet<String>> {
        self.sysfs_modules.as_ref().ok()
    }

    pub fn kallsyms_names(&self) -> Option<&BTreeSet<String>> {
        self.kallsyms_modules.as_ref().ok()
    }
}

fn parse_proc_modules(content: &str) -> (Result<BTreeSet<String>, String>, Result<BTreeMap<char, Vec<String>>, String>) {
    let mut names = BTreeSet::new();
    let mut taints: BTreeMap<char, Vec<String>> = BTreeMap::new();

    for line in content.lines() {
        let name = match line.split_whitespace().next() {
            Some(name) if !name.is_empty() => name.to_string(),
            _ => continue,
        };
        names.insert(name.clone());

        if let Some(start) = line.find('(') {
            if let Some(end_offset) = line[start + 1..].find(')') {
                for ch in line[start + 1..start + 1 + end_offset].chars() {
                    if ch.is_ascii_alphabetic() {
                        taints.entry(ch).or_default().push(name.clone());
                    }
                }
            }
        }
    }

    for modules in taints.values_mut() {
        modules.sort();
        modules.dedup();
    }
    (Ok(names), Ok(taints))
}

fn read_sysfs_modules(path: &Path) -> io::Result<BTreeSet<String>> {
    let mut set = BTreeSet::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            set.insert(entry.file_name().to_string_lossy().into_owned());
        }
    }
    Ok(set)
}

fn parse_kallsyms_modules(content: &str) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for line in content.lines() {
        if let Some(module) = extract_module_name(line) {
            set.insert(module);
        }
    }
    set
}

fn extract_module_name(line: &str) -> Option<String> {
    let start = line.rfind('[')?;
    let end = line.rfind(']')?;
    if end + 1 != line.len() || end < start {
        return None;
    }
    let module = &line[start + 1..end];
    if module.is_empty() {
        None
    } else {
        Some(module.to_string())
    }
}

/// Kernel taint value plus the module letters visible in this generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaintEvidence {
    /// Generation that produced the value and module letters.
    pub generation: Option<CollectionGeneration>,
    /// `Err` already contains the scanner-compatible message.
    pub value: Result<u64, String>,
    /// `Err` already contains the scanner-compatible message.
    pub module_letters: Result<BTreeMap<char, Vec<String>>, String>,
}

impl TaintEvidence {
    fn collect(
        paths: &EvidencePaths,
        modules: &ModuleSources,
        generation: &CollectionGeneration,
    ) -> Self {
        let value = match fs::read_to_string(paths.tainted_path()) {
            Ok(raw) => match raw.trim().parse::<u64>() {
                Ok(value) => Ok(value),
                Err(err) => Err(format!("failed to parse tainted value '{raw}': {err}")),
            },
            Err(err) => Err(format!("failed to read /proc/sys/kernel/tainted: {err}")),
        };

        let module_letters = collect_module_taint_letters(paths, modules)
            .map_err(|err| format!("failed to collect module taints: {err}"));

        Self {
            generation: Some(generation.clone()),
            value,
            module_letters,
        }
    }
}

fn collect_module_taint_letters(
    paths: &EvidencePaths,
    modules: &ModuleSources,
) -> Result<BTreeMap<char, Vec<String>>, String> {
    let mut map: BTreeMap<char, BTreeSet<String>> = BTreeMap::new();

    let entries = fs::read_dir(paths.sys_module_path()).map_err(|err| err.to_string())?;
    for entry in entries {
        let entry = entry.map_err(|err| err.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Ok(content) = fs::read_to_string(entry.path().join("taint")) {
            for ch in content.trim().chars() {
                if ch.is_ascii_alphabetic() {
                    map.entry(ch).or_default().insert(name.clone());
                }
            }
        }
    }

    let proc_taints = modules
        .proc_module_taints
        .as_ref()
        .map_err(|err| err.clone())?;
    for (ch, names) in proc_taints {
        map.entry(*ch).or_default().extend(names.iter().cloned());
    }

    let mut result = BTreeMap::new();
    for (letter, modules) in map {
        result.insert(letter, modules.into_iter().collect());
    }
    Ok(result)
}

/// A symbol source considered in this generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SymbolSource {
    Kallsyms,
    SystemMap {
        path: PathBuf,
        kernel_release: Option<String>,
    },
    /// `/proc/sys/kernel/osrelease` itself was unreadable.
    KernelRelease,
}

impl SymbolSource {
    pub fn label(&self) -> String {
        match self {
            Self::Kallsyms => "/proc/kallsyms".to_string(),
            Self::SystemMap { path, .. } => format!("System.map({})", path.display()),
            Self::KernelRelease => "/proc/sys/kernel/osrelease".to_string(),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Kallsyms => "kallsyms",
            Self::SystemMap { .. } => "system_map",
            Self::KernelRelease => "kernel_release",
        }
    }

    pub fn configured_release(&self) -> Option<&str> {
        match self {
            Self::SystemMap { kernel_release, .. } => kernel_release.as_deref(),
            Self::Kallsyms | Self::KernelRelease => None,
        }
    }
}

/// Result of one symbol lookup attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SymbolResult {
    Found(u64),
    Missing,
    Failed(String),
}

/// Symbol evidence stamped with the generation that produced it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymbolEvidence {
    pub source: SymbolSource,
    pub result: SymbolResult,
    pub source_release: Option<String>,
    pub generation: CollectionGeneration,
}

impl SymbolEvidence {
    pub fn label(&self) -> String {
        self.source.label()
    }

    /// `Some(reason)` when this source belongs to a different kernel release.
    pub fn foreign_release_reason(&self, current: &CollectionGeneration) -> Option<String> {
        let configured = self.source.configured_release()?;
        if current.kernel_release == UNKNOWN {
            return None;
        }
        if normalize_release(configured) == current.kernel_release {
            None
        } else {
            Some(format!(
                "source={} issue=foreign_kernel_release cross_generation=1 expected_kernel_release={} observed_kernel_release={}",
                self.source.label(),
                current.kernel_release,
                normalize_release(configured)
            ))
        }
    }

    pub fn is_unverified_release(&self) -> bool {
        matches!(
            &self.source,
            SymbolSource::SystemMap {
                kernel_release: None,
                ..
            }
        )
    }
}

#[derive(Clone, Debug)]
struct RawSymbol {
    source: SymbolSource,
    result: SymbolResult,
    source_release: Option<String>,
}

fn collect_raw_symbols(
    paths: &EvidencePaths,
    release: &str,
    release_error: Option<&str>,
    kallsyms_raw: &Result<String, String>,
) -> Vec<RawSymbol> {
    let mut raw = Vec::new();

    match kallsyms_raw {
        Ok(content) => match find_symbol_in_text(content, "sys_call_table") {
            Some(address) => raw.push(RawSymbol {
                source: SymbolSource::Kallsyms,
                result: SymbolResult::Found(address),
                source_release: Some(release.to_string()),
            }),
            None => raw.push(RawSymbol {
                source: SymbolSource::Kallsyms,
                result: SymbolResult::Missing,
                source_release: Some(release.to_string()),
            }),
        },
        Err(err) => raw.push(RawSymbol {
            source: SymbolSource::Kallsyms,
            result: SymbolResult::Failed(err.clone()),
            source_release: Some(release.to_string()),
        }),
    }

    if release == UNKNOWN {
        raw.push(RawSymbol {
            source: SymbolSource::KernelRelease,
            result: SymbolResult::Failed(
                release_error
                    .unwrap_or("kernel release is unknown")
                    .to_string(),
            ),
            source_release: None,
        });
        return raw;
    }

    let mut seen = BTreeSet::new();
    for candidate in paths.system_map_candidates(release) {
        if !seen.insert(candidate.clone()) {
            continue;
        }
        let source_release = kernel_release_from_path(&candidate);
        match File::open(&candidate) {
            Ok(file) => match find_symbol_in_reader(file, "sys_call_table") {
                Ok(Some(address)) => raw.push(RawSymbol {
                    source: SymbolSource::SystemMap {
                        path: candidate,
                        kernel_release: source_release.clone(),
                    },
                    result: SymbolResult::Found(address),
                    source_release,
                }),
                Ok(None) => raw.push(RawSymbol {
                    source: SymbolSource::SystemMap {
                        path: candidate,
                        kernel_release: source_release.clone(),
                    },
                    result: SymbolResult::Missing,
                    source_release,
                }),
                Err(err) => raw.push(RawSymbol {
                    source: SymbolSource::SystemMap {
                        path: candidate,
                        kernel_release: source_release.clone(),
                    },
                    result: SymbolResult::Failed(err.to_string()),
                    source_release,
                }),
            },
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => raw.push(RawSymbol {
                source: SymbolSource::SystemMap {
                    path: candidate,
                    kernel_release: source_release.clone(),
                },
                result: SymbolResult::Failed(err.to_string()),
                source_release,
            }),
        }
    }

    raw
}

fn kernel_release_from_path(path: &Path) -> Option<String> {
    if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
        if let Some(release) = name.strip_prefix("System.map-") {
            if !release.is_empty() {
                return Some(release.to_string());
            }
        }
    }

    let components: Vec<String> = path
        .components()
        .filter_map(|component| component.as_os_str().to_str().map(str::to_string))
        .collect();
    if let Some(index) = components
        .iter()
        .position(|part| part.as_str() == "modules")
    {
        if let Some(release) = components.get(index + 1) {
            if !release.is_empty() {
                return Some(release.clone());
            }
        }
    }

    if let Ok(target) = fs::canonicalize(path) {
        if target.as_path() != path {
            return kernel_release_from_path(&target);
        }
    }
    None
}

fn find_symbol_in_reader(file: fs::File, target: &str) -> io::Result<Option<u64>> {
    let reader = io::BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        let mut parts = line.split_whitespace();
        let address = match parts.next() {
            Some(value) => value,
            None => continue,
        };
        let _symbol_type = parts.next();
        let symbol = match parts.next() {
            Some(value) => value,
            None => continue,
        };
        if symbol == target {
            return Ok(Some(u64::from_str_radix(address, 16).unwrap_or(0)));
        }
    }
    Ok(None)
}

fn find_symbol_in_text(content: &str, target: &str) -> Option<u64> {
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let address = match parts.next() {
            Some(value) => value,
            None => continue,
        };
        let _symbol_type = parts.next();
        let symbol = match parts.next() {
            Some(value) => value,
            None => continue,
        };
        if symbol == target {
            return Some(u64::from_str_radix(address, 16).unwrap_or(0));
        }
    }
    None
}

/// One immutable kernel evidence generation shared by all kernel scanners.
#[derive(Clone, Debug)]
pub struct KernelEvidence {
    pub paths: EvidencePaths,
    pub generation: CollectionGeneration,
    pub modules: ModuleSources,
    pub taint: TaintEvidence,
    pub symbols: Vec<SymbolEvidence>,
    /// True only for a generation installed by [`begin_scan_with`].
    pub installed: bool,
}

/// Compatibility aliases for front ends that call the shared snapshot a boot
/// observation or an evidence generation.
pub type BootObservation = KernelEvidence;
pub type EvidenceGeneration = CollectionGeneration;
pub type KernelGeneration = CollectionGeneration;
pub type Generation = CollectionGeneration;

impl KernelEvidence {
    /// Alias for [`begin_scan`] for callers that prefer the type namespace.
    pub fn begin_scan() -> Arc<Self> {
        crate::kernel_evidence::begin_scan()
    }

    /// Alias for [`begin_scan_with`].
    pub fn begin_scan_with(paths: EvidencePaths) -> Arc<Self> {
        crate::kernel_evidence::begin_scan_with(paths)
    }

    /// Alias for [`begin_scan_pinned`].
    pub fn begin_scan_pinned(paths: EvidencePaths) -> Arc<Self> {
        crate::kernel_evidence::begin_scan_pinned(paths)
    }

    /// Alias for [`current`].
    pub fn active() -> Option<Arc<Self>> {
        crate::kernel_evidence::current()
    }

    /// Alias for [`finish_scan`].
    pub fn finish_scan() {
        crate::kernel_evidence::finish_scan()
    }

    /// Collect a standalone generation without installing it as the active one.
    pub fn collect(paths: EvidencePaths) -> Self {
        let round = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
        let started_unix_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let boot_id = read_trim(&paths.boot_id_path()).unwrap_or_else(|_| UNKNOWN.to_string());
        let (kernel_release, release_error) = match read_trim(&paths.osrelease_path()) {
            Ok(value) => (normalize_release(&value), None),
            Err(err) => (UNKNOWN.to_string(), Some(err.to_string())),
        };
        let boot_time_unix_secs = read_boot_time(&paths.stat_path());

        let mut modules = ModuleSources::collect(&paths);
        let (module_fingerprint, module_count) = modules.module_fingerprint();

        let raw_symbols = collect_raw_symbols(
            &paths,
            &kernel_release,
            release_error.as_deref(),
            &modules.kallsyms_raw,
        );
        let mut symbol_sources: Vec<String> = raw_symbols
            .iter()
            .map(|symbol| symbol.source.label())
            .collect();
        symbol_sources.sort();
        symbol_sources.dedup();
        let mut source_identity: Vec<String> = raw_symbols
            .iter()
            .map(|symbol| {
                format!(
                    "{}@{}",
                    symbol.source.label(),
                    symbol.source_release.as_deref().unwrap_or(UNKNOWN)
                )
            })
            .collect();
        let symbol_source_fingerprint = fingerprint_labels(&mut source_identity);

        let mut generation = CollectionGeneration {
            boot_id,
            kernel_release,
            boot_time_unix_secs,
            module_fingerprint: module_fingerprint.unwrap_or_else(|| UNKNOWN.to_string()),
            module_count,
            symbol_source_fingerprint,
            symbol_sources,
            taint_value: None,
            round,
            started_unix_ns,
            pid: std::process::id(),
        };

        let mut taint = TaintEvidence::collect(&paths, &modules, &generation);
        generation.taint_value = taint.value.as_ref().ok().copied();
        modules.generation = Some(generation.clone());
        taint.generation = Some(generation.clone());
        let symbols = raw_symbols
            .into_iter()
            .map(|raw| SymbolEvidence {
                source: raw.source,
                result: raw.result,
                source_release: raw.source_release,
                generation: generation.clone(),
            })
            .collect();

        Self {
            paths,
            generation,
            modules,
            taint,
            symbols,
            installed: false,
        }
    }

    /// Collect a standalone generation from the process environment.
    pub fn collect_default() -> Self {
        Self::collect(EvidencePaths::from_env())
    }

    /// Alias for [`Self::collect`] used by fixture-driven front ends.
    pub fn collect_with(paths: EvidencePaths) -> Self {
        Self::collect(paths)
    }

    /// Alias for [`Self::collect`].
    pub fn new(paths: EvidencePaths) -> Self {
        Self::collect(paths)
    }

    pub fn module_sources(&self) -> &ModuleSources {
        &self.modules
    }

    pub fn taint(&self) -> &TaintEvidence {
        &self.taint
    }

    pub fn symbols(&self) -> &[SymbolEvidence] {
        &self.symbols
    }

    pub fn paths(&self) -> &EvidencePaths {
        &self.paths
    }

    pub fn generation(&self) -> &CollectionGeneration {
        &self.generation
    }

    pub fn boot_id(&self) -> &str {
        &self.generation.boot_id
    }

    pub fn kernel_release(&self) -> &str {
        &self.generation.kernel_release
    }

    pub fn module_fingerprint(&self) -> &str {
        &self.generation.module_fingerprint
    }

    pub fn symbol_sources(&self) -> &[String] {
        &self.generation.symbol_sources
    }

    pub fn cross_generation_evidence(&self) -> usize {
        self.report().cross_generation_evidence
    }

    /// Module evidence was stamped with this exact generation.
    pub fn module_sources_current(&self) -> bool {
        self.modules
            .generation
            .as_ref()
            .map_or(true, |generation| {
                generation.same_generation(&self.generation)
            })
    }

    /// Taint evidence was stamped with this exact generation.
    pub fn taint_current(&self) -> bool {
        self.taint
            .generation
            .as_ref()
            .map_or(true, |generation| {
                generation.same_generation(&self.generation)
            })
    }

    /// Every module, taint and symbol record belongs to this exact generation
    /// and no symbol source points at another kernel release.
    pub fn all_evidence_same_generation(&self) -> bool {
        self.module_sources_current()
            && self.taint_current()
            && self.symbols.iter().all(|symbol| {
                symbol.generation.same_generation(&self.generation)
                    && symbol.foreign_release_reason(&self.generation).is_none()
            })
    }

    /// Complete module set names (empty when no source was readable).
    pub fn module_set(&self) -> BTreeSet<String> {
        self.modules.all_names()
    }

    pub fn module_set_known(&self) -> bool {
        self.generation.module_count.is_some()
    }

    /// Cheap revalidation of the host identity against the same roots.
    ///
    /// Unreadable identity files keep the existing generation instead of
    /// turning a permission error into a synthetic reboot.
    pub fn boot_identity_matches(&self, paths: &EvidencePaths) -> bool {
        let boot_id = match read_trim(&paths.boot_id_path()) {
            Ok(value) => value,
            Err(_) => return true,
        };
        let kernel_release = match read_trim(&paths.osrelease_path()) {
            Ok(value) => normalize_release(&value),
            Err(_) => return true,
        };
        boot_id == self.generation.boot_id
            && kernel_release == self.generation.kernel_release
    }

    /// Cheaply revalidate the two live module inventories.  A failed read is
    /// left to the existing generation so a permission error does not look
    /// like a reboot; a changed set starts a fresh generation.
    pub fn module_lists_match(&self, paths: &EvidencePaths) -> bool {
        match fs::read_to_string(paths.proc_modules_path()) {
            Ok(content) => {
                let (current, _) = parse_proc_modules(&content);
                match (&current, &self.modules.proc_modules) {
                    (Ok(current), Ok(stored)) if current == stored => {}
                    (Ok(_), Ok(_)) => return false,
                    (Ok(_), Err(_)) => return false,
                    (Err(_), _) => {}
                }
            }
            Err(_) => {}
        }

        match read_sysfs_modules(&paths.sys_module_path()) {
            Ok(current) => match &self.modules.sysfs_modules {
                Ok(stored) if &current == stored => {}
                Ok(_) => return false,
                Err(_) => return false,
            },
            Err(_) => {}
        }
        true
    }

    /// Revalidate the taint value without turning a permission failure into a
    /// synthetic change.
    pub fn taint_value_matches(&self, paths: &EvidencePaths) -> bool {
        let current = match fs::read_to_string(paths.tainted_path()) {
            Ok(raw) => raw.trim().parse::<u64>().ok(),
            Err(_) => None,
        };
        match current {
            Some(current) => match &self.taint.value {
                Ok(stored) => *stored == current,
                Err(_) => false,
            },
            None => true,
        }
    }

    /// The snapshot still describes the host it was collected from.
    pub fn host_still_matches(&self) -> bool {
        self.boot_identity_matches(&self.paths)
            && self.module_lists_match(&self.paths)
            && self.taint_value_matches(&self.paths)
    }

    /// Reason the installed generation has been superseded, if any.
    ///
    /// Standalone generations are never considered stale.  An installed
    /// generation is stale unless the active observation describes the same
    /// boot, release, module set and symbol-source set; a reboot or source
    /// switch cannot republish the previous observation's records.
    pub fn staleness(&self) -> Option<String> {
        if !self.installed {
            return None;
        }
        let active = current()?;
        if active.generation.same_generation(&self.generation) {
            None
        } else {
            Some(format!(
                "stale_generation evidence_generation={} active_generation={}",
                self.generation.label(),
                active.generation.label()
            ))
        }
    }

    /// Scanner-compatible `unknown` line for superseded evidence.
    pub fn unknown_outcome(&self, collector: &str) -> Option<String> {
        self.staleness().map(|reason| {
            format!(
                "collector={} state=unknown reason={} boot_id={} kernel_release={}",
                collector, reason, self.generation.boot_id, self.generation.kernel_release
            )
        })
    }

    /// Count evidence that belongs to the same generation and evidence that
    /// must be rejected (different stamp or different kernel release).
    pub fn report(&self) -> KernelEvidenceReport {
        let mut merge = GenerationMerge::default();
        match &self.modules.generation {
            Some(generation) => merge.offer(&self.generation, generation),
            None => merge.accept(),
        }
        match &self.taint.generation {
            Some(generation) => merge.offer(&self.generation, generation),
            None => merge.accept(),
        }
        for symbol in &self.symbols {
            if symbol.generation.same_generation(&self.generation) {
                if !matches!(&symbol.result, SymbolResult::Failed(_))
                    && symbol
                        .foreign_release_reason(&self.generation)
                        .is_some()
                {
                    merge.reject(&symbol.label());
                } else {
                    merge.accept();
                }
            } else {
                merge.reject(&symbol.label());
            }
        }

        let stale = self.staleness().is_some();
        let host_moved = !self.host_still_matches();
        let unverified = self
            .symbols
            .iter()
            .filter(|symbol| symbol.is_unverified_release())
            .count();
        let state = if stale || host_moved {
            "STALE"
        } else if merge.rejected > 0 {
            "FOREIGN_SOURCE"
        } else if self.generation.boot_identity_known()
            && self.generation.module_count.is_some()
            && self.taint.value.is_ok()
        {
            "CURRENT"
        } else {
            "UNKNOWN"
        };
        let failure_stage = if merge.rejected > 0 {
            "symbol_generation"
        } else {
            failure_stage(self)
        };

        KernelEvidenceReport {
            generation: self.generation.clone(),
            accepted_evidence: merge.accepted,
            rejected_evidence: merge.rejected,
            cross_generation_evidence: merge.rejected,
            unverified_symbol_sources: unverified,
            permission_errors: permission_error_count(self),
            mixed_boot: false,
            stale,
            host_moved,
            failure_stage,
            state,
            rejected_sources: merge.rejected_sources,
        }
    }

    /// Human-readable one-line summary printed once after the scanner loop.
    pub fn summary(&self) -> String {
        let report = self.report();
        let module_count = match self.generation.module_count {
            Some(count) => count.to_string(),
            None => UNKNOWN.to_string(),
        };
        let module_sources = format!(
            "proc_modules={},sysfs={},kallsyms={}",
            source_state(&self.modules.proc_modules),
            source_state(&self.modules.sysfs_modules),
            source_state(&self.modules.kallsyms_modules),
        );
        let symbol_sources = if self.generation.symbol_sources.is_empty() {
            "none".to_string()
        } else {
            self.generation.symbol_sources.join("|")
        };
        let failure_stage = report.failure_stage;
        let module_generation = generation_state(self.module_sources_current());
        let taint_generation = generation_state(self.taint_current());
        let taint_value = self
            .generation
            .taint_value
            .map(|value| value.to_string())
            .unwrap_or_else(|| UNKNOWN.to_string());
        let permission_errors = permission_error_count(self);
        let empty_modules = matches!(self.generation.module_count, Some(0));
        let module_set_known = self.generation.module_count.is_some();
        let host_matches = !report.host_moved;
        let rejected_sources = if report.rejected_sources.is_empty() {
            "none".to_string()
        } else {
            report.rejected_sources.join("|")
        };

        format!(
            "KERNEL_EVIDENCE boot_id={} kernel_release={} module_count={} module_set={} empty_modules={} module_set_known={} module_fingerprint={} taint_value={} symbol_source={} symbol_sources={} symbol_source_fingerprint={} unverified_symbol_sources={} generation={} generation_round={} host_matches={} module_sources={} module_generation={} taint_generation={} failure_stage={} permission_errors={} cross_generation_evidence={} rejected_sources={} rejected_evidence={} mixed_boot={} state={}",
            self.generation.boot_id,
            self.generation.kernel_release,
            module_count,
            module_count,
            empty_modules,
            module_set_known,
            self.generation.module_fingerprint,
            taint_value,
            symbol_sources,
            symbol_sources,
            self.generation.symbol_source_fingerprint,
            report.unverified_symbol_sources,
            self.generation.label(),
            self.generation.round,
            host_matches,
            module_sources,
            module_generation,
            taint_generation,
            failure_stage,
            permission_errors,
            report.cross_generation_evidence,
            rejected_sources,
            report.rejected_evidence,
            report.mixed_boot,
            report.state,
        )
    }
}

fn source_state<T>(source: &Result<T, String>) -> &'static str {
    match source {
        Ok(_) => "ok",
        Err(_) => "failed",
    }
}

/// `PermissionDenied`, EACCES and EPERM stay in the original error text; the
/// summary only counts them so a partially readable source is visible.
fn is_permission_denied(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("permission denied")
        || message.contains("operation not permitted")
        || message.contains("permissiondenied")
}

fn permission_error_count(evidence: &KernelEvidence) -> usize {
    let mut count = 0;
    for source in [
        &evidence.modules.proc_modules,
        &evidence.modules.sysfs_modules,
        &evidence.modules.kallsyms_modules,
    ] {
        if let Err(err) = source {
            if is_permission_denied(err) {
                count += 1;
            }
        }
    }
    if let Err(err) = &evidence.taint.value {
        if is_permission_denied(err) {
            count += 1;
        }
    }
    if let Err(err) = &evidence.taint.module_letters {
        if is_permission_denied(err) {
            count += 1;
        }
    }
    count
        + evidence
            .modules
            .holder_errors
            .iter()
            .filter(|err| is_permission_denied(err.as_str()))
            .count()
        + evidence
            .symbols
            .iter()
            .filter(|symbol| match &symbol.result {
                SymbolResult::Failed(err) => is_permission_denied(err),
                _ => false,
            })
            .count()
}

fn generation_state(current: bool) -> &'static str {
    if current {
        "current"
    } else {
        "stale"
    }
}

fn failure_stage(evidence: &KernelEvidence) -> &'static str {
    if evidence.modules.proc_modules.is_err()
        || evidence.modules.sysfs_modules.is_err()
        || evidence.modules.kallsyms_modules.is_err()
        || !evidence.modules.holder_errors.is_empty()
    {
        return "module_collection";
    }
    if evidence.taint.value.is_err() || evidence.taint.module_letters.is_err() {
        return "taint_collection";
    }
    if evidence
        .symbols
        .iter()
        .any(|symbol| matches!(&symbol.result, SymbolResult::Failed(_)))
    {
        return "symbol_lookup";
    }
    "none"
}

/// Counts produced from one generation's stamps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelEvidenceReport {
    pub generation: CollectionGeneration,
    pub accepted_evidence: usize,
    pub rejected_evidence: usize,
    pub cross_generation_evidence: usize,
    pub unverified_symbol_sources: usize,
    pub permission_errors: usize,
    pub mixed_boot: bool,
    pub stale: bool,
    pub host_moved: bool,
    pub failure_stage: &'static str,
    pub state: &'static str,
    pub rejected_sources: Vec<String>,
}

/// Simple generation fence used by [`KernelEvidence::report`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GenerationMerge {
    pub accepted: usize,
    pub rejected: usize,
    pub rejected_sources: Vec<String>,
}

impl GenerationMerge {
    pub fn offer(&mut self, current: &CollectionGeneration, offered: &CollectionGeneration) {
        if current.same_generation(offered) {
            self.accepted += 1;
        } else {
            self.rejected += 1;
        }
    }

    pub fn accept(&mut self) {
        self.accepted += 1;
    }

    pub fn reject(&mut self, source: &str) {
        self.rejected += 1;
        self.rejected_sources.push(source.to_string());
    }
}

/// Compare an offered generation with the current one.
pub fn same_generation(
    current: &CollectionGeneration,
    offered: &CollectionGeneration,
) -> bool {
    current.same_generation(offered)
}

/// Reject foreign symbol sources and stale evidence before the report.
pub fn final_scan_outcome(evidence: &KernelEvidence) -> crate::ScanOutcome {
    if let Some(stale) = evidence.staleness() {
        return Ok(Some(format!(
            "collector=kernel_evidence state=unknown reason={stale}"
        )));
    }

    let mut lines = Vec::new();

    if !evidence.host_still_matches() {
        lines.push(format!(
            "collector=kernel_evidence state=unknown reason=host_changed_during_scan boot_id={} kernel_release={} generation={}",
            evidence.generation.boot_id,
            evidence.generation.kernel_release,
            evidence.generation.label()
        ));
    }

    if !evidence.generation.boot_identity_known() {
        // Do not claim a clean boot when the boot id or kernel release was
        // unreadable.
        lines.push(format!(
            "collector=kernel_evidence state=unknown reason=boot_identity_unavailable boot_id={} kernel_release={}",
            evidence.generation.boot_id, evidence.generation.kernel_release
        ));
    }

    if evidence.generation.module_count.is_none() {
        lines.push(format!(
            "collector=kernel_evidence state=unknown reason=module_set_incomplete boot_id={} kernel_release={}",
            evidence.generation.boot_id, evidence.generation.kernel_release
        ));
    }

    if evidence.taint.value.is_err() {
        lines.push(format!(
            "collector=kernel_evidence state=unknown reason=taint_value_unavailable boot_id={} kernel_release={}",
            evidence.generation.boot_id, evidence.generation.kernel_release
        ));
    }
    if matches!(&evidence.taint.value, Ok(value) if *value != 0)
        && evidence.taint.module_letters.is_err()
    {
        lines.push(format!(
            "collector=kernel_evidence state=unknown reason=taint_module_evidence_unavailable boot_id={} kernel_release={}",
            evidence.generation.boot_id, evidence.generation.kernel_release
        ));
    }

    if !evidence.module_sources_current() {
        lines.push(format!(
            "source=module_set issue=stale_generation current_generation={}",
            evidence.generation.label()
        ));
    }
    if !evidence.taint_current() {
        lines.push(format!(
            "source=kernel_taint issue=stale_generation current_generation={}",
            evidence.generation.label()
        ));
    }
    for symbol in &evidence.symbols {
        if !matches!(&symbol.result, SymbolResult::Failed(_)) {
            if let Some(reason) = symbol.foreign_release_reason(&evidence.generation) {
                lines.push(reason);
            }
        }
    }
    if lines.is_empty() {
        Ok(None)
    } else {
        Ok(Some(lines.join("\n")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::{
        hidden_lkm, kernel_taint, module_list_linkage_tamper, syscall_table,
    };

    static NEXT_TEST: AtomicU64 = AtomicU64::new(1);
    static ACTIVE_TEST: Mutex<()> = Mutex::new(());

    struct Fixture {
        root: PathBuf,
        paths: EvidencePaths,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let root = env::temp_dir().join(format!(
                "ghostscan-kernel-evidence-{}-{}-{}",
                std::process::id(),
                name,
                NEXT_TEST.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join("proc/sys/kernel/random")).unwrap();
            fs::create_dir_all(root.join("sys/module")).unwrap();
            let paths = EvidencePaths::new(root.join("proc"), root.join("sys"))
                .with_system_maps(Vec::new());
            Self { root, paths }
        }

        fn write(&self, relative: &str, content: &str) {
            let path = self.root.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, content).unwrap();
        }

        fn mkdir(&self, relative: &str) {
            fs::create_dir_all(self.root.join(relative)).unwrap();
        }

        fn boot(&self, boot_id: &str, release: &str) {
            self.write(
                "proc/sys/kernel/random/boot_id",
                &format!("{boot_id}\n"),
            );
            self.write("proc/sys/kernel/osrelease", &format!("{release}\n"));
            self.write("proc/stat", "cpu 0 0 0 0 0 0 0 0\nbtime 1000\n");
        }

        fn map(&self, relative: &str, address: &str) -> PathBuf {
            self.write(
                relative,
                &format!("{address} T sys_call_table\n"),
            );
            self.root.join(relative)
        }

        fn with_maps(&self, maps: Vec<PathBuf>) -> EvidencePaths {
            self.paths.clone().with_system_maps(maps)
        }

        fn collect(&self) -> KernelEvidence {
            KernelEvidence::collect(self.paths.clone())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn empty_module_set_is_complete_evidence() {
        let fixture = Fixture::new("empty");
        fixture.boot("boot-empty", "6.1.0-test");
        fixture.write("proc/modules", "");
        fixture.write("proc/sys/kernel/tainted", "0\n");
        fixture.write(
            "proc/kallsyms",
            "ffffffff81000000 T sys_call_table\n",
        );

        let evidence = fixture.collect();
        assert_eq!(evidence.generation.module_count, Some(0));
        assert_ne!(evidence.generation.module_fingerprint, UNKNOWN);
        assert_eq!(hidden_lkm::run_with_evidence(&evidence).unwrap(), None);
        assert_eq!(syscall_table::run_with_evidence(&evidence).unwrap(), None);
        assert_eq!(final_scan_outcome(&evidence).unwrap(), None);
    }

    #[test]
    fn reboot_creates_a_distinct_generation_and_merge_rejects_it() {
        let first = Fixture::new("reboot-a");
        first.boot("boot-a", "6.1.0-test");
        first.write("proc/modules", "ghost 1 0 - Live 0x0 (O)\n");
        first.mkdir("sys/module/ghost");
        first.write(
            "proc/kallsyms",
            "ffffffff81000000 T sys_call_table\nffffffff81001000 t ghost_fn [ghost]\n",
        );
        let first_map = first.map("boot/System.map-6.1.0-test", "ffffffff81000000");
        let old = KernelEvidence::collect(first.with_maps(vec![first_map]));

        let second = Fixture::new("reboot-b");
        second.boot("boot-b", "6.2.0-test");
        second.write("proc/modules", "other 1 0 - Live 0x0 (O)\n");
        second.mkdir("sys/module/other");
        second.write(
            "proc/kallsyms",
            "ffffffff82000000 T sys_call_table\n",
        );
        let second_map = second.map("boot/System.map-6.2.0-test", "ffffffff82000000");
        let new = KernelEvidence::collect(second.with_maps(vec![second_map]));

        assert!(!old.generation.same_boot(&new.generation));
        assert!(!old.generation.same_collection(&new.generation));
        assert_ne!(
            old.generation.module_fingerprint,
            new.generation.module_fingerprint
        );

        let mut merge = GenerationMerge::default();
        merge.offer(&new.generation, &old.generation);
        assert_eq!(merge.rejected, 1);

        let output = hidden_lkm::run_with_evidence(&new)
            .unwrap()
            .unwrap_or_default();
        assert!(!output.contains("ghost"));
    }

    #[test]
    fn source_switch_to_another_release_is_not_joined() {
        let fixture = Fixture::new("foreign-map");
        fixture.boot("boot-new", "6.2.0-new");
        fixture.write("proc/modules", "");
        fixture.write(
            "proc/kallsyms",
            "ffffffff81000000 T sys_call_table\n",
        );
        let foreign = fixture.map("boot/System.map-6.1.0-old", "ffffffff82000000");

        let evidence = KernelEvidence::collect(fixture.with_maps(vec![foreign]));
        assert_eq!(evidence.report().cross_generation_evidence, 1);

        let output = syscall_table::run_with_evidence(&evidence)
            .unwrap()
            .unwrap_or_default();
        assert!(output.contains("foreign_kernel_release"));
        assert!(!output.contains("0xffffffff82000000"));
        assert!(!output.contains("inconsistent_addresses"));
    }

    #[test]
    fn permission_and_missing_source_text_is_preserved() {
        let fixture = Fixture::new("permission");
        fixture.boot("boot-permission", "6.1.0-test");
        fixture.mkdir("sys/module/kept");
        fixture.write(
            "proc/kallsyms",
            "ffffffff81000000 T sys_call_table\n",
        );
        let evidence = fixture.collect();
        assert_eq!(evidence.generation.module_count, None);

        let hidden = hidden_lkm::run_with_evidence(&evidence)
            .unwrap()
            .unwrap_or_default();
        assert!(hidden.contains("collection_errors=proc_modules:"));

        let taint = kernel_taint::run_with_evidence(&evidence).unwrap_err();
        assert!(taint.contains("failed to read /proc/sys/kernel/tainted"));

        let linkage = module_list_linkage_tamper::run_with_evidence(&evidence).unwrap_err();
        assert!(linkage.contains("/proc/modules:"));
    }

    #[test]
    fn module_and_symbol_order_do_not_change_the_generation() {
        let fixture = Fixture::new("order");
        fixture.boot("boot-order", "6.1.0-test");
        fixture.write(
            "proc/modules",
            "alpha 1 0 - Live 0x0 (O)\nbeta 1 0 - Live 0x0 (O)\n",
        );
        fixture.write(
            "proc/kallsyms",
            "ffffffff81000000 T sys_call_table\nffffffff81001000 t a [alpha]\n",
        );
        let first = fixture.map("maps-a/System.map-6.1.0-test", "ffffffff81000000");
        let second = fixture.map("maps-b/System.map-6.1.0-test", "ffffffff81000000");

        let one = KernelEvidence::collect(fixture.with_maps(vec![
            first.clone(),
            second.clone(),
        ]));
        let two = KernelEvidence::collect(fixture.with_maps(vec![second, first]));

        assert_eq!(
            one.generation.symbol_source_fingerprint,
            two.generation.symbol_source_fingerprint
        );
        assert_eq!(
            one.generation.module_fingerprint,
            two.generation.module_fingerprint
        );
        assert!(one.generation.same_collection(&two.generation));
    }

    #[test]
    fn equivalent_release_whitespace_does_not_change_the_generation() {
        let fixture = Fixture::new("release-whitespace");
        fixture.boot("boot-whitespace", "6.1.0-test");
        fixture.write("proc/modules", "");
        fixture.write(
            "proc/kallsyms",
            "ffffffff81000000 T sys_call_table\n",
        );

        let one = fixture.collect();
        fixture.write("proc/sys/kernel/osrelease", "  6.1.0-test  \n");
        let two = fixture.collect();
        assert_eq!(one.generation.kernel_release, "6.1.0-test");
        assert!(one.generation.same_boot(&two.generation));
        assert!(one.generation.same_collection(&two.generation));
        assert!(one.generation.same_generation(&two.generation));
        assert!(!one.generation.same_attempt(&two.generation));
    }

    #[test]
    fn module_linkage_consumer_reads_the_shared_snapshot() {
        let fixture = Fixture::new("linkage");
        fixture.boot("boot-linkage", "6.1.0-test");
        fixture.write(
            "proc/modules",
            "ghost 1 0 - Live 0x0 (O)\n",
        );
        fixture.mkdir("sys/module/other");
        fixture.write("sys/module/other/holders/other", "");
        fixture.write(
            "proc/kallsyms",
            "ffffffff81000000 T sys_call_table\n",
        );

        let evidence = fixture.collect();
        let output = module_list_linkage_tamper::run_with_evidence(&evidence)
            .unwrap()
            .unwrap_or_default();
        assert!(output.contains("module_name=ghost"));
        assert!(output.contains("anomaly=null_gap"));
        assert!(output.contains("module_name=other"));
        assert!(output.contains("anomaly=self_loop"));
    }

    #[test]
    fn taint_consumer_uses_the_same_module_generation() {
        let fixture = Fixture::new("taint");
        fixture.boot("boot-taint", "6.1.0-test");
        fixture.write("proc/modules", "evil 1 0 - Live 0x0 (E)\n");
        fixture.write("sys/module/evil/taint", "E\n");
        fixture.write("proc/sys/kernel/tainted", "1\n");
        fixture.write(
            "proc/kallsyms",
            "ffffffff81000000 T sys_call_table\nffffffff81001000 t evil [evil]\n",
        );

        let evidence = fixture.collect();
        let output = kernel_taint::run_with_evidence(&evidence)
            .unwrap()
            .unwrap_or_default();
        assert!(output.contains("tainted=1"));
        assert!(output.contains("missing_module_flags=P"));
        assert!(output.contains("E -> evil"));
    }

    #[test]
    fn same_release_symbol_mismatch_keeps_the_old_risk_report() {
        let fixture = Fixture::new("mismatch");
        fixture.boot("boot-mismatch", "6.1.0-test");
        fixture.write("proc/modules", "");
        fixture.write(
            "proc/kallsyms",
            "ffffffff81000000 T sys_call_table\n",
        );
        let map = fixture.map("boot/System.map-6.1.0-test", "ffffffff82000000");

        let evidence = KernelEvidence::collect(fixture.with_maps(vec![map]));
        let output = syscall_table::run_with_evidence(&evidence)
            .unwrap()
            .unwrap_or_default();
        assert!(output.contains("inconsistent_addresses"));
        assert!(output.contains("0xffffffff81000000"));
        assert!(output.contains("0xffffffff82000000"));
    }

    #[test]
    fn superseded_installed_generation_publishes_unknown_not_old_modules() {
        let _guard = ACTIVE_TEST
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        clear();

        let first = Fixture::new("stale-a");
        first.boot("boot-stale-a", "6.1.0-test");
        first.write("proc/modules", "oldmod 1 0 - Live 0x0 (O)\n");
        first.mkdir("sys/module/oldmod");
        first.write(
            "proc/kallsyms",
            "ffffffff81000000 T sys_call_table\nffffffff81001000 t old [oldmod]\n",
        );
        let old = begin_scan_with(first.paths.clone());

        let second = Fixture::new("stale-b");
        second.boot("boot-stale-b", "6.2.0-test");
        second.write("proc/modules", "newmod 1 0 - Live 0x0 (O)\n");
        second.mkdir("sys/module/newmod");
        second.write(
            "proc/kallsyms",
            "ffffffff82000000 T sys_call_table\nffffffff82001000 t new [newmod]\n",
        );
        let _new = begin_scan_with(second.paths.clone());

        let output = hidden_lkm::run_with_evidence(&old)
            .unwrap()
            .unwrap_or_default();
        assert!(output.contains("state=unknown"));
        assert!(!output.contains("oldmod"));

        let addresses = syscall_table::run_with_evidence(&old)
            .unwrap()
            .unwrap_or_default();
        assert!(addresses.contains("state=unknown"));
        assert!(!addresses.contains("0xffffffff81000000"));

        clear();
    }

    #[test]
    fn a_changed_fake_boot_is_revalidated_before_the_next_scanner() {
        let _guard = ACTIVE_TEST
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        clear();

        let fixture = Fixture::new("refresh");
        fixture.boot("boot-refresh-a", "6.1.0-test");
        fixture.write("proc/modules", "oldmod 1 0 - Live 0x0 (O)\n");
        fixture.mkdir("sys/module/oldmod");
        fixture.write(
            "proc/kallsyms",
            "ffffffff81000000 T sys_call_table\nffffffff81001000 t old [oldmod]\n",
        );
        let _old = begin_scan_with(fixture.paths.clone());

        fixture.boot("boot-refresh-b", "6.2.0-test");
        fixture.write("proc/modules", "newmod 1 0 - Live 0x0 (O)\n");
        fixture.mkdir("sys/module/newmod");
        fixture.write(
            "proc/kallsyms",
            "ffffffff82000000 T sys_call_table\nffffffff82001000 t new [newmod]\n",
        );

        let output = hidden_lkm::run().unwrap().unwrap_or_default();
        assert!(!output.contains("oldmod"));
        let active = current().expect("scanner should install the refreshed generation");
        assert_eq!(active.boot_id(), "boot-refresh-b");
        assert_eq!(active.kernel_release(), "6.2.0-test");

        clear();
    }

    #[test]
    fn a_pinned_full_scan_never_mixes_a_mid_scan_reboot() {
        let _guard = ACTIVE_TEST
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        clear();

        let fixture = Fixture::new("pinned");
        fixture.boot("boot-pinned-a", "6.1.0-test");
        fixture.write("proc/modules", "oldmod 1 0 - Live 0x0 (O)\n");
        fixture.mkdir("sys/module/oldmod");
        fixture.write("proc/sys/kernel/tainted", "0\n");
        fixture.write(
            "proc/kallsyms",
            "ffffffff81000000 T sys_call_table\nffffffff81001000 t old [oldmod]\n",
        );
        let snapshot = begin_scan_pinned(fixture.paths.clone());

        fixture.boot("boot-pinned-b", "6.2.0-test");
        fixture.write("proc/modules", "newmod 1 0 - Live 0x0 (O)\n");
        fixture.mkdir("sys/module/newmod");
        fixture.write(
            "proc/kallsyms",
            "ffffffff82000000 T sys_call_table\nffffffff82001000 t new [newmod]\n",
        );

        // The scanner stays on the pinned generation; it must not pick up the
        // new boot halfway through the report.
        let output = hidden_lkm::run().unwrap().unwrap_or_default();
        assert!(!output.contains("newmod"));
        assert!(snapshot.report().host_moved);
        let verdict = final_scan_outcome(&snapshot)
            .unwrap()
            .unwrap_or_default();
        assert!(verdict.contains("host_changed_during_scan"));
        assert!(verdict.contains("state=unknown"));

        clear();
    }
}

