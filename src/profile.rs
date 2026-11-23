//! One profile transaction for the whole scan startup.
//!
//! A ghostscan run is described by a profile: the ordered scanner set, the
//! permission rules attached to those scanners and the startup records that
//! say which profile actually served a run.  Keeping those three things in
//! separate files (or applying them one after another) lets an interrupted
//! migration leave a process running the old scanner set with a few new rules
//! attached.  This module makes the selection explicit and atomic:
//!
//! * a profile is loaded, validated and (when necessary) migrated while a
//!   store lock is held,
//! * the migrated profile and the startup record are written with one
//!   temporary-file + `fsync` + `rename` transaction,
//! * the scanner loop only receives the ordered scanner set from the committed
//!   snapshot,
//! * a failed migration never installs a partial profile: the default policy
//!   refuses to start, and the explicit legacy policy uses the complete old
//!   profile (never a mix of old scanners and new rules),
//! * an unknown profile name or version is refused before any scanner runs.
//!
//! Compatibility is deliberate:
//!
//! * old scanner names are retained as legacy aliases even after the new
//!   profile version stops scheduling them,
//! * scanners without a permission rule still run and keep their original
//!   permission errors; the transaction reports the rule as missing instead of
//!   inventing one,
//! * scanner ordering is validated instead of being silently sorted, so the
//!   registry order and any old profile order that is still valid are kept,
//! * permission-denied errors are recorded verbatim and are never turned into
//!   a clean result.

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::io::AsRawFd,
    path::{Path, PathBuf},
    process,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

/// Version written by the current profile schema.
pub const CURRENT_PROFILE_VERSION: u32 = 2;
/// First profile schema.  Version one profiles are migrated at startup.
pub const LEGACY_PROFILE_VERSION: u32 = 1;
/// Short alias used by reports and compatibility checks.
pub const PROFILE_VERSION: u32 = CURRENT_PROFILE_VERSION;
/// Version of the on-disk container that stores all named profiles.
pub const PROFILE_FORMAT_VERSION: u32 = 1;

/// Built-in profile used when the host has not selected another profile.
pub const DEFAULT_PROFILE_NAME: &str = "default";
/// Built-in version-one profile used to exercise and recover migrations.
pub const LEGACY_PROFILE_NAME: &str = "legacy";

/// File and lock names inside the profile directory.
pub const PROFILE_FILE: &str = "profiles.json";
pub const PROFILE_LOCK_FILE: &str = "profiles.lock";

/// Keep the startup history bounded; the latest record is the one that matters
/// for the current transaction.
pub const MAX_STARTUP_RECORDS: usize = 32;

/// A scanner scheduled by the old profile version.  The name is known forever
/// as a legacy alias, but current profiles do not schedule it.
pub const REMOVED_SCANNERS: &[&str] = &["Legacy inode walker (removed in profile v2)"];

/// Additional names seen in older profile documents.  They are recognised so
/// an old profile can still be validated and migrated, but they are never
/// scheduled by the current profile version.
pub const LEGACY_SCANNER_ALIASES: &[&str] = &[
    "Legacy inode walker",
    "Legacy kernel symbol walker",
    "Hidden inode walker",
    "Legacy BPF syscall tracer",
];

fn is_retired_scanner(name: &str) -> bool {
    REMOVED_SCANNERS.iter().any(|removed| *removed == name)
        || LEGACY_SCANNER_ALIASES
            .iter()
            .any(|alias| *alias == name)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

static NEXT_TRANSACTION: AtomicU64 = AtomicU64::new(1);
static NEXT_TEMPORARY_FILE: AtomicU64 = AtomicU64::new(1);

// `flock` serializes different processes.  This mutex makes the same guarantee
// for transactions created concurrently inside one process (unit tests and
// embedded front ends).
static STORE_MUTEX: Mutex<()> = Mutex::new(());

fn hex(bytes: &[u8]) -> String {
    let mut rendered = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        rendered.push(HEX[(byte >> 4) as usize] as char);
        rendered.push(HEX[(byte & 0x0f) as usize] as char);
    }
    rendered
}

fn sha256_parts(parts: &[String]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update(b"\n");
    }
    let digest = hasher.finalize();
    hex(digest.as_slice())
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

fn boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|value| value.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn current_euid() -> u32 {
    if let Ok(value) = env::var("GHOSTSCAN_EUID") {
        if let Ok(parsed) = value.trim().parse::<u32>() {
            return parsed;
        }
    }
    // SAFETY: `geteuid` has no preconditions and does not touch memory owned by
    // the caller.
    unsafe { libc::geteuid() as u32 }
}

/// Stable generation label shared by the profile, every scanner start record
/// in this process and the final report.
fn generation_label() -> String {
    let round = NEXT_TRANSACTION.fetch_add(1, Ordering::Relaxed);
    format!("{}:{}:{}:{}", boot_id(), round, now_ns(), process::id())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileErrorKind {
    Io,
    Lock,
    Corrupt,
    UnknownProfile,
    UnknownVersion,
    UnknownScanner,
    DuplicateScanner,
    OrderingViolation,
    InvalidRule,
    MigrationFailed,
    CommitFailed,
}

impl ProfileErrorKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Io => "io",
            Self::Lock => "lock",
            Self::Corrupt => "corrupt",
            Self::UnknownProfile => "unknown_profile",
            Self::UnknownVersion => "unknown_version",
            Self::UnknownScanner => "unknown_scanner",
            Self::DuplicateScanner => "duplicate_scanner",
            Self::OrderingViolation => "ordering",
            Self::InvalidRule => "invalid_rule",
            Self::MigrationFailed => "migration_failed",
            Self::CommitFailed => "commit_failed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileError {
    pub kind: ProfileErrorKind,
    pub message: String,
}

impl ProfileError {
    pub fn new(kind: ProfileErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.kind.label(), self.message)
    }
}

impl std::error::Error for ProfileError {}

fn io_error(context: impl Into<String>, error: io::Error) -> ProfileError {
    ProfileError::new(ProfileErrorKind::Io, format!("{}: {error}", context.into()))
}

/// Ordered scanner set.  Ordering is part of the profile identity and is never
/// silently normalised.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ScannerSet {
    pub names: Vec<String>,
}

impl<'de> Deserialize<'de> for ScannerSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Representation {
            List(Vec<String>),
            Named { names: Vec<String> },
        }

        Ok(match Representation::deserialize(deserializer)? {
            Representation::List(names) => Self { names },
            Representation::Named { names } => Self { names },
        })
    }
}

impl ScannerSet {
    pub fn new<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            names: names.into_iter().map(Into::into).collect(),
        }
    }

    pub fn from_registry(registry: &[&str]) -> Self {
        Self::new(registry.iter().map(|name| (*name).to_string()))
    }

    pub fn contains(&self, name: &str) -> bool {
        self.names
            .iter()
            .any(|candidate| candidate.as_str() == name)
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    pub fn as_slice(&self) -> &[String] {
        &self.names
    }

    pub fn hash(&self) -> String {
        let parts: Vec<String> = self
            .names
            .iter()
            .map(|name| format!("scanner={name}"))
            .collect();
        sha256_parts(&parts)
    }
}

fn default_rule_since_version() -> u32 {
    LEGACY_PROFILE_VERSION
}

/// A permission rule attached to one scanner in a profile.
///
/// Rules are advisory at startup: a denied rule is reported and the scanner
/// still runs, so the scanner's original permission error remains visible.
/// A scanner without a rule is a supported state, not an error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionRule {
    pub scanner: String,
    pub rule: String,
    #[serde(default, alias = "root")]
    pub requires_root: bool,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default = "default_rule_since_version", alias = "since")]
    pub since_version: u32,
}

impl PermissionRule {
    pub fn id(&self) -> String {
        format!("{}:{}", self.scanner, self.rule)
    }
}

/// Persisted record of one startup.  It names the exact profile and scanner
/// set that served the run, so a report can prove it did not mix migrations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartupRecord {
    #[serde(default)]
    pub generation: String,
    #[serde(default)]
    pub profile: String,
    #[serde(default)]
    pub profile_version: u32,
    #[serde(default)]
    pub profile_hash: String,
    #[serde(default)]
    pub scanner_set_hash: String,
    #[serde(default)]
    pub scanner_names: Vec<String>,
    #[serde(default)]
    pub permission_rules_hash: String,
    #[serde(default)]
    pub permission_rule_ids: Vec<String>,
    #[serde(default)]
    pub scanner_count: usize,
    #[serde(default)]
    pub permission_rule_count: usize,
    #[serde(default)]
    pub permission_errors: usize,
    #[serde(default)]
    pub migration: String,
    #[serde(default)]
    pub started_unix_ns: u64,
    #[serde(default)]
    pub pid: u32,
}

/// A complete profile document.  `startup_records` is part of the same
/// document so a migration and its startup record are installed by one atomic
/// write.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileDocument {
    pub name: String,
    pub version: u32,
    #[serde(default, alias = "scanners")]
    pub scanner_set: ScannerSet,
    #[serde(default, alias = "rules")]
    pub permission_rules: Vec<PermissionRule>,
    #[serde(default, alias = "startup_log")]
    pub startup_records: Vec<StartupRecord>,
    #[serde(default)]
    pub legacy_scanner_names: Vec<String>,
}

impl Default for ProfileDocument {
    fn default() -> Self {
        Self {
            name: DEFAULT_PROFILE_NAME.to_string(),
            version: CURRENT_PROFILE_VERSION,
            scanner_set: ScannerSet::default(),
            permission_rules: Vec::new(),
            startup_records: Vec::new(),
            legacy_scanner_names: Vec::new(),
        }
    }
}

impl ProfileDocument {
    pub fn current(registry: &[&str]) -> Self {
        Self {
            name: DEFAULT_PROFILE_NAME.to_string(),
            version: CURRENT_PROFILE_VERSION,
            scanner_set: ScannerSet::from_registry(registry),
            permission_rules: builtin_permission_rules(registry),
            startup_records: Vec::new(),
            legacy_scanner_names: REMOVED_SCANNERS
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
        }
    }

    pub fn legacy(registry: &[&str]) -> Self {
        let mut names: Vec<String> = registry.iter().map(|name| (*name).to_string()).collect();
        for removed in REMOVED_SCANNERS {
            if !names.iter().any(|name| name.as_str() == *removed) {
                names.push((*removed).to_string());
            }
        }

        let mut rules: Vec<PermissionRule> = builtin_permission_rules(registry)
            .into_iter()
            .filter(|rule| rule.since_version <= LEGACY_PROFILE_VERSION)
            .collect();
        for removed in REMOVED_SCANNERS {
            if !rules
                .iter()
                .any(|rule| rule.scanner.as_str() == *removed)
            {
                rules.push(PermissionRule {
                    scanner: (*removed).to_string(),
                    rule: "legacy-inode-walk".to_string(),
                    requires_root: true,
                    paths: vec!["/sys/kernel".to_string()],
                    since_version: LEGACY_PROFILE_VERSION,
                });
            }
        }

        Self {
            name: LEGACY_PROFILE_NAME.to_string(),
            version: LEGACY_PROFILE_VERSION,
            scanner_set: ScannerSet { names },
            permission_rules: rules,
            startup_records: Vec::new(),
            legacy_scanner_names: REMOVED_SCANNERS
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
        }
    }

    pub fn profile_hash(&self) -> String {
        let mut parts = vec![
            format!("name={}", self.name),
            format!("version={}", self.version),
        ];
        for name in &self.scanner_set.names {
            parts.push(format!("scanner={name}"));
        }
        let mut rules: Vec<String> = self
            .permission_rules
            .iter()
            .map(|rule| {
                format!(
                    "rule={}:{}:root={}:since={}:paths={}",
                    rule.scanner,
                    rule.rule,
                    rule.requires_root,
                    rule.since_version,
                    rule.paths.join(",")
                )
            })
            .collect();
        rules.sort();
        parts.extend(rules);
        let mut legacy = self.legacy_scanner_names.clone();
        legacy.sort();
        for name in legacy {
            parts.push(format!("legacy={name}"));
        }
        sha256_parts(&parts)
    }

    pub fn scanners(&self) -> &[String] {
        self.scanner_set.as_slice()
    }

    pub fn validate(&self, registry: &[&str]) -> Result<(), ProfileError> {
        if self.name.trim().is_empty() {
            return Err(ProfileError::new(
                ProfileErrorKind::UnknownProfile,
                "profile name is empty",
            ));
        }
        if self.version > CURRENT_PROFILE_VERSION {
            return Err(ProfileError::new(
                ProfileErrorKind::UnknownVersion,
                format!(
                    "profile {} uses future version {} (current is {})",
                    self.name, self.version, CURRENT_PROFILE_VERSION
                ),
            ));
        }
        if self.version != LEGACY_PROFILE_VERSION && self.version != CURRENT_PROFILE_VERSION {
            return Err(ProfileError::new(
                ProfileErrorKind::UnknownVersion,
                format!("profile {} uses unknown version {}", self.name, self.version),
            ));
        }

        let mut seen = BTreeSet::new();
        let mut present = Vec::new();
        for name in &self.scanner_set.names {
            if name.trim().is_empty() {
                return Err(ProfileError::new(
                    ProfileErrorKind::UnknownScanner,
                    "scanner name is empty",
                ));
            }
            if !seen.insert(name.clone()) {
                return Err(ProfileError::new(
                    ProfileErrorKind::DuplicateScanner,
                    format!("scanner {name:?} appears more than once"),
                ));
            }

            let is_registered = registry
                .iter()
                .any(|registered| *registered == name.as_str());
            if self.version == CURRENT_PROFILE_VERSION {
                if !is_registered {
                    return Err(ProfileError::new(
                        ProfileErrorKind::UnknownScanner,
                        format!(
                            "profile {} version {} references unknown scanner {name:?}",
                            self.name, self.version
                        ),
                    ));
                }
                present.push(name.clone());
            } else if is_registered {
                // An old profile may still name a scanner that this binary no
                // longer ships.  It is not part of the order check here; the
                // migration records it as a retired legacy name.
                present.push(name.clone());
            }
        }
        validate_scanner_order(&present, registry)?;

        let mut rule_ids = BTreeSet::new();
        for rule in &self.permission_rules {
            if rule.rule.trim().is_empty() {
                return Err(ProfileError::new(
                    ProfileErrorKind::InvalidRule,
                    format!("scanner {} has an empty rule id", rule.scanner),
                ));
            }
            if rule.since_version > CURRENT_PROFILE_VERSION {
                return Err(ProfileError::new(
                    ProfileErrorKind::InvalidRule,
                    format!("rule {} uses future version {}", rule.id(), rule.since_version),
                ));
            }
            if !self.scanner_set.contains(&rule.scanner) {
                return Err(ProfileError::new(
                    ProfileErrorKind::InvalidRule,
                    format!(
                        "rule {} targets a scanner outside the profile set",
                        rule.id()
                    ),
                ));
            }
            if !rule_ids.insert(rule.id()) {
                return Err(ProfileError::new(
                    ProfileErrorKind::InvalidRule,
                    format!("rule {} appears more than once", rule.id()),
                ));
            }
        }

        Ok(())
    }
}

fn validate_scanner_order(names: &[String], registry: &[&str]) -> Result<(), ProfileError> {
    let mut previous: Option<usize> = None;
    for name in names {
        let Some(index) = registry
            .iter()
            .position(|registered| *registered == name.as_str())
        else {
            return Err(ProfileError::new(
                ProfileErrorKind::UnknownScanner,
                format!("unknown scanner {name:?}"),
            ));
        };
        if let Some(previous) = previous {
            if index <= previous {
                return Err(ProfileError::new(
                    ProfileErrorKind::OrderingViolation,
                    format!(
                        "scanner {name:?} is out of registry order (found {index} after {previous})"
                    ),
                ));
            }
        }
        previous = Some(index);
    }
    Ok(())
}

/// Built-in permission rules.  Some scanners deliberately have no rule: those
/// "missing rules" are part of the compatibility surface and stay missing
/// across migrations.
pub fn builtin_permission_rules(registry: &[&str]) -> Vec<PermissionRule> {
    registry
        .iter()
        .enumerate()
        .filter_map(|(index, name)| builtin_rule_for(name, index))
        .collect()
}

fn builtin_rule_for(name: &str, index: usize) -> Option<PermissionRule> {
    let lower = name.to_ascii_lowercase();
    let (rule, requires_root, paths): (&str, bool, &[&str]) =
        if lower.contains("bpf") || lower.contains("kprobe") || lower.contains("kfunc") {
            (
                "read-bpf-inventory",
                true,
                &["/sys/fs/bpf", "/proc/kallsyms"],
            )
        } else if lower.contains("kernel")
            || lower.contains("lkm")
            || lower.contains("module")
            || lower.contains("syscall")
            || lower.contains("ftrace")
            || lower.contains("taint")
        {
            (
                "read-kernel-state",
                true,
                &["/proc/kallsyms", "/sys/module"],
            )
        } else if lower.contains("container")
            || lower.contains("namespace")
            || lower.contains("mount")
            || lower.contains("overlay")
            || lower.contains("fanotify")
        {
            (
                "read-mount-inventory",
                false,
                &["/proc/self/mountinfo", "/proc"],
            )
        } else if lower.contains("socket")
            || lower.contains("listener")
            || lower.contains("netfilter")
            || lower.contains("netlink")
            || lower.contains("port")
        {
            (
                "read-network-state",
                true,
                &["/proc/net", "/proc/net/netlink"],
            )
        } else if lower.contains("audit")
            || lower.contains("journal")
            || lower.contains("printk")
            || lower.contains("sudoers")
            || lower.contains("ssh")
            || lower.contains("pam")
            || lower.contains("systemd")
            || lower.contains("cron")
            || lower.contains("scripts")
        {
            (
                "read-persistence-config",
                true,
                &["/etc", "/var/log"],
            )
        } else {
            // No rule for this scanner.  This is intentional: a missing rule
            // must remain missing rather than being fabricated at startup.
            return None;
        };

    Some(PermissionRule {
        scanner: name.to_string(),
        rule: rule.to_string(),
        requires_root,
        paths: paths.iter().map(|path| (*path).to_string()).collect(),
        since_version: if index % 2 == 0 {
            LEGACY_PROFILE_VERSION
        } else {
            CURRENT_PROFILE_VERSION
        },
    })
}

/// Result of moving an older profile to the current schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MigrationOutcome {
    NotNeeded,
    Migrated {
        from: u32,
        to: u32,
        removed_scanners: Vec<String>,
        added_rules: Vec<String>,
    },
    Failed {
        reason: String,
        active: String,
    },
}

impl MigrationOutcome {
    pub fn label(&self) -> String {
        match self {
            Self::NotNeeded => "NOT_NEEDED".to_string(),
            Self::Migrated {
                from,
                to,
                removed_scanners,
                added_rules,
            } => format!(
                "MIGRATED_v{}_to_v{} removed={} added_rules={}",
                from,
                to,
                join_or_dash(removed_scanners),
                added_rules.len()
            ),
            Self::Failed { reason, active } => {
                format!(
                    "MIGRATION_FAILED active={} reason={}",
                    active,
                    sanitise(reason)
                )
            }
        }
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }
}

fn join_or_dash(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values.join(",")
    }
}

fn sanitise(value: &str) -> String {
    value
        .replace('\n', " ")
        .replace('\r', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The only two safe responses to a failed migration.  The default is to
/// refuse to run, so a caller can never silently publish a half-migrated set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationFailurePolicy {
    Refuse,
    LegacyComplete,
}

impl MigrationFailurePolicy {
    pub fn from_env() -> Self {
        let value = env::var("GHOSTSCAN_PROFILE_ON_MIGRATION_FAILURE")
            .or_else(|_| env::var("GHOSTSCAN_PROFILE_MIGRATION_FAILURE"))
            .unwrap_or_default()
            .to_ascii_lowercase();
        match value.trim() {
            "legacy" | "old" | "complete" => Self::LegacyComplete,
            _ => Self::Refuse,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Refuse => "refuse",
            Self::LegacyComplete => "legacy-complete",
        }
    }
}

pub fn migrate_profile(
    old: &ProfileDocument,
    registry: &[&str],
) -> Result<ProfileDocument, ProfileError> {
    migrate_profile_with_rules(old, registry, &builtin_permission_rules(registry))
}

/// Short alias for [`migrate_profile`].
pub fn migrate(
    old: &ProfileDocument,
    registry: &[&str],
) -> Result<ProfileDocument, ProfileError> {
    migrate_profile(old, registry)
}

/// Migrate a version-one profile into the current schema.
///
/// The migration is deliberately conservative:
/// * removed scanners leave the scheduled set but remain known legacy names,
/// * the relative order of the remaining scanners is preserved,
/// * existing rules for surviving scanners are kept exactly as they were,
/// * only rules introduced by the new version are added,
/// * scanners with no rule in either version still have no rule.
pub fn migrate_profile_with_rules(
    old: &ProfileDocument,
    registry: &[&str],
    current_rules: &[PermissionRule],
) -> Result<ProfileDocument, ProfileError> {
    if old.version == CURRENT_PROFILE_VERSION {
        // Already migrated: validation is still required, but there is no
        // schema change to apply and the existing records/order are preserved.
        old.validate(registry)?;
        return Ok(old.clone());
    }
    if old.version != LEGACY_PROFILE_VERSION {
        return Err(ProfileError::new(
            ProfileErrorKind::UnknownVersion,
            format!(
                "profile {} is version {}, migration expects version {}",
                old.name, old.version, LEGACY_PROFILE_VERSION
            ),
        ));
    }
    old.validate(registry)?;

    let mut names = Vec::new();
    let mut removed_scanners = Vec::new();
    let mut seen = BTreeSet::new();
    for name in &old.scanner_set.names {
        let registered = registry
            .iter()
            .any(|registered| *registered == name.as_str());
        if !registered || is_retired_scanner(name.as_str()) {
            removed_scanners.push(name.clone());
            continue;
        }
        if seen.insert(name.clone()) {
            names.push(name.clone());
        }
    }
    validate_scanner_order(&names, registry)?;

    let mut rules: Vec<PermissionRule> = Vec::new();
    for rule in &old.permission_rules {
        let survives = names.iter().any(|name| name == &rule.scanner);
        if survives {
            if !rules.iter().any(|existing| existing.id() == rule.id()) {
                rules.push(rule.clone());
            }
        }
        // Rules for retired or registry-missing scanners disappear with the
        // scanner.  They are never attached to a replacement scanner.
    }

    let mut added_rules = Vec::new();
    for rule in current_rules {
        if rule.since_version <= old.version {
            continue;
        }
        if !names.iter().any(|name| name == &rule.scanner) {
            continue;
        }
        if !rules
            .iter()
            .any(|existing| existing.scanner == rule.scanner && existing.rule == rule.rule)
        {
            added_rules.push(rule.id());
            rules.push(rule.clone());
        }
    }

    let mut legacy_scanner_names = old.legacy_scanner_names.clone();
    for removed in &removed_scanners {
        if !legacy_scanner_names.contains(removed) {
            legacy_scanner_names.push(removed.clone());
        }
    }
    let mut seen_legacy = BTreeSet::new();
    legacy_scanner_names.retain(|name| seen_legacy.insert(name.clone()));

    let migrated = ProfileDocument {
        name: old.name.clone(),
        version: CURRENT_PROFILE_VERSION,
        scanner_set: ScannerSet { names },
        permission_rules: rules,
        startup_records: old.startup_records.clone(),
        legacy_scanner_names,
    };
    migrated.validate(registry)?;
    Ok(migrated)
}

pub fn builtin_profile_named(name: &str, registry: &[&str]) -> Option<ProfileDocument> {
    match name {
        DEFAULT_PROFILE_NAME => Some(ProfileDocument::current(registry)),
        LEGACY_PROFILE_NAME => Some(ProfileDocument::legacy(registry)),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileSource {
    Builtin,
    Store,
}

impl ProfileSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::Builtin => "builtin",
            Self::Store => "store",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileState {
    Current,
    Migrated,
    LegacyComplete,
    Ephemeral,
    Refused,
}

impl ProfileState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Current => "CURRENT",
            Self::Migrated => "MIGRATED",
            Self::LegacyComplete => "LEGACY_COMPLETE",
            Self::Ephemeral => "EPHEMERAL",
            Self::Refused => "REFUSED",
        }
    }

    pub fn should_run(self) -> bool {
        matches!(
            self,
            Self::Current | Self::Migrated | Self::LegacyComplete | Self::Ephemeral
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermissionError {
    pub scanner: String,
    pub rule: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PermissionReport {
    pub evaluated: usize,
    pub satisfied: usize,
    pub denied: usize,
    pub missing_rules: Vec<String>,
    pub errors: Vec<PermissionError>,
}

impl PermissionReport {
    pub fn missing_rule_count(&self) -> usize {
        self.missing_rules.len()
    }
}

/// Evaluate the rules of a profile against the effective uid.
///
/// Evaluation is intentionally independent of scanner execution.  Scanners
/// without a rule are listed as missing and are not gated; a denied rule is
/// recorded with its original error text and the scanner still runs.
pub fn evaluate_permission_rules(
    rules: &[PermissionRule],
    scanner_set: &ScannerSet,
    euid: u32,
) -> PermissionReport {
    let mut report = PermissionReport::default();
    for scanner in &scanner_set.names {
        if !rules.iter().any(|rule| &rule.scanner == scanner) {
            report.missing_rules.push(scanner.clone());
        }
    }

    for rule in rules {
        report.evaluated += 1;
        let mut denied_reason: Option<String> = None;

        if rule.requires_root && euid != 0 {
            denied_reason = Some(format!(
                "permission denied: rule {} requires root (euid={euid})",
                rule.id()
            ));
        }

        if denied_reason.is_none() {
            for path in &rule.paths {
                if let Err(error) = fs::metadata(path.as_str()) {
                    if error.kind() == io::ErrorKind::PermissionDenied {
                        denied_reason = Some(format!(
                            "permission denied: rule {} cannot read {}: {error}",
                            rule.id(),
                            path
                        ));
                        break;
                    }
                }
            }
        }

        match denied_reason {
            Some(reason) => {
                report.denied += 1;
                report.errors.push(PermissionError {
                    scanner: rule.scanner.clone(),
                    rule: rule.rule.clone(),
                    reason,
                });
            }
            None => report.satisfied += 1,
        }
    }

    report
}

/// An immutable profile snapshot plus the establishment of its startup record.
#[derive(Clone, Debug)]
pub struct LoadedProfile {
    pub snapshot: ProfileSnapshot,
    pub state: ProfileState,
    pub migration: MigrationOutcome,
    pub errors: Vec<String>,
    pub permission: PermissionReport,
}

#[derive(Clone, Debug)]
pub struct ProfileSnapshot {
    pub name: String,
    pub version: u32,
    pub source: ProfileSource,
    pub scanner_set: ScannerSet,
    pub permission_rules: Vec<PermissionRule>,
    pub startup_records: Vec<StartupRecord>,
    pub legacy_scanner_names: Vec<String>,
    pub profile_hash: String,
}

impl ProfileSnapshot {
    pub fn from_document(document: &ProfileDocument, source: ProfileSource) -> Self {
        Self {
            name: document.name.clone(),
            version: document.version,
            source,
            scanner_set: document.scanner_set.clone(),
            permission_rules: document.permission_rules.clone(),
            startup_records: document.startup_records.clone(),
            legacy_scanner_names: document.legacy_scanner_names.clone(),
            profile_hash: document.profile_hash(),
        }
    }

    pub fn permission_rule(&self, scanner: &str) -> Option<&PermissionRule> {
        self.permission_rules
            .iter()
            .find(|rule| rule.scanner.as_str() == scanner)
    }

    pub fn scanner_names(&self) -> &[String] {
        self.scanner_set.as_slice()
    }

    pub fn permission_rules_hash(&self) -> String {
        let mut rules: Vec<String> = self
            .permission_rules
            .iter()
            .map(|rule| {
                format!(
                    "{}|{}|root={}|since={}|paths={}",
                    rule.scanner,
                    rule.rule,
                    rule.requires_root,
                    rule.since_version,
                    rule.paths.join(",")
                )
            })
            .collect();
        rules.sort();
        sha256_parts(&rules)
    }
}

fn startup_record_hash(record: &StartupRecord) -> String {
    sha256_parts(&[
        format!("generation={}", record.generation),
        format!("profile={}", record.profile),
        format!("version={}", record.profile_version),
        format!("profile_hash={}", record.profile_hash),
        format!("scanner_set={}", record.scanner_set_hash),
        format!("scanner_names={}", record.scanner_names.join(",")),
        format!("permission_rules={}", record.permission_rules_hash),
        format!("permission_rule_ids={}", record.permission_rule_ids.join(",")),
        format!("scanners={}", record.scanner_count),
        format!("rules={}", record.permission_rule_count),
        format!("permission_errors={}", record.permission_errors),
        format!("migration={}", record.migration),
        format!("started={}", record.started_unix_ns),
        format!("pid={}", record.pid),
    ])
}

#[derive(Clone, Debug)]
pub struct ScannerStartRecord {
    pub scanner: String,
    pub index: usize,
    pub generation: String,
    pub profile_hash: String,
    pub started_unix_ns: u64,
    pub pid: u32,
}

#[derive(Clone, Debug, Default)]
struct RuntimeLedger {
    started: Vec<ScannerStartRecord>,
    findings: usize,
    failures: usize,
    missing: Vec<String>,
}

/// On-disk registry of named profiles.  It is replaced as one file, which is
/// what makes a migration and its startup record a single transaction.
#[derive(Clone, Debug, Serialize)]
struct ProfileRegistryFile {
    #[serde(default = "default_format_version")]
    format_version: u32,
    #[serde(default)]
    active_profile: String,
    #[serde(default)]
    profiles: BTreeMap<String, ProfileDocument>,
}

impl<'de> Deserialize<'de> for ProfileRegistryFile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Representation {
            Single(ProfileDocument),
            Registry {
                #[serde(default = "default_format_version")]
                format_version: u32,
                #[serde(default)]
                active_profile: String,
                profiles: BTreeMap<String, ProfileDocument>,
            },
        }

        Ok(match Representation::deserialize(deserializer)? {
            Representation::Single(document) => {
                let name = document.name.clone();
                let mut profiles = BTreeMap::new();
                profiles.insert(name.clone(), document);
                Self {
                    format_version: PROFILE_FORMAT_VERSION,
                    active_profile: name,
                    profiles,
                }
            }
            Representation::Registry {
                format_version,
                active_profile,
                profiles,
            } => Self {
                format_version,
                active_profile,
                profiles,
            },
        })
    }
}

fn default_format_version() -> u32 {
    PROFILE_FORMAT_VERSION
}

impl ProfileRegistryFile {
    fn new() -> Self {
        Self {
            format_version: PROFILE_FORMAT_VERSION,
            active_profile: String::new(),
            profiles: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProfileStore {
    dir: PathBuf,
    file_override: Option<PathBuf>,
    explicit: bool,
    fail_writes: bool,
}

impl ProfileStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            file_override: None,
            explicit: false,
            fail_writes: false,
        }
    }

    pub fn from_env() -> Self {
        if let Some(file) = env::var_os("GHOSTSCAN_PROFILE_FILE") {
            let file = PathBuf::from(file);
            let dir = file
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."));
            return Self {
                dir,
                file_override: Some(file),
                explicit: true,
                fail_writes: false,
            };
        }

        if let Some(dir) = env::var_os("GHOSTSCAN_PROFILE_DIR")
            .or_else(|| env::var_os("GHOSTSCAN_STATE_DIR"))
            .or_else(|| env::var_os("GHOSTSCAN_PROFILE_STORE"))
        {
            return Self {
                dir: PathBuf::from(dir),
                file_override: None,
                explicit: true,
                fail_writes: false,
            };
        }

        let dir = env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .map(|root| root.join("ghostscan"))
            .or_else(|| {
                env::var_os("HOME")
                    .map(PathBuf::from)
                    .map(|home| home.join(".local/state/ghostscan"))
            })
            .unwrap_or_else(|| {
                env::temp_dir().join(format!("ghostscan-profile-{}", current_euid()))
            });
        Self {
            dir,
            file_override: None,
            explicit: false,
            fail_writes: false,
        }
    }

    /// A store whose commits fail.  Used by tests and by front ends that need
    /// to exercise the migration-failure path without changing permissions.
    #[doc(hidden)]
    pub fn failing_writes(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            file_override: None,
            explicit: true,
            fail_writes: true,
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn is_explicit(&self) -> bool {
        self.explicit
    }

    pub fn profile_path(&self) -> PathBuf {
        self.file_override
            .clone()
            .unwrap_or_else(|| self.dir.join(PROFILE_FILE))
    }

    pub fn lock_path(&self) -> PathBuf {
        match &self.file_override {
            Some(file) => file.with_extension("lock"),
            None => self.dir.join(PROFILE_LOCK_FILE),
        }
    }

    /// Read one persisted profile without migrating or writing it.  Useful for
    /// audits and for acceptance tests that compare the committed document
    /// with the scanner set that was printed.
    pub fn read_profile(&self, name: &str) -> Result<Option<ProfileDocument>, ProfileError> {
        Ok(self
            .read_registry()?
            .and_then(|registry| registry.profiles.get(name).cloned()))
    }

    /// Read the persisted active profile, if a store already exists.
    pub fn read_active_profile(&self) -> Result<Option<ProfileDocument>, ProfileError> {
        let Some(registry) = self.read_registry()? else {
            return Ok(None);
        };
        let name = if registry.active_profile.trim().is_empty() {
            DEFAULT_PROFILE_NAME.to_string()
        } else {
            registry.active_profile
        };
        Ok(registry.profiles.get(&name).cloned())
    }

    fn ensure_dir(&self) -> Result<(), ProfileError> {
        let dir = self
            .profile_path()
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        fs::create_dir_all(&dir)
            .map_err(|error| io_error(format!("create profile directory {}", dir.display()), error))
    }

    fn read_registry(&self) -> Result<Option<ProfileRegistryFile>, ProfileError> {
        let path = self.profile_path();
        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(format!("open {}", path.display()), error)),
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|error| io_error(format!("read {}", path.display()), error))?;
        let registry: ProfileRegistryFile = serde_json::from_slice(&bytes).map_err(|error| {
            ProfileError::new(
                ProfileErrorKind::Corrupt,
                format!("parse {}: {error}", path.display()),
            )
        })?;
        Ok(Some(registry))
    }

    fn write_registry_atomic(&self, registry: &ProfileRegistryFile) -> Result<(), ProfileError> {
        if self.fail_writes {
            return Err(ProfileError::new(
                ProfileErrorKind::CommitFailed,
                "profile store is configured to fail writes",
            ));
        }
        self.ensure_dir()?;
        let path = self.profile_path();
        let dir = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let sequence = NEXT_TEMPORARY_FILE.fetch_add(1, Ordering::Relaxed);
        let file_name = path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| PROFILE_FILE.to_string());
        let temporary = dir.join(format!(
            ".{file_name}.tmp.{}.{}",
            process::id(),
            sequence
        ));

        let bytes = serde_json::to_vec_pretty(registry).map_err(|error| {
            ProfileError::new(
                ProfileErrorKind::CommitFailed,
                format!("serialize profile registry: {error}"),
            )
        })?;
        let write_result = (|| -> Result<(), ProfileError> {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&temporary)
                .map_err(|error| io_error(format!("create {}", temporary.display()), error))?;
            file.write_all(&bytes)
                .map_err(|error| io_error(format!("write {}", temporary.display()), error))?;
            file.sync_all()
                .map_err(|error| io_error(format!("sync {}", temporary.display()), error))?;
            fs::rename(&temporary, &path).map_err(|error| {
                io_error(
                    format!("rename {} to {}", temporary.display(), path.display()),
                    error,
                )
            })?;
            if let Ok(directory) = File::open(&dir) {
                let _ = directory.sync_all();
            }
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        write_result
    }

    fn acquire_lock(&self) -> Result<FileLock, ProfileError> {
        self.ensure_dir()?;
        let path = self.lock_path();
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|error| io_error(format!("open lock {}", path.display()), error))?;
        // SAFETY: `file` is an open file descriptor for the lifetime of the
        // call and `LOCK_EX` does not dereference caller memory.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if result != 0 {
            return Err(ProfileError::new(
                ProfileErrorKind::Lock,
                format!("flock {}: {}", path.display(), io::Error::last_os_error()),
            ));
        }
        Ok(FileLock { file })
    }

    /// Load, validate, migrate and commit a profile while holding the store
    /// lock.  The returned snapshot is exactly what was committed (or the
    /// complete legacy snapshot when the explicit fallback policy was used).
    pub fn load_and_commit(
        &self,
        requested: Option<&str>,
        registry: &[&str],
        policy: MigrationFailurePolicy,
        generation: &str,
        euid: u32,
    ) -> Result<LoadedProfile, ProfileError> {
        let _process_guard = STORE_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _lock = self.acquire_lock()?;

        let mut registry_file = match self.read_registry()? {
            Some(registry_file) => registry_file,
            None => ProfileRegistryFile::new(),
        };
        if registry_file.format_version > PROFILE_FORMAT_VERSION {
            return Err(ProfileError::new(
                ProfileErrorKind::UnknownVersion,
                format!(
                    "profile store format {} is newer than supported format {}",
                    registry_file.format_version, PROFILE_FORMAT_VERSION
                ),
            ));
        }
        if registry_file.format_version == 0 {
            registry_file.format_version = PROFILE_FORMAT_VERSION;
        }

        let name = requested
            .map(str::to_string)
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| {
                if registry_file.active_profile.trim().is_empty() {
                    DEFAULT_PROFILE_NAME.to_string()
                } else {
                    registry_file.active_profile.clone()
                }
            });

        let mut source = ProfileSource::Store;
        let mut document = if let Some(document) = registry_file.profiles.get(&name).cloned() {
            document
        } else if let Some(document) = builtin_profile_named(&name, registry) {
            source = ProfileSource::Builtin;
            registry_file.profiles.insert(name.clone(), document.clone());
            registry_file.active_profile = name.clone();
            document
        } else {
            return Err(ProfileError::new(
                ProfileErrorKind::UnknownProfile,
                format!("unknown profile {name:?}; refusing to start"),
            ));
        };

        document.validate(registry)?;
        let old_document = document.clone();
        let mut state = ProfileState::Current;
        let mut migration = MigrationOutcome::NotNeeded;
        let mut errors = Vec::new();

        if document.version < CURRENT_PROFILE_VERSION {
            match migrate_profile(&document, registry) {
                Ok(migrated) => {
                    state = ProfileState::Migrated;
                    migration = MigrationOutcome::Migrated {
                        from: document.version,
                        to: migrated.version,
                        removed_scanners: document
                            .scanner_set
                            .names
                            .iter()
                            .filter(|name| {
                                !migrated.scanner_set.contains(name.as_str())
                            })
                            .cloned()
                            .collect(),
                        added_rules: migrated
                            .permission_rules
                            .iter()
                            .filter(|rule| {
                                !document.permission_rules.iter().any(|old_rule| {
                                    old_rule.scanner == rule.scanner && old_rule.rule == rule.rule
                                })
                            })
                            .map(PermissionRule::id)
                            .collect(),
                    };
                    document = migrated;
                }
                Err(error) => {
                    let reason = format!("migration failed: {error}");
                    if policy == MigrationFailurePolicy::LegacyComplete {
                        let mut legacy = old_document.clone();
                        let snapshot = ProfileSnapshot::from_document(&legacy, source);
                        let permission = evaluate_permission_rules(
                            &snapshot.permission_rules,
                            &snapshot.scanner_set,
                            euid,
                        );
                        append_startup_record(
                            &mut legacy,
                            &snapshot,
                            generation,
                            &MigrationOutcome::Failed {
                                reason: reason.clone(),
                                active: "legacy-complete".to_string(),
                            },
                            &permission,
                        );
                        let snapshot = ProfileSnapshot::from_document(&legacy, source);
                        return Ok(LoadedProfile {
                            snapshot,
                            state: ProfileState::LegacyComplete,
                            migration: MigrationOutcome::Failed {
                                reason: reason.clone(),
                                active: "legacy-complete".to_string(),
                            },
                            errors: vec![reason],
                            permission,
                        });
                    }
                    return Ok(LoadedProfile {
                        snapshot: ProfileSnapshot::from_document(&old_document, source),
                        state: ProfileState::Refused,
                        migration: MigrationOutcome::Failed {
                            reason: reason.clone(),
                            active: "refused".to_string(),
                        },
                        errors: vec![reason],
                        permission: evaluate_permission_rules(
                            &old_document.permission_rules,
                            &old_document.scanner_set,
                            euid,
                        ),
                    });
                }
            }
        }

        let snapshot_before_record = ProfileSnapshot::from_document(&document, source);
        let permission = evaluate_permission_rules(
            &snapshot_before_record.permission_rules,
            &snapshot_before_record.scanner_set,
            euid,
        );
        append_startup_record(
            &mut document,
            &snapshot_before_record,
            generation,
            &migration,
            &permission,
        );
        let snapshot = ProfileSnapshot::from_document(&document, source);

        registry_file.profiles.insert(name.clone(), document.clone());
        registry_file.active_profile = name;
        registry_file.format_version = PROFILE_FORMAT_VERSION;

        match self.write_registry_atomic(&registry_file) {
            Ok(()) => Ok(LoadedProfile {
                snapshot,
                state,
                migration,
                errors,
                permission,
            }),
            Err(error) => {
                let reason = format!("profile commit failed: {error}");
                errors.push(reason.clone());
                if state == ProfileState::Migrated {
                    if policy == MigrationFailurePolicy::LegacyComplete {
                        let mut legacy = old_document.clone();
                        let old_snapshot = ProfileSnapshot::from_document(&legacy, source);
                        let old_permission = evaluate_permission_rules(
                            &old_snapshot.permission_rules,
                            &old_snapshot.scanner_set,
                            euid,
                        );
                        append_startup_record(
                            &mut legacy,
                            &old_snapshot,
                            generation,
                            &MigrationOutcome::Failed {
                                reason: reason.clone(),
                                active: "legacy-complete".to_string(),
                            },
                            &old_permission,
                        );
                        let old_snapshot = ProfileSnapshot::from_document(&legacy, source);
                        return Ok(LoadedProfile {
                            snapshot: old_snapshot,
                            state: ProfileState::LegacyComplete,
                            migration: MigrationOutcome::Failed {
                                reason: reason.clone(),
                                active: "legacy-complete".to_string(),
                            },
                            errors,
                            permission: old_permission,
                        });
                    }
                    return Ok(LoadedProfile {
                        snapshot,
                        state: ProfileState::Refused,
                        migration: MigrationOutcome::Failed {
                            reason: reason.clone(),
                            active: "refused".to_string(),
                        },
                        errors,
                        permission,
                    });
                }

                // The selected profile itself is complete; only persistence of
                // the new startup record failed.  Keep using the validated
                // in-memory profile and report the store failure explicitly.
                Ok(LoadedProfile {
                    snapshot,
                    state: ProfileState::Ephemeral,
                    migration,
                    errors,
                    permission,
                })
            }
        }
    }
}

fn append_startup_record(
    document: &mut ProfileDocument,
    snapshot: &ProfileSnapshot,
    generation: &str,
    migration: &MigrationOutcome,
    permission: &PermissionReport,
) {
    document.startup_records.push(StartupRecord {
        generation: generation.to_string(),
        profile: document.name.clone(),
        profile_version: document.version,
        profile_hash: snapshot.profile_hash.clone(),
        scanner_set_hash: snapshot.scanner_set.hash(),
        scanner_names: snapshot.scanner_set.names.clone(),
        permission_rules_hash: snapshot.permission_rules_hash(),
        permission_rule_ids: {
            let mut ids: Vec<String> = snapshot
                .permission_rules
                .iter()
                .map(PermissionRule::id)
                .collect();
            ids.sort();
            ids
        },
        scanner_count: snapshot.scanner_set.len(),
        permission_rule_count: snapshot.permission_rules.len(),
        permission_errors: permission.denied,
        migration: migration.label(),
        started_unix_ns: now_ns(),
        pid: process::id(),
    });
    let excess = document.startup_records.len().saturating_sub(MAX_STARTUP_RECORDS);
    if excess > 0 {
        document.startup_records.drain(0..excess);
    }
}

struct FileLock {
    file: File,
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // SAFETY: the descriptor is still open and `LOCK_UN` does not
        // dereference caller memory.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// The process-wide profile transaction.
pub struct ProfileTransaction {
    snapshot: ProfileSnapshot,
    state: ProfileState,
    migration: MigrationOutcome,
    errors: Vec<String>,
    permission: PermissionReport,
    generation: String,
    ledger: Mutex<RuntimeLedger>,
}

impl ProfileTransaction {
    pub fn start() -> Self {
        let registry = crate::scanner_names();
        let requested = env::var("GHOSTSCAN_PROFILE")
            .or_else(|_| env::var("GHOSTSCAN_SCAN_PROFILE"))
            .ok();
        Self::start_with_store(
            ProfileStore::from_env(),
            &registry,
            requested.as_deref(),
            MigrationFailurePolicy::from_env(),
            current_euid(),
        )
    }

    /// Alias used by front ends that name the transaction after the scan.
    pub fn begin_scan() -> Self {
        Self::start()
    }

    pub fn new() -> Self {
        Self::start()
    }

    /// Start against the environment-selected store with an explicit registry.
    pub fn start_with_registry(
        registry: &[&str],
        requested: Option<&str>,
        policy: MigrationFailurePolicy,
        euid: u32,
    ) -> Self {
        Self::start_with_store(
            ProfileStore::from_env(),
            registry,
            requested,
            policy,
            euid,
        )
    }

    pub fn start_with_store(
        store: ProfileStore,
        registry: &[&str],
        requested: Option<&str>,
        policy: MigrationFailurePolicy,
        euid: u32,
    ) -> Self {
        let generation = generation_label();
        let requested_name = requested
            .map(str::to_string)
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_PROFILE_NAME.to_string());

        match store.load_and_commit(
            requested,
            registry,
            policy,
            &generation,
            euid,
        ) {
            Ok(loaded) => Self {
                snapshot: loaded.snapshot,
                state: loaded.state,
                migration: loaded.migration,
                errors: loaded.errors,
                permission: loaded.permission,
                generation,
                ledger: Mutex::new(RuntimeLedger::default()),
            },
            Err(error) => {
                let refuse = store.is_explicit()
                    || requested_name != DEFAULT_PROFILE_NAME
                    || matches!(
                        error.kind,
                        ProfileErrorKind::UnknownProfile
                            | ProfileErrorKind::UnknownVersion
                            | ProfileErrorKind::Corrupt
                            | ProfileErrorKind::UnknownScanner
                            | ProfileErrorKind::DuplicateScanner
                            | ProfileErrorKind::OrderingViolation
                            | ProfileErrorKind::InvalidRule
                    );
                if refuse {
                    Self::refused(requested_name, error, generation)
                } else {
                    Self::ephemeral(registry, error, generation, euid)
                }
            }
        }
    }

    fn refused(name: String, error: ProfileError, generation: String) -> Self {
        let document = ProfileDocument {
            name,
            version: 0,
            scanner_set: ScannerSet::default(),
            permission_rules: Vec::new(),
            startup_records: Vec::new(),
            legacy_scanner_names: REMOVED_SCANNERS
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
        };
        Self {
            snapshot: ProfileSnapshot::from_document(&document, ProfileSource::Store),
            state: ProfileState::Refused,
            migration: MigrationOutcome::Failed {
                reason: error.message.clone(),
                active: "refused".to_string(),
            },
            errors: vec![error.to_string()],
            permission: PermissionReport::default(),
            generation,
            ledger: Mutex::new(RuntimeLedger::default()),
        }
    }

    fn ephemeral(
        registry: &[&str],
        error: ProfileError,
        generation: String,
        euid: u32,
    ) -> Self {
        let document = ProfileDocument::current(registry);
        let snapshot = ProfileSnapshot::from_document(&document, ProfileSource::Builtin);
        let permission = evaluate_permission_rules(
            &snapshot.permission_rules,
            &snapshot.scanner_set,
            euid,
        );
        Self {
            snapshot,
            state: ProfileState::Ephemeral,
            migration: MigrationOutcome::NotNeeded,
            errors: vec![format!(
                "profile store unavailable, using complete builtin profile: {error}"
            )],
            permission,
            generation,
            ledger: Mutex::new(RuntimeLedger::default()),
        }
    }

    pub fn state(&self) -> ProfileState {
        self.state
    }

    pub fn should_run(&self) -> bool {
        self.state.should_run()
    }

    pub fn scanner_names(&self) -> &[String] {
        if self.should_run() {
            self.snapshot.scanner_names()
        } else {
            // A refused transaction must not expose a scanner set that the
            // caller could accidentally run.
            &[] as &[String]
        }
    }

    pub fn should_run_scanner(&self, name: &str) -> bool {
        self.should_run() && self.snapshot.scanner_set.contains(name)
    }

    pub fn permission_rule(&self, scanner: &str) -> Option<&PermissionRule> {
        self.snapshot.permission_rule(scanner)
    }

    pub fn profile_hash(&self) -> &str {
        &self.snapshot.profile_hash
    }

    pub fn snapshot(&self) -> &ProfileSnapshot {
        &self.snapshot
    }

    pub fn profile_name(&self) -> &str {
        &self.snapshot.name
    }

    pub fn profile_version(&self) -> u32 {
        self.snapshot.version
    }

    pub fn permission_rules(&self) -> &[PermissionRule] {
        &self.snapshot.permission_rules
    }

    pub fn startup_records(&self) -> &[StartupRecord] {
        &self.snapshot.startup_records
    }

    pub fn legacy_scanner_names(&self) -> &[String] {
        &self.snapshot.legacy_scanner_names
    }

    pub fn permission_report(&self) -> &PermissionReport {
        &self.permission
    }

    pub fn migration(&self) -> &MigrationOutcome {
        &self.migration
    }

    pub fn errors(&self) -> &[String] {
        &self.errors
    }

    pub fn generation(&self) -> &str {
        &self.generation
    }

    pub fn note_scanner_start(&self, scanner: &str, index: usize) {
        let mut ledger = self
            .ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ledger.started.push(ScannerStartRecord {
            scanner: scanner.to_string(),
            index,
            generation: self.generation.clone(),
            profile_hash: self.snapshot.profile_hash.clone(),
            started_unix_ns: now_ns(),
            pid: process::id(),
        });
    }

    pub fn note_scanner_outcome(&self, scanner: &str, outcome: &crate::ScanOutcome) {
        let mut ledger = self
            .ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match outcome {
            Ok(Some(_)) => ledger.findings += 1,
            Ok(None) => {}
            Err(_) => ledger.failures += 1,
        }
        if !self.snapshot.scanner_set.contains(scanner) {
            ledger.missing.push(scanner.to_string());
        }
    }

    pub fn note_scanner_missing(&self, scanner: &str) {
        let mut ledger = self
            .ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !ledger.missing.iter().any(|name| name.as_str() == scanner) {
            ledger.missing.push(scanner.to_string());
        }
    }

    pub fn report(&self) -> ProfileReport {
        let ledger = self
            .ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let started_names: BTreeSet<&str> = ledger
            .started
            .iter()
            .map(|record| record.scanner.as_str())
            .collect();
        let expected = &self.snapshot.scanner_set.names;
        let all_expected_started = expected
            .iter()
            .all(|name| started_names.contains(name.as_str()));
        let all_hashes_match = ledger
            .started
            .iter()
            .all(|record| record.profile_hash == self.snapshot.profile_hash);
        let all_generations_match = ledger
            .started
            .iter()
            .all(|record| record.generation == self.generation);
        let startup_record_matches = self
            .snapshot
            .startup_records
            .last()
            .map(|record| {
                (record.profile.is_empty() || record.profile == self.snapshot.name)
                    && (record.profile_version == 0
                        || record.profile_version == self.snapshot.version)
                    && (record.profile_hash.is_empty()
                        || record.profile_hash == self.snapshot.profile_hash)
                    && (record.scanner_set_hash.is_empty()
                        || record.scanner_set_hash == self.snapshot.scanner_set.hash())
                    && (record.permission_rules_hash.is_empty()
                        || record.permission_rules_hash
                            == self.snapshot.permission_rules_hash())
            })
            .unwrap_or(true);
        let same_profile = if !self.should_run() {
            // A refused profile runs nothing, so no cross-profile evidence can
            // have been published.
            ledger.started.is_empty()
        } else {
            let complete = all_expected_started && ledger.started.len() == expected.len();
            all_hashes_match && all_generations_match && startup_record_matches && complete
        };

        let verdict = if self.should_run() {
            if self.state == ProfileState::Ephemeral {
                "READY_EPHEMERAL"
            } else {
                "READY"
            }
        } else {
            "REFUSED"
        };
        let reason = if self.should_run() {
            if same_profile {
                "one complete profile served the run".to_string()
            } else {
                "scanner startup records do not match the selected profile".to_string()
            }
        } else {
            self.errors
                .first()
                .cloned()
                .unwrap_or_else(|| "profile was not usable".to_string())
        };

        let mut lines = vec![
            format!(
                "profile={} profile_version={} profile_source={} state={} runnable={}",
                self.snapshot.name,
                self.snapshot.version,
                self.snapshot.source.label(),
                self.state.label(),
                self.should_run()
            ),
            format!("generation={} pid={}", self.generation, process::id()),
            format!(
                "scanner_set_sha256={} scanner_count={}",
                self.snapshot.scanner_set.hash(),
                if self.should_run() {
                    self.snapshot.scanner_set.len()
                } else {
                    0
                }
            ),
            format!(
                "scanner_names={}",
                if self.should_run() {
                    join_or_dash(&self.snapshot.scanner_set.names)
                } else {
                    "-".to_string()
                }
            ),
            format!(
                "permission_rules={} missing_rules={} permission_errors={}",
                self.snapshot.permission_rules.len(),
                self.permission.missing_rule_count(),
                self.permission.errors.len()
            ),
            format!(
                "permission_rules_sha256={}",
                self.snapshot.permission_rules_hash()
            ),
            format!(
                "startup_records={} startup_record_sha256={} same_profile={}",
                self.snapshot.startup_records.len(),
                self.snapshot
                    .startup_records
                    .last()
                    .map(startup_record_hash)
                    .unwrap_or_else(|| "-".to_string()),
                same_profile
            ),
            format!(
                "scanner_starts={} scanner_start_generations_match={} findings={} failures={} migration={}",
                ledger.started.len(),
                all_generations_match,
                ledger.findings,
                ledger.failures,
                self.migration.label()
            ),
            format!(
                "legacy_scanner_names={}",
                join_or_dash(&self.snapshot.legacy_scanner_names)
            ),
        ];
        if !self.permission.missing_rules.is_empty() {
            lines.push(format!(
                "missing_rules={}",
                join_or_dash(&self.permission.missing_rules)
            ));
        }
        for error in &self.errors {
            lines.push(format!("profile_error={}", sanitise(error)));
        }
        for error in &self.permission.errors {
            lines.push(format!(
                "permission_error={}:{}:{}",
                error.scanner,
                error.rule,
                sanitise(&error.reason)
            ));
        }
        if !ledger.missing.is_empty() {
            lines.push(format!(
                "missing_scanner_implementations={}",
                join_or_dash(&ledger.missing)
            ));
        }

        ProfileReport {
            lines,
            verdict: verdict.to_string(),
            reason,
            same_profile,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProfileReport {
    pub lines: Vec<String>,
    pub verdict: String,
    pub reason: String,
    pub same_profile: bool,
}

impl ProfileReport {
    pub fn render_lines(&self) -> Vec<String> {
        let mut lines = self.lines.clone();
        lines.push(format!(
            "PROFILE_VERDICT={} same_profile={} reason={}",
            self.verdict,
            self.same_profile,
            sanitise(&self.reason)
        ));
        lines
    }

    pub fn is_ready(&self) -> bool {
        self.verdict.starts_with("READY")
    }
}

/// Start one profile transaction.  This is the entry point used by `main` and
/// is kept as a free function for callers that do not want to name the type.
pub fn begin_scan() -> ProfileTransaction {
    ProfileTransaction::start()
}

/// Alias for [`begin_scan`].
pub fn start_scan() -> ProfileTransaction {
    ProfileTransaction::start()
}

/// Render the final report for callers that want the lines without printing.
pub fn summary(transaction: &ProfileTransaction) -> Vec<String> {
    transaction.report().render_lines()
}

/// Compatibility aliases for callers that call the document a scan profile.
pub type ScanProfile = ProfileDocument;
pub type Profile = ProfileDocument;
pub type ScannerProfile = ProfileDocument;
pub type ProfileRule = PermissionRule;
pub type StartupLedger = StartupRecord;
pub type ProfileTransactionReport = ProfileReport;

/// Print the final profile transaction block.
pub fn print_profile_transaction(transaction: &ProfileTransaction) {
    println!("[Profile transaction]");
    for line in transaction.report().render_lines() {
        println!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn registry() -> Vec<&'static str> {
        vec![
            "Alpha kernel probe",
            "Beta bpf probe",
            "Gamma socket probe",
            "Delta container mount probe",
            "Epsilon no-rule probe",
        ]
    }

    fn temp_dir(name: &str) -> PathBuf {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let dir = env::temp_dir().join(format!(
            "ghostscan-profile-{name}-{}-{sequence}",
            process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn current_profile_preserves_registry_order() {
        let registry = registry();
        let document = ProfileDocument::current(&registry);
        document.validate(&registry).unwrap();
        assert_eq!(
            document.scanner_set.names,
            registry
                .iter()
                .map(|name| (*name).to_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(document.version, CURRENT_PROFILE_VERSION);
    }

    #[test]
    fn reversed_order_is_rejected_not_sorted() {
        let registry = registry();
        let mut document = ProfileDocument::current(&registry);
        document.scanner_set.names.reverse();
        let error = document.validate(&registry).unwrap_err();
        assert_eq!(error.kind, ProfileErrorKind::OrderingViolation);
    }

    #[test]
    fn migration_removes_only_the_removed_scanner_and_adds_new_rules() {
        let registry = registry();
        let mut legacy = ProfileDocument::legacy(&registry);
        legacy.version = LEGACY_PROFILE_VERSION;
        legacy.scanner_set.names = vec![
            "Alpha kernel probe".to_string(),
            REMOVED_SCANNERS[0].to_string(),
            "Beta bpf probe".to_string(),
            "Gamma socket probe".to_string(),
            "Delta container mount probe".to_string(),
            "Epsilon no-rule probe".to_string(),
        ];
        legacy.permission_rules = vec![PermissionRule {
            scanner: "Alpha kernel probe".to_string(),
            rule: "old-alpha-rule".to_string(),
            requires_root: true,
            paths: Vec::new(),
            since_version: LEGACY_PROFILE_VERSION,
        }];

        let mut current_rules = builtin_permission_rules(&registry);
        current_rules.push(PermissionRule {
            scanner: "Alpha kernel probe".to_string(),
            rule: "v2-alpha-rule".to_string(),
            requires_root: false,
            paths: Vec::new(),
            since_version: CURRENT_PROFILE_VERSION,
        });
        let migrated = migrate_profile_with_rules(&legacy, &registry, &current_rules).unwrap();

        assert_eq!(migrated.version, CURRENT_PROFILE_VERSION);
        assert!(!migrated
            .scanner_set
            .names
            .iter()
            .any(|name| name.as_str() == REMOVED_SCANNERS[0]));
        assert!(migrated
            .legacy_scanner_names
            .iter()
            .any(|name| name.as_str() == REMOVED_SCANNERS[0]));
        assert_eq!(
            migrated.scanner_set.names.first().map(String::as_str),
            Some("Alpha kernel probe")
        );
        assert!(migrated
            .permission_rules
            .iter()
            .any(|rule| rule.rule == "old-alpha-rule"));
        assert!(migrated
            .permission_rules
            .iter()
            .any(|rule| rule.rule == "v2-alpha-rule"));
        // This scanner deliberately has no built-in rule; it must stay missing.
        assert!(!migrated
            .permission_rules
            .iter()
            .any(|rule| rule.scanner.as_str() == "Epsilon no-rule probe"));
    }

    #[test]
    fn migration_failure_refuses_to_run_and_keeps_old_names_known() {
        let dir = temp_dir("refuse");
        let store = ProfileStore::failing_writes(dir.clone());
        let registry = registry();
        let transaction = ProfileTransaction::start_with_store(
            store,
            &registry,
            Some(LEGACY_PROFILE_NAME),
            MigrationFailurePolicy::Refuse,
            0,
        );
        assert_eq!(transaction.state(), ProfileState::Refused);
        assert!(!transaction.should_run());
        assert!(transaction.scanner_names().is_empty());
        let report = transaction.report().render_lines().join("\n");
        assert!(report.contains("state=REFUSED"));
        assert!(report.contains("same_profile="));
        assert!(report.contains(REMOVED_SCANNERS[0]));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn migration_retires_scanners_missing_from_the_current_registry() {
        let registry = registry();
        let mut old = ProfileDocument::legacy(&registry);
        old.scanner_set.names.insert(2, "Old scanner retired by this build".to_string());
        old.permission_rules.push(PermissionRule {
            scanner: "Old scanner retired by this build".to_string(),
            rule: "old-builtin-rule".to_string(),
            requires_root: true,
            paths: Vec::new(),
            since_version: LEGACY_PROFILE_VERSION,
        });

        let migrated = migrate_profile(&old, &registry).unwrap();
        assert!(migrated
            .scanner_set
            .names
            .iter()
            .all(|name| name.as_str() != "Old scanner retired by this build"));
        assert!(migrated
            .legacy_scanner_names
            .iter()
            .any(|name| name.as_str() == "Old scanner retired by this build"));
        assert!(!migrated
            .permission_rules
            .iter()
            .any(|rule| rule.scanner.as_str() == "Old scanner retired by this build"));
    }

    #[test]
    fn migration_failure_can_use_complete_legacy_profile_but_never_mixes() {
        let dir = temp_dir("legacy");
        let store = ProfileStore::failing_writes(dir.clone());
        let registry = registry();
        let transaction = ProfileTransaction::start_with_store(
            store,
            &registry,
            Some(LEGACY_PROFILE_NAME),
            MigrationFailurePolicy::LegacyComplete,
            0,
        );
        assert_eq!(transaction.state(), ProfileState::LegacyComplete);
        assert!(transaction.should_run());
        assert!(transaction
            .scanner_names()
            .iter()
            .any(|name| name.as_str() == REMOVED_SCANNERS[0]));
        // The complete old profile keeps only old rules.
        assert!(!transaction
            .snapshot
            .permission_rules
            .iter()
            .any(|rule| rule.since_version > LEGACY_PROFILE_VERSION));
        let report = transaction.report().render_lines().join("\n");
        assert!(report.contains("state=LEGACY_COMPLETE"));
        assert!(report.contains("MIGRATION"));
        assert!(report.contains("FAILED"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn unknown_profile_refuses_before_any_scanner_runs() {
        let dir = temp_dir("unknown");
        let store = ProfileStore::new(dir.clone());
        let registry = registry();
        let transaction = ProfileTransaction::start_with_store(
            store,
            &registry,
            Some("does-not-exist"),
            MigrationFailurePolicy::Refuse,
            0,
        );
        assert_eq!(transaction.state(), ProfileState::Refused);
        assert!(!transaction.should_run());
        assert!(transaction.scanner_names().is_empty());
        assert!(transaction
            .report()
            .render_lines()
            .join("\n")
            .contains("unknown profile"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn store_accepts_a_single_profile_document() {
        let dir = temp_dir("single-document");
        let registry = registry();
        let document = ProfileDocument::legacy(&registry);
        let bytes = serde_json::to_vec(&document).unwrap();
        fs::write(dir.join(PROFILE_FILE), bytes).unwrap();

        let store = ProfileStore::new(dir.clone());
        let loaded = store.read_profile(LEGACY_PROFILE_NAME).unwrap().unwrap();
        assert_eq!(loaded.version, LEGACY_PROFILE_VERSION);
        assert_eq!(loaded.name.as_str(), LEGACY_PROFILE_NAME);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn concurrent_startups_share_one_committed_profile_and_record_set() {
        let dir = temp_dir("concurrent");
        let registry = registry();
        let mut handles = Vec::new();
        for _ in 0..4 {
            let dir = dir.clone();
            let registry = registry.clone();
            handles.push(std::thread::spawn(move || {
                ProfileTransaction::start_with_store(
                    ProfileStore::new(dir),
                    &registry,
                    Some(LEGACY_PROFILE_NAME),
                    MigrationFailurePolicy::Refuse,
                    0,
                )
            }));
        }
        let transactions: Vec<ProfileTransaction> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        let first_hash = transactions[0].profile_hash().to_string();
        for transaction in &transactions {
            assert!(transaction.should_run());
            assert_eq!(transaction.profile_hash(), first_hash.as_str());
        }
        let reports: Vec<String> = transactions
            .iter()
            .map(|transaction| transaction.report().render_lines().join("\n"))
            .collect();
        assert!(reports.iter().all(|report| report.contains("state=CURRENT")
            || report.contains("state=MIGRATED")));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn scanner_start_records_are_stamped_with_the_selected_profile() {
        let dir = temp_dir("starts");
        let store = ProfileStore::new(dir.clone());
        let registry = registry();
        let transaction = ProfileTransaction::start_with_store(
            store,
            &registry,
            Some(DEFAULT_PROFILE_NAME),
            MigrationFailurePolicy::Refuse,
            0,
        );
        for (index, name) in transaction.scanner_names().to_vec().iter().enumerate() {
            transaction.note_scanner_start(name, index);
            transaction.note_scanner_outcome(name, &Ok(None));
        }
        let report = transaction.report();
        assert!(report.same_profile);
        assert!(report
            .render_lines()
            .join("\n")
            .contains("same_profile=true"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn permission_errors_are_recorded_and_missing_rules_stay_missing() {
        let registry = registry();
        let document = ProfileDocument::current(&registry);
        let report = evaluate_permission_rules(
            &document.permission_rules,
            &document.scanner_set,
            1000,
        );
        assert!(!report.errors.is_empty());
        assert!(report
            .errors
            .iter()
            .all(|error| error.reason.contains("permission denied")));
        assert!(report
            .missing_rules
            .iter()
            .any(|name| name.as_str() == "Epsilon no-rule probe"));
    }

    #[test]
    fn startup_record_matches_the_profile_identity() {
        let dir = temp_dir("record");
        let store = ProfileStore::new(dir.clone());
        let registry = registry();
        let transaction = ProfileTransaction::start_with_store(
            store,
            &registry,
            Some(DEFAULT_PROFILE_NAME),
            MigrationFailurePolicy::Refuse,
            0,
        );
        let record = transaction
            .snapshot
            .startup_records
            .last()
            .expect("startup record");
        assert_eq!(record.profile, transaction.snapshot.name);
        assert_eq!(
            record.scanner_set_hash,
            transaction.snapshot.scanner_set.hash()
        );
        assert_eq!(
            record.profile_version,
            transaction.snapshot.version
        );
        let _ = fs::remove_dir_all(dir);
    }
}
