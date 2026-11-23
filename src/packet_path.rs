//! One packet-path transaction per scan round.
//!
//! ghostscan used to let the netfilter and XDP/TC scanners collect their own
//! evidence with independent `nft` / `bpftool` invocations.  During a table
//! migration that produced a report which mixed an old table's cloaking chain
//! with an XDP program attached a moment later, and a retry (or a second
//! entry point) could do the same with two different rule generations.
//!
//! [`PacketPathTransaction`] fixes that by making one packet-path observation
//! explicit:
//!
//! * [`PacketPathGeneration`] captures the boot id, a process-local round,
//!   the start time, the examining PID and the network namespace inode before
//!   any collector runs,
//! * every collector result carries a [`PacketPathStamp`] with that
//!   generation, its [`PacketPathSource`] and the attempt number,
//! * all three planes (netfilter tables/chains/hooks, interfaces, and eBPF
//!   XDP/TC programs) are collected once and can only be read through the
//!   transaction,
//! * the final [`PacketPathReport`] accepts only stamps from the current
//!   generation; a stale stamp is counted as cross-generation evidence and
//!   never merged,
//! * a failed/partial collector has no previous-round fallback,
//! * retrying a failed collector restarts *every* plane in a new generation
//!   instead of patching one plane against evidence collected at another
//!   time, and a second entry point always creates its own generation.
//!
//! Findings are attributed field by field: `netns`, `table`, `chain`, `hook`,
//! `interface`, `program` and `finding` are always present (with the literal
//! value `none` when a plane does not apply).  A regular/cloaking netfilter
//! chain therefore has a `netfilter:` path and an XDP attachment has a
//! `bpf:` path; they can never be collapsed into one path just because they
//! were printed next to each other.

#![allow(dead_code)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_PACKET_PATH_ROUND: AtomicU64 = AtomicU64::new(1);

// ---------------------------------------------------------------------------
// Namespace and generation identity
// ---------------------------------------------------------------------------

/// The network namespace in which a packet-path transaction was started.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NetnsId {
    pub inum: u32,
    pub link: String,
}

impl NetnsId {
    pub fn new(inum: u32, link: impl Into<String>) -> Self {
        Self {
            inum,
            link: link.into(),
        }
    }

    pub fn unknown() -> Self {
        Self {
            inum: 0,
            link: "unknown".to_string(),
        }
    }

    /// Read the namespace inode of the process performing the scan.
    pub fn current() -> Result<Self, String> {
        let link = fs::read_link("/proc/self/ns/net")
            .map_err(|err| format!("failed to read /proc/self/ns/net: {err}"))?;
        let text = link.to_string_lossy().to_string();
        let inum = parse_netns_link_target(&text)?;
        Ok(Self { inum, link: text })
    }

    pub fn is_known(&self) -> bool {
        self.inum != 0
    }

    pub fn label(&self) -> String {
        if self.inum == 0 {
            "net:[unknown]".to_string()
        } else {
            format!("net:[{}]", self.inum)
        }
    }
}

impl fmt::Display for NetnsId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.label())
    }
}

/// Parse `net:[4026531840]` (or any symlink target ending in that form).
pub fn parse_netns_link_target(target: &str) -> Result<u32, String> {
    let start = target
        .rfind('[')
        .ok_or_else(|| format!("unexpected netns symlink target: {target}"))?;
    let end = target[start + 1..]
        .find(']')
        .map(|index| start + 1 + index)
        .ok_or_else(|| format!("unexpected netns symlink target: {target}"))?;
    let value = target[start + 1..end]
        .parse::<u64>()
        .map_err(|err| format!("failed to parse netns inum from '{target}': {err}"))?;
    if value > u32::MAX as u64 {
        return Err(format!("netns inum {value} exceeds u32 range"));
    }
    Ok(value as u32)
}

fn parse_netns_link(path: &Path) -> Result<u32, String> {
    let link = fs::read_link(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    parse_netns_link_target(&link.to_string_lossy())
}

/// Identity of one packet-path observation round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketPathGeneration {
    round: u64,
    boot_id: String,
    started_unix_ns: u128,
    pid: u32,
    netns: NetnsId,
    netns_error: Option<String>,
}

impl PacketPathGeneration {
    pub fn start() -> Self {
        Self::start_with_netns(NetnsId::current())
    }

    pub fn start_in(netns: NetnsId) -> Self {
        Self::start_with_netns(Ok(netns))
    }

    pub fn start_with_netns(netns: Result<NetnsId, String>) -> Self {
        let round = NEXT_PACKET_PATH_ROUND.fetch_add(1, Ordering::Relaxed);
        let started_unix_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|value| value.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        let (netns, netns_error) = match netns {
            Ok(netns) => (netns, None),
            Err(err) => (NetnsId::unknown(), Some(err)),
        };

        Self {
            round,
            boot_id,
            started_unix_ns,
            pid: std::process::id(),
            netns,
            netns_error,
        }
    }

    pub fn round(&self) -> u64 {
        self.round
    }

    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    pub fn started_unix_ns(&self) -> u128 {
        self.started_unix_ns
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn netns(&self) -> &NetnsId {
        &self.netns
    }

    pub fn netns_inum(&self) -> u32 {
        self.netns.inum
    }

    pub fn netns_error(&self) -> Option<&str> {
        self.netns_error.as_deref()
    }

    /// Stable human-readable identity used by stamps and reports.
    pub fn label(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.boot_id,
            self.round,
            self.started_unix_ns,
            self.pid,
            self.netns.inum
        )
    }
}

// ---------------------------------------------------------------------------
// Collection failure, source and stamp
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketPathFailure {
    pub reason: String,
    pub cancelled: bool,
}

impl PacketPathFailure {
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

impl fmt::Display for PacketPathFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.reason)
    }
}

/// The three packet-path planes that must come from one instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PacketPathSource {
    Netfilter,
    BpfNet,
    BpfPrograms,
}

impl PacketPathSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::Netfilter => "netfilter",
            Self::BpfNet => "bpf_net",
            Self::BpfPrograms => "bpf_programs",
        }
    }

    pub fn all() -> [Self; 3] {
        [Self::Netfilter, Self::BpfNet, Self::BpfPrograms]
    }
}

/// Backwards-friendly alias: each plane is a collector.
pub type CollectorKind = PacketPathSource;

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

/// Generation stamp attached to every collected plane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketPathStamp {
    pub source: PacketPathSource,
    pub generation: PacketPathGeneration,
    pub attempt: u64,
}

impl PacketPathStamp {
    pub fn belongs_to(&self, generation: &PacketPathGeneration) -> bool {
        &self.generation == generation
    }

    pub fn source(&self) -> PacketPathSource {
        self.source
    }

    pub fn attempt(&self) -> u64 {
        self.attempt
    }

    pub fn netns_inum(&self) -> u32 {
        self.generation.netns_inum()
    }

    pub fn same_netns(&self, generation: &PacketPathGeneration) -> bool {
        self.generation.netns_inum() == generation.netns_inum()
    }
}

// ---------------------------------------------------------------------------
// Netfilter snapshot
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TableId {
    pub family: String,
    pub table: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChainId {
    pub family: String,
    pub table: String,
    pub chain: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScopedSet {
    pub family: String,
    pub table: String,
    pub name: String,
}

/// One nftables chain with the rule facts ghostscan uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetfilterChain {
    pub family: String,
    pub table: String,
    pub chain: String,
    pub chain_type: Option<String>,
    pub hook: Option<String>,
    pub priority: Option<i64>,
    pub policy: Option<String>,
    pub rule_count: usize,
    /// `iifname`/`oifname` literals matched by rules in this chain.  An empty
    /// set means the chain is not bound to a particular interface.
    pub interfaces: BTreeSet<String>,
    pub jump_targets: BTreeSet<String>,
    pub set_refs: BTreeSet<String>,
}

impl NetfilterChain {
    pub fn id(&self) -> ChainId {
        ChainId {
            family: self.family.clone(),
            table: self.table.clone(),
            chain: self.chain.clone(),
        }
    }

    pub fn is_base(&self) -> bool {
        self.hook.is_some() || self.chain_type.is_some()
    }

    pub fn is_regular(&self) -> bool {
        !self.is_base()
    }

    pub fn is_orphan_base(&self) -> bool {
        self.chain_type.is_some() && self.hook.is_none()
    }

    pub fn hook_label(&self) -> &str {
        self.hook.as_deref().unwrap_or("none")
    }

    pub fn interface_label(&self) -> String {
        if !self.interfaces.is_empty() {
            self.interfaces.iter().cloned().collect::<Vec<_>>().join("|")
        } else if self.hook.is_some() {
            "any".to_string()
        } else {
            "none".to_string()
        }
    }
}

/// One atomic `nft -j list ruleset` snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetfilterSnapshot {
    pub netns_inum: u32,
    pub fingerprint: String,
    pub source: String,
    pub tables: BTreeSet<TableId>,
    pub chains: Vec<NetfilterChain>,
    pub sets: BTreeSet<ScopedSet>,
    pub errors: Vec<String>,
}

impl Default for NetfilterSnapshot {
    fn default() -> Self {
        Self {
            netns_inum: 0,
            fingerprint: fingerprint(&[]),
            source: "nft -j list ruleset".to_string(),
            tables: BTreeSet::new(),
            chains: Vec::new(),
            sets: BTreeSet::new(),
            errors: Vec::new(),
        }
    }
}

impl NetfilterSnapshot {
    pub fn find_chain(&self, family: &str, table: &str, chain: &str) -> Option<&NetfilterChain> {
        self.chains.iter().find(|candidate| {
            candidate.family == family && candidate.table == table && candidate.chain == chain
        })
    }

    pub fn chain_count(&self) -> usize {
        self.chains.len()
    }
}

// ---------------------------------------------------------------------------
// eBPF net/interface/program snapshot
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct InterfaceRef {
    pub ifindex: Option<u32>,
    pub ifname: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BpfAttachment {
    pub ifindex: Option<u32>,
    pub ifname: String,
    pub program_id: Option<u64>,
    pub program_name: String,
    pub program_tag: Option<String>,
    pub attach_type: String,
    pub hook: String,
    pub direction: String,
    pub family: String,
    pub mode: Option<String>,
    pub priority: Option<i64>,
}

/// One atomic `bpftool -j net list` snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BpfNetSnapshot {
    pub netns_inum: u32,
    pub fingerprint: String,
    pub source: String,
    pub available: bool,
    pub interfaces: BTreeSet<InterfaceRef>,
    pub attachments: Vec<BpfAttachment>,
    pub errors: Vec<String>,
}

impl Default for BpfNetSnapshot {
    fn default() -> Self {
        Self {
            netns_inum: 0,
            fingerprint: fingerprint(&[]),
            source: "bpftool -j net list".to_string(),
            available: true,
            interfaces: BTreeSet::new(),
            attachments: Vec::new(),
            errors: Vec::new(),
        }
    }
}

impl BpfNetSnapshot {
    pub fn interface_count(&self) -> usize {
        self.interfaces.len()
    }

    pub fn xdp_tc_count(&self) -> usize {
        self.attachments.len()
    }

    pub fn is_empty(&self) -> bool {
        self.attachments.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BpfProgram {
    pub id: Option<u64>,
    pub name: String,
    pub tag: Option<String>,
    pub program_type: String,
    pub ifindex: Option<u32>,
    pub ifname: Option<String>,
    pub pinned: bool,
    pub loaded: bool,
}

/// One `bpftool -j prog list` snapshot, used only to attribute attachments
/// and to spot XDP/TC programs that are not attached in this netns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BpfProgramSnapshot {
    pub netns_inum: u32,
    pub fingerprint: String,
    pub source: String,
    pub available: bool,
    pub programs: Vec<BpfProgram>,
    pub errors: Vec<String>,
}

impl Default for BpfProgramSnapshot {
    fn default() -> Self {
        Self {
            netns_inum: 0,
            fingerprint: fingerprint(&[]),
            source: "bpftool -j prog list".to_string(),
            // An absent program inventory must not turn every attachment into
            // a "missing program" finding.  Only a successful collection can
            // prove that a program id is absent.
            available: false,
            programs: Vec::new(),
            errors: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Findings and path observations
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingKind {
    OrphanBaseChain,
    MissingJumpTarget,
    UnresolvedSet,
    CloakedChain,
    DetachedProgram,
    AttachmentWithoutInterface,
    AttachmentMissingProgram,
}

impl FindingKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::OrphanBaseChain => "orphan_base_chain",
            Self::MissingJumpTarget => "jump_to_missing_handle",
            Self::UnresolvedSet => "anon_set_unresolved",
            Self::CloakedChain => "cloaked_chain",
            Self::DetachedProgram => "detached_xdp_tc_program",
            Self::AttachmentWithoutInterface => "attachment_without_interface",
            Self::AttachmentMissingProgram => "attachment_missing_program",
        }
    }

    pub fn is_netfilter(self) -> bool {
        matches!(
            self,
            Self::OrphanBaseChain | Self::MissingJumpTarget | Self::UnresolvedSet | Self::CloakedChain
        )
    }

    pub fn is_bpf(self) -> bool {
        matches!(
            self,
            Self::DetachedProgram
                | Self::AttachmentWithoutInterface
                | Self::AttachmentMissingProgram
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathPlane {
    Netfilter,
    Bpf,
    Joint,
}

impl PathPlane {
    pub fn label(self) -> &'static str {
        match self {
            Self::Netfilter => "netfilter",
            Self::Bpf => "bpf",
            Self::Joint => "joint",
        }
    }
}

/// A risk finding with full per-field attribution.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PacketPathFinding {
    pub kind: FindingKind,
    pub netns_inum: u32,
    pub generation: String,
    pub plane: PathPlane,
    pub family: String,
    pub table: String,
    pub chain: String,
    pub hook: String,
    pub interface: String,
    pub ifindex: Option<u32>,
    pub program: String,
    pub program_id: Option<u64>,
    pub path: String,
    pub detail: String,
}

impl PacketPathFinding {
    /// Item-by-item attribution used by the final risk report.
    pub fn attribution(&self) -> BTreeMap<&'static str, String> {
        let mut fields = BTreeMap::new();
        fields.insert("netns", self.netns_inum.to_string());
        fields.insert("generation", self.generation.clone());
        fields.insert("table", self.table.clone());
        fields.insert("chain", self.chain.clone());
        fields.insert("hook", self.hook.clone());
        fields.insert("interface", self.interface.clone());
        fields.insert("program", self.program.clone());
        fields.insert(
            "program_id",
            self.program_id
                .map(|program_id| program_id.to_string())
                .unwrap_or_else(|| "none".to_string()),
        );
        fields.insert("path", self.path.clone());
        fields.insert("finding", self.kind.label().to_string());
        fields
    }

    pub fn render_line(&self) -> String {
        format!(
            "netns={} generation={} plane={} family={} table={} chain={} hook={} \
             interface={} program={} program_id={} ifindex={} path={} finding={} detail={} \
             netns_label=net:[{}]",
            self.netns_inum,
            self.generation,
            self.plane.label(),
            self.family,
            self.table,
            self.chain,
            self.hook,
            self.interface,
            self.program,
            optional_u64(self.program_id),
            optional_number(self.ifindex),
            self.path,
            self.kind.label(),
            sanitize(&self.detail),
            self.netns_inum
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProgramRef {
    pub program_id: Option<u64>,
    pub program_name: String,
    pub attach_type: String,
    pub mode: Option<String>,
}

/// A legitimate physical packet path seen by both planes.  This is an
/// attribution record, not a risk finding.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PacketPathObservation {
    pub netns_inum: u32,
    pub generation: String,
    pub plane: PathPlane,
    pub interface: String,
    pub ifindex: Option<u32>,
    pub hook_group: String,
    pub direction: String,
    pub family: String,
    pub tables: Vec<String>,
    pub chains: Vec<ChainId>,
    pub programs: Vec<ProgramRef>,
    pub path: String,
}

impl PacketPathObservation {
    pub fn render_line(&self) -> String {
        let tables = if self.tables.is_empty() {
            "none".to_string()
        } else {
            self.tables
                .iter()
                .map(|table| {
                    table
                        .rsplit_once('/')
                        .map(|(_, name)| name)
                        .unwrap_or(table.as_str())
                })
                .collect::<Vec<_>>()
                .join("|")
        };
        let chains = if self.chains.is_empty() {
            "none".to_string()
        } else {
            self.chains
                .iter()
                .map(|chain| chain.chain.clone())
                .collect::<Vec<_>>()
                .join("|")
        };
        let table_paths = if self.tables.is_empty() {
            "none".to_string()
        } else {
            self.tables.join("|")
        };
        let chain_paths = if self.chains.is_empty() {
            "none".to_string()
        } else {
            self.chains
                .iter()
                .map(|chain| format!("{}/{}/{}", chain.family, chain.table, chain.chain))
                .collect::<Vec<_>>()
                .join("|")
        };
        let programs = self
            .programs
            .iter()
            .map(|program| program.program_name.clone())
            .collect::<Vec<_>>()
            .join("|");
        let program_ids = self
            .programs
            .iter()
            .map(|program| optional_u64(program.program_id))
            .collect::<Vec<_>>()
            .join("|");
        format!(
            "netns={} generation={} plane={} family={} table={} chain={} hook={} \
             interface={} program={} program_id={} ifindex={} path={} \
             finding=packet_path_observed detail=table_paths={} chain_paths={} programs={} direction={} \
             netns_label=net:[{}]",
            self.netns_inum,
            self.generation,
            self.plane.label(),
            self.family,
            tables,
            chains,
            self.hook_group,
            self.interface,
            programs,
            program_ids,
            optional_number(self.ifindex),
            self.path,
            table_paths,
            chain_paths,
            self.programs
                .iter()
                .map(|program| format!("{}#{}", program.program_name, optional_u64(program.program_id)))
                .collect::<Vec<_>>()
                .join("|"),
            self.direction,
            self.netns_inum
        )
    }
}

fn optional_number(value: Option<u32>) -> String {
    value
        .map(|number| number.to_string())
        .unwrap_or_else(|| "none".to_string())
}

fn optional_u64(value: Option<u64>) -> String {
    value
        .map(|number| number.to_string())
        .unwrap_or_else(|| "none".to_string())
}

fn sanitize(value: &str) -> String {
    value.replace('\n', " ")
}

fn finding_for_chain(
    kind: FindingKind,
    generation: &PacketPathGeneration,
    chain: &NetfilterChain,
    detail: String,
) -> PacketPathFinding {
    let interface = chain.interface_label();
    let path = format!(
        "netfilter:{}/{}/{}/{}/{}/{}",
        generation.netns_inum(),
        chain.family,
        chain.table,
        chain.chain,
        chain.hook_label(),
        interface
    );
    PacketPathFinding {
        kind,
        netns_inum: generation.netns_inum(),
        generation: generation.label(),
        plane: PathPlane::Netfilter,
        family: chain.family.clone(),
        table: chain.table.clone(),
        chain: chain.chain.clone(),
        hook: chain.hook_label().to_string(),
        interface,
        ifindex: None,
        program: "none".to_string(),
        program_id: None,
        path,
        detail,
    }
}

fn finding_for_attachment(
    kind: FindingKind,
    generation: &PacketPathGeneration,
    attachment: &BpfAttachment,
    detail: String,
) -> PacketPathFinding {
    let interface = if attachment.ifname.is_empty() {
        "none".to_string()
    } else {
        attachment.ifname.clone()
    };
    let path = format!(
        "bpf:{}/{}/{}/{}/{}",
        generation.netns_inum(),
        interface,
        attachment.hook,
        attachment.direction,
        optional_u64(attachment.program_id)
    );
    PacketPathFinding {
        kind,
        netns_inum: generation.netns_inum(),
        generation: generation.label(),
        plane: PathPlane::Bpf,
        family: attachment.family.clone(),
        table: "none".to_string(),
        chain: "none".to_string(),
        hook: attachment.hook.clone(),
        interface,
        ifindex: attachment.ifindex,
        program: attachment.program_name.clone(),
        program_id: attachment.program_id,
        path,
        detail,
    }
}

fn finding_for_detached_program(
    generation: &PacketPathGeneration,
    program: &BpfProgram,
    detail: String,
) -> PacketPathFinding {
    let interface = program
        .ifname
        .clone()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "none".to_string());
    let path = format!(
        "bpf:{}/{}/{}/{}/{}",
        generation.netns_inum(),
        interface,
        "none",
        "unknown",
        optional_u64(program.id)
    );
    PacketPathFinding {
        kind: FindingKind::DetachedProgram,
        netns_inum: generation.netns_inum(),
        generation: generation.label(),
        plane: PathPlane::Bpf,
        family: "any".to_string(),
        table: "none".to_string(),
        chain: "none".to_string(),
        hook: "none".to_string(),
        interface,
        ifindex: program.ifindex,
        program: program.name.clone(),
        program_id: program.id,
        path,
        detail,
    }
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

/// Derive netfilter-only findings from one snapshot.
pub fn analyze_netfilter(
    snapshot: &NetfilterSnapshot,
    generation: &PacketPathGeneration,
) -> Vec<PacketPathFinding> {
    let mut findings = Vec::new();
    let mut chains_by_table: BTreeMap<TableId, BTreeSet<ChainId>> = BTreeMap::new();

    for chain in &snapshot.chains {
        chains_by_table
            .entry(TableId {
                family: chain.family.clone(),
                table: chain.table.clone(),
            })
            .or_default()
            .insert(chain.id());
    }

    let mut reachable: BTreeSet<ChainId> = BTreeSet::new();
    for table in chains_by_table.keys() {
        let mut queue = VecDeque::new();
        for chain in &snapshot.chains {
            if chain.family == table.family && chain.table == table.table && chain.hook.is_some() {
                queue.push_back(chain.id());
            }
        }
        while let Some(current) = queue.pop_front() {
            if !reachable.insert(current.clone()) {
                continue;
            }
            if let Some(chain) = snapshot
                .chains
                .iter()
                .find(|candidate| candidate.id() == current)
            {
                for target in &chain.jump_targets {
                    queue.push_back(ChainId {
                        family: current.family.clone(),
                        table: current.table.clone(),
                        chain: target.clone(),
                    });
                }
            }
        }
    }

    for chain in &snapshot.chains {
        if chain.is_orphan_base() {
            findings.push(finding_for_chain(
                FindingKind::OrphanBaseChain,
                generation,
                chain,
                "anomaly=orphan_base_chain type_without_hook".to_string(),
            ));
        }

        let table_chains = chains_by_table.get(&TableId {
            family: chain.family.clone(),
            table: chain.table.clone(),
        });
        for target in &chain.jump_targets {
            let target_id = ChainId {
                family: chain.family.clone(),
                table: chain.table.clone(),
                chain: target.clone(),
            };
            let present = table_chains
                .map(|chains| chains.contains(&target_id))
                .unwrap_or(false);
            if !present {
                findings.push(finding_for_chain(
                    FindingKind::MissingJumpTarget,
                    generation,
                    chain,
                    format!("anomaly=jump_to_missing_handle target={target}"),
                ));
            }
        }

        for set in &chain.set_refs {
            let scoped = ScopedSet {
                family: chain.family.clone(),
                table: chain.table.clone(),
                name: set.clone(),
            };
            if !snapshot.sets.contains(&scoped) {
                findings.push(finding_for_chain(
                    FindingKind::UnresolvedSet,
                    generation,
                    chain,
                    format!("anomaly=anon_set_unresolved set=@{set}"),
                ));
            }
        }

        // An empty regular chain is explicitly legal.  Only a chain that
        // carries rules while being unreachable from every base chain is a
        // cloaking candidate.
        if chain.is_regular() && chain.rule_count > 0 && !reachable.contains(&chain.id()) {
            findings.push(finding_for_chain(
                FindingKind::CloakedChain,
                generation,
                chain,
                "anomaly=cloaked_chain unreachable_chain_with_rules empty_chains_are_ignored"
                    .to_string(),
            ));
        }
    }

    findings.sort();
    findings.dedup();
    findings
}

fn is_xdp_tc_program(program_type: &str) -> bool {
    matches!(
        program_type.to_ascii_lowercase().as_str(),
        "xdp" | "xdp_frags" | "sched_cls" | "sched_act" | "tc" | "classifier" | "action"
    )
}

/// Derive BPF-only findings from the net and program snapshots.
pub fn analyze_bpf(
    net: &BpfNetSnapshot,
    programs: Option<&BpfProgramSnapshot>,
    generation: &PacketPathGeneration,
) -> Vec<PacketPathFinding> {
    let mut findings = Vec::new();
    let mut attached_ids: BTreeSet<u64> = BTreeSet::new();

    for attachment in &net.attachments {
        if let Some(program_id) = attachment.program_id {
            attached_ids.insert(program_id);
        }

        let missing_interface = attachment.ifindex.is_none()
            && (attachment.ifname.is_empty()
                || attachment.ifname == "unknown"
                || attachment.ifname == "none");
        if missing_interface {
            findings.push(finding_for_attachment(
                FindingKind::AttachmentWithoutInterface,
                generation,
                attachment,
                "anomaly=attachment_without_interface".to_string(),
            ));
        }

        if let (Some(programs), Some(program_id)) = (programs, attachment.program_id) {
            if programs.available
                && !programs
                    .programs
                    .iter()
                    .any(|program| program.id == Some(program_id))
            {
                findings.push(finding_for_attachment(
                    FindingKind::AttachmentMissingProgram,
                    generation,
                    attachment,
                    format!("anomaly=attachment_missing_program prog_id={program_id}"),
                ));
            }
        }
    }

    if let Some(programs) = programs {
        // Only a successful program inventory can prove that nothing is
        // attached.  A failed inventory silently disables this check instead
        // of turning every loaded XDP/TC program into a finding.
        if programs.available && net.available {
            for program in &programs.programs {
                if !is_xdp_tc_program(&program.program_type) {
                    continue;
                }
                let program_id = match program.id {
                    Some(program_id) => program_id,
                    None => continue,
                };
                if !attached_ids.contains(&program_id) {
                    findings.push(finding_for_detached_program(
                        generation,
                        program,
                        format!(
                            "anomaly=detached_xdp_tc_program type={} scope=transaction_netns",
                            program.program_type
                        ),
                    ));
                }
            }
        }
    }

    findings.sort();
    findings.dedup();
    findings
}

fn hook_group(hook: &str) -> &'static str {
    match hook.to_ascii_lowercase().as_str() {
        "prerouting" | "input" | "ingress" => "ingress",
        "postrouting" | "output" | "egress" => "egress",
        "forward" => "forward",
        _ => "unknown",
    }
}

fn attachment_group(attachment: &BpfAttachment) -> &'static str {
    match attachment.direction.to_ascii_lowercase().as_str() {
        "ingress" => "ingress",
        "egress" => "egress",
        "forward" => "forward",
        _ => hook_group(&attachment.hook),
    }
}

fn families_compatible(left: &str, right: &str) -> bool {
    let left = left.to_ascii_lowercase();
    let right = right.to_ascii_lowercase();
    if left == right || left == "any" || right == "any" {
        return true;
    }
    let ip_family = |value: &str| {
        matches!(
            value,
            "ip" | "ip6" | "ipv4" | "ipv6" | "inet" | "inet6"
        )
    };
    if left == "inet" && ip_family(&right) {
        return true;
    }
    if right == "inet" && ip_family(&left) {
        return true;
    }
    false
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PacketPathKey {
    pub netns_inum: u32,
    pub interface: String,
    pub group: String,
    pub family: String,
}

impl PacketPathKey {
    pub fn label(&self) -> String {
        format!(
            "path:{}/{}/{}/{}",
            self.netns_inum, self.interface, self.group, self.family
        )
    }
}

/// Correlate only anchors that really share one physical packet path.
///
/// Regular (and therefore old/cloaking) chains are deliberately not anchors;
/// they can only be attributed through the base chain that jumps to them.
/// This is what prevents an old table's chain from being rendered as the same
/// path as a freshly attached XDP program.
pub fn analyze_packet_paths(
    netfilter: &NetfilterSnapshot,
    net: &BpfNetSnapshot,
    generation: &PacketPathGeneration,
) -> Vec<PacketPathObservation> {
    let mut netfilter_paths: BTreeMap<PacketPathKey, Vec<&NetfilterChain>> = BTreeMap::new();
    for chain in &netfilter.chains {
        let hook = match &chain.hook {
            Some(hook) => hook,
            None => continue,
        };
        let group = hook_group(hook);
        if group == "unknown" {
            continue;
        }
        let interfaces: Vec<String> = if chain.interfaces.is_empty() {
            vec!["any".to_string()]
        } else {
            chain.interfaces.iter().cloned().collect()
        };
        for interface in interfaces {
            netfilter_paths
                .entry(PacketPathKey {
                    netns_inum: generation.netns_inum(),
                    interface,
                    group: group.to_string(),
                    family: chain.family.clone(),
                })
                .or_default()
                .push(chain);
        }
    }

    let mut observations: BTreeMap<
        (u32, String, String, String, Vec<ChainId>),
        PacketPathObservation,
    > = BTreeMap::new();
    let mut joined_attachments: BTreeSet<(String, Option<u64>, String, String)> =
        BTreeSet::new();

    for attachment in &net.attachments {
        if attachment.ifname.is_empty() || attachment.ifname == "unknown" {
            continue;
        }
        let group = attachment_group(attachment);
        if group == "unknown" {
            continue;
        }

        for (key, chains) in &netfilter_paths {
            if key.netns_inum != generation.netns_inum() || key.group != group {
                continue;
            }
            if key.interface != "any" && key.interface != attachment.ifname {
                continue;
            }
            if !families_compatible(&key.family, &attachment.family) {
                continue;
            }

            let mut chain_ids: Vec<ChainId> =
                chains.iter().map(|chain| chain.id()).collect();
            chain_ids.sort();
            chain_ids.dedup();
            if chain_ids.is_empty() {
                continue;
            }
            let tables: Vec<String> = chain_ids
                .iter()
                .map(|chain| format!("{}/{}", chain.family, chain.table))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let observation_key = (
                generation.netns_inum(),
                attachment.ifname.clone(),
                group.to_string(),
                key.family.clone(),
                chain_ids.clone(),
            );
            let path = format!(
                "joint:{}/{}/{}/{}",
                generation.netns_inum(),
                attachment.ifname,
                group,
                key.family
            );
            let observation =
                observations
                    .entry(observation_key)
                    .or_insert_with(|| PacketPathObservation {
                        netns_inum: generation.netns_inum(),
                        generation: generation.label(),
                        plane: PathPlane::Joint,
                        interface: attachment.ifname.clone(),
                        ifindex: attachment.ifindex,
                        hook_group: group.to_string(),
                        direction: group.to_string(),
                        family: key.family.clone(),
                        tables,
                        chains: chain_ids,
                        programs: Vec::new(),
                        path,
                    });
            observation.programs.push(ProgramRef {
                program_id: attachment.program_id,
                program_name: attachment.program_name.clone(),
                attach_type: attachment.attach_type.clone(),
                mode: attachment.mode.clone(),
            });
            joined_attachments.insert(attachment_key(attachment));
        }
    }

    let mut result: Vec<PacketPathObservation> = observations.into_values().collect();

    // Keep every legitimate interface/program attachment attributed even when
    // no netfilter base chain happens to share that path.  These records use
    // the independent `bpf:` plane and can never be mistaken for a netfilter
    // table/chain finding.
    for attachment in &net.attachments {
        if attachment.ifname.is_empty() || attachment.ifname == "unknown" {
            continue;
        }
        let group = attachment_group(attachment);
        if group == "unknown" || joined_attachments.contains(&attachment_key(attachment)) {
            continue;
        }
        let path = format!(
            "bpf:{}/{}/{}/{}/{}",
            generation.netns_inum(),
            attachment.ifname,
            group,
            "any",
            optional_u64(attachment.program_id)
        );
        result.push(PacketPathObservation {
            netns_inum: generation.netns_inum(),
            generation: generation.label(),
            plane: PathPlane::Bpf,
            interface: attachment.ifname.clone(),
            ifindex: attachment.ifindex,
            hook_group: group.to_string(),
            direction: group.to_string(),
            family: "any".to_string(),
            tables: Vec::new(),
            chains: Vec::new(),
            programs: vec![ProgramRef {
                program_id: attachment.program_id,
                program_name: attachment.program_name.clone(),
                attach_type: attachment.attach_type.clone(),
                mode: attachment.mode.clone(),
            }],
            path,
        });
    }

    for observation in &mut result {
        observation.programs.sort();
        observation.programs.dedup();
    }
    result.sort();
    result.dedup();
    result
}

fn attachment_key(
    attachment: &BpfAttachment,
) -> (String, Option<u64>, String, String) {
    (
        attachment.ifname.clone(),
        attachment.program_id,
        attachment.hook.clone(),
        attachment.direction.clone(),
    )
}

// ---------------------------------------------------------------------------
// Collector state and transaction
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum CollectorState<T> {
    Complete(T),
    Partial(T),
    Failed(String),
    Cancelled(String),
}

#[derive(Debug)]
struct Collector<T> {
    stamp: PacketPathStamp,
    state: CollectorState<T>,
}

impl<T> Collector<T> {
    fn collect(
        source: PacketPathSource,
        generation: &PacketPathGeneration,
        attempt: u64,
        result: Result<T, PacketPathFailure>,
        netns_of: fn(&T) -> u32,
        is_partial: fn(&T) -> bool,
    ) -> Self {
        let expected_netns = generation.netns_inum();
        let state = match result {
            Ok(value) => {
                let actual_netns = netns_of(&value);
                if expected_netns != 0 && actual_netns != 0 && expected_netns != actual_netns {
                    CollectorState::Failed(format!(
                        "source {} was collected in netns {} but the transaction owns netns {}; \
                         refusing to mix network namespaces",
                        source.label(),
                        actual_netns,
                        expected_netns
                    ))
                } else if (expected_netns == 0) != (actual_netns == 0) || is_partial(&value) {
                    CollectorState::Partial(value)
                } else {
                    CollectorState::Complete(value)
                }
            }
            Err(failure) if failure.cancelled => CollectorState::Cancelled(failure.reason),
            Err(failure) => CollectorState::Failed(failure.reason),
        };

        Self {
            stamp: PacketPathStamp {
                source,
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

    fn failure(&self) -> Option<PacketPathFailure> {
        match &self.state {
            CollectorState::Failed(reason) => Some(PacketPathFailure::failed(reason.clone())),
            CollectorState::Cancelled(reason) => {
                Some(PacketPathFailure::cancelled(reason.clone()))
            }
            CollectorState::Complete(_) | CollectorState::Partial(_) => None,
        }
    }

    fn stamp(&self) -> &PacketPathStamp {
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
) -> Result<&'a T, PacketPathFailure> {
    collector.value().ok_or_else(|| {
        collector
            .failure()
            .unwrap_or_else(|| PacketPathFailure::failed(missing_reason))
    })
}

/// Production collectors.  Tests can substitute deterministic functions.
#[derive(Clone, Copy)]
pub struct PacketPathBackend {
    pub netns: fn() -> Result<NetnsId, String>,
    pub netfilter: fn() -> Result<NetfilterSnapshot, PacketPathFailure>,
    pub bpf_net: fn() -> Result<BpfNetSnapshot, PacketPathFailure>,
    pub bpf_programs: fn() -> Result<BpfProgramSnapshot, PacketPathFailure>,
}

impl Default for PacketPathBackend {
    fn default() -> Self {
        Self {
            netns: live_netns,
            netfilter: live_netfilter,
            bpf_net: live_bpf_net,
            bpf_programs: live_bpf_programs,
        }
    }
}

fn netfilter_netns(snapshot: &NetfilterSnapshot) -> u32 {
    snapshot.netns_inum
}

fn bpf_net_netns(snapshot: &BpfNetSnapshot) -> u32 {
    snapshot.netns_inum
}

fn bpf_programs_netns(snapshot: &BpfProgramSnapshot) -> u32 {
    snapshot.netns_inum
}

fn netfilter_partial(snapshot: &NetfilterSnapshot) -> bool {
    !snapshot.errors.is_empty()
}

fn bpf_net_partial(snapshot: &BpfNetSnapshot) -> bool {
    !snapshot.errors.is_empty()
}

fn bpf_programs_partial(snapshot: &BpfProgramSnapshot) -> bool {
    !snapshot.errors.is_empty()
}

/// One packet-path transaction shared by all packet-path scanners.
pub struct PacketPathTransaction {
    generation: PacketPathGeneration,
    backend: PacketPathBackend,
    netfilter: Collector<NetfilterSnapshot>,
    bpf_net: Collector<BpfNetSnapshot>,
    bpf_programs: Collector<BpfProgramSnapshot>,
}

impl PacketPathTransaction {
    /// Start a transaction and collect all planes exactly once.
    pub fn start() -> Self {
        Self::start_with(PacketPathBackend::default())
    }

    /// Start a transaction with explicit collector functions.
    ///
    /// This is also the second-entry-point constructor used by tests and
    /// alternative front ends: every call creates a fresh generation, so it
    /// can never reuse another entry's evidence.
    pub fn start_with(backend: PacketPathBackend) -> Self {
        let generation = PacketPathGeneration::start_with_netns((backend.netns)());
        let (netfilter, bpf_net, bpf_programs) = collect_sources(backend, &generation);
        Self {
            generation,
            backend,
            netfilter,
            bpf_net,
            bpf_programs,
        }
    }

    /// Build a transaction from already parsed snapshots.  Used by tests and
    /// by embedding front ends that received the snapshots from elsewhere.
    pub fn from_snapshots(
        netns: NetnsId,
        netfilter: NetfilterSnapshot,
        bpf_net: BpfNetSnapshot,
        bpf_programs: BpfProgramSnapshot,
    ) -> Self {
        let generation = PacketPathGeneration::start_in(netns);
        let netfilter = Collector::collect(
            PacketPathSource::Netfilter,
            &generation,
            1,
            Ok(netfilter),
            netfilter_netns,
            netfilter_partial,
        );
        let bpf_net = Collector::collect(
            PacketPathSource::BpfNet,
            &generation,
            1,
            Ok(bpf_net),
            bpf_net_netns,
            bpf_net_partial,
        );
        let bpf_programs = Collector::collect(
            PacketPathSource::BpfPrograms,
            &generation,
            1,
            Ok(bpf_programs),
            bpf_programs_netns,
            bpf_programs_partial,
        );

        Self {
            generation,
            backend: PacketPathBackend::default(),
            netfilter,
            bpf_net,
            bpf_programs,
        }
    }

    pub fn generation(&self) -> &PacketPathGeneration {
        &self.generation
    }

    pub fn netns(&self) -> &NetnsId {
        self.generation.netns()
    }

    pub fn netns_inum(&self) -> u32 {
        self.generation.netns_inum()
    }

    /// Netfilter tables/chains/hooks collected for this generation.
    pub fn netfilter(&self) -> Result<&NetfilterSnapshot, PacketPathFailure> {
        require_value(&self.netfilter, "netfilter collector produced no evidence")
    }

    pub fn netfilter_snapshot(&self) -> Result<&NetfilterSnapshot, PacketPathFailure> {
        self.netfilter()
    }

    /// Interfaces and XDP/TC attachments collected for this generation.
    pub fn bpf_net(&self) -> Result<&BpfNetSnapshot, PacketPathFailure> {
        require_value(&self.bpf_net, "bpftool net collector produced no evidence")
    }

    pub fn bpf_snapshot(&self) -> Result<&BpfNetSnapshot, PacketPathFailure> {
        self.bpf_net()
    }

    /// eBPF program inventory collected for this generation.
    pub fn bpf_programs(&self) -> Result<&BpfProgramSnapshot, PacketPathFailure> {
        require_value(
            &self.bpf_programs,
            "bpftool prog collector produced no evidence",
        )
    }

    pub fn program_snapshot(&self) -> Result<&BpfProgramSnapshot, PacketPathFailure> {
        self.bpf_programs()
    }

    /// Alias used by scanner code that talks about programs directly.
    pub fn programs(&self) -> Result<&BpfProgramSnapshot, PacketPathFailure> {
        self.bpf_programs()
    }

    /// Interfaces attributed to the transaction's netns.
    pub fn interfaces(&self) -> BTreeSet<InterfaceRef> {
        self.bpf_net
            .value()
            .map(|snapshot| snapshot.interfaces.clone())
            .unwrap_or_default()
    }

    pub fn source_status(&self, source: PacketPathSource) -> CollectorStatus {
        match source {
            PacketPathSource::Netfilter => self.netfilter.status(),
            PacketPathSource::BpfNet => self.bpf_net.status(),
            PacketPathSource::BpfPrograms => self.bpf_programs.status(),
        }
    }

    pub fn collector_status(&self, source: PacketPathSource) -> Option<CollectorStatus> {
        Some(self.source_status(source))
    }

    pub fn source_stamp(&self, source: PacketPathSource) -> PacketPathStamp {
        match source {
            PacketPathSource::Netfilter => self.netfilter.stamp().clone(),
            PacketPathSource::BpfNet => self.bpf_net.stamp().clone(),
            PacketPathSource::BpfPrograms => self.bpf_programs.stamp().clone(),
        }
    }

    pub fn collector_stamp(&self, source: PacketPathSource) -> PacketPathStamp {
        self.source_stamp(source)
    }

    /// Mark one plane cancelled.  The value is dropped immediately; a read
    /// after cancellation cannot silently reuse evidence from this attempt.
    pub fn cancel(&mut self, source: PacketPathSource, reason: impl Into<String>) {
        let reason = reason.into();
        match source {
            PacketPathSource::Netfilter => self.netfilter.cancel(reason),
            PacketPathSource::BpfNet => self.bpf_net.cancel(reason),
            PacketPathSource::BpfPrograms => self.bpf_programs.cancel(reason),
        }
    }

    /// Retry a failed or cancelled plane.
    ///
    /// A packet path is only meaningful when every plane was read at the same
    /// instant.  Patching just the failed plane would mix the old netfilter
    /// generation with a new XDP generation, so the whole transaction is
    /// restarted under a new generation instead.  Evidence that already
    /// succeeded is never replaced in place.
    pub fn retry_failed(
        &mut self,
        source: PacketPathSource,
    ) -> Result<CollectorStatus, String> {
        let current = self.source_status(source);
        if !current.needs_retry() {
            return Err(format!(
                "source {} is {}; refusing to replace evidence in generation {}",
                source.label(),
                current.label(),
                self.generation.label()
            ));
        }

        // Recollect every plane in a fresh generation.  This is the only
        // retry form that cannot combine two packet-path generations.
        let generation = PacketPathGeneration::start_with_netns((self.backend.netns)());
        let (netfilter, bpf_net, bpf_programs) = collect_sources(self.backend, &generation);
        self.generation = generation;
        self.netfilter = netfilter;
        self.bpf_net = bpf_net;
        self.bpf_programs = bpf_programs;
        Ok(self.source_status(source))
    }

    /// Alias documented for callers that prefer the transaction vocabulary.
    pub fn retry_all_failed(
        &mut self,
        source: PacketPathSource,
    ) -> Result<CollectorStatus, String> {
        self.retry_failed(source)
    }

    pub fn has_usable_evidence(&self) -> bool {
        self.netfilter.status().is_usable()
            || self.bpf_net.status().is_usable()
            || self.bpf_programs.status().is_usable()
    }

    /// All findings derived from this generation's snapshots.
    pub fn findings(&self) -> Vec<PacketPathFinding> {
        self.report().findings().to_vec()
    }

    pub fn risk_findings(&self) -> Vec<PacketPathFinding> {
        self.findings()
    }

    pub fn observations(&self) -> Vec<PacketPathObservation> {
        self.report().observations().to_vec()
    }

    /// Build the final report from this generation only.
    pub fn report(&self) -> PacketPathReport {
        let collectors = vec![
            collector_report(
                &self.netfilter,
                self.netfilter_item_count(),
                self.netfilter_error_count(),
                self.netfilter.value().map(|snapshot| snapshot.fingerprint.clone()),
            ),
            collector_report(
                &self.bpf_net,
                self.bpf_net_item_count(),
                self.bpf_net_error_count(),
                self.bpf_net.value().map(|snapshot| snapshot.fingerprint.clone()),
            ),
            collector_report(
                &self.bpf_programs,
                self.bpf_programs_item_count(),
                self.bpf_programs_error_count(),
                self.bpf_programs
                    .value()
                    .map(|snapshot| snapshot.fingerprint.clone()),
            ),
        ];
        let mut merge = PacketPathMerge::new(&self.generation);
        for collector in &collectors {
            merge.offer(&collector.stamp);
        }

        let mut findings = Vec::new();
        if let Some(snapshot) = self.netfilter.value() {
            findings.extend(analyze_netfilter(snapshot, &self.generation));
        }
        if let Some(snapshot) = self.bpf_net.value() {
            findings.extend(analyze_bpf(
                snapshot,
                self.bpf_programs.value(),
                &self.generation,
            ));
        }
        findings.sort();
        findings.dedup();

        let observations = match (self.netfilter.value(), self.bpf_net.value()) {
            (Some(netfilter), Some(bpf_net)) => {
                analyze_packet_paths(netfilter, bpf_net, &self.generation)
            }
            _ => Vec::new(),
        };

        PacketPathReport {
            generation: self.generation.clone(),
            collectors,
            merge,
            findings,
            observations,
        }
    }

    fn netfilter_item_count(&self) -> usize {
        self.netfilter
            .value()
            .map(|snapshot| snapshot.chains.len())
            .unwrap_or(0)
    }

    fn netfilter_error_count(&self) -> usize {
        self.netfilter
            .value()
            .map(|snapshot| snapshot.errors.len())
            .unwrap_or(0)
    }

    fn bpf_net_item_count(&self) -> usize {
        self.bpf_net
            .value()
            .map(|snapshot| snapshot.attachments.len())
            .unwrap_or(0)
    }

    fn bpf_net_error_count(&self) -> usize {
        self.bpf_net
            .value()
            .map(|snapshot| snapshot.errors.len())
            .unwrap_or(0)
    }

    fn bpf_programs_item_count(&self) -> usize {
        self.bpf_programs
            .value()
            .map(|snapshot| snapshot.programs.len())
            .unwrap_or(0)
    }

    fn bpf_programs_error_count(&self) -> usize {
        self.bpf_programs
            .value()
            .map(|snapshot| snapshot.errors.len())
            .unwrap_or(0)
    }
}

fn collect_sources(
    backend: PacketPathBackend,
    generation: &PacketPathGeneration,
) -> (
    Collector<NetfilterSnapshot>,
    Collector<BpfNetSnapshot>,
    Collector<BpfProgramSnapshot>,
) {
    (
        Collector::collect(
            PacketPathSource::Netfilter,
            generation,
            1,
            (backend.netfilter)(),
            netfilter_netns,
            netfilter_partial,
        ),
        Collector::collect(
            PacketPathSource::BpfNet,
            generation,
            1,
            (backend.bpf_net)(),
            bpf_net_netns,
            bpf_net_partial,
        ),
        Collector::collect(
            PacketPathSource::BpfPrograms,
            generation,
            1,
            (backend.bpf_programs)(),
            bpf_programs_netns,
            bpf_programs_partial,
        ),
    )
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct PacketPathCollectorReport {
    pub stamp: PacketPathStamp,
    pub status: CollectorStatus,
    pub item_count: usize,
    pub error_count: usize,
    pub fingerprint: Option<String>,
    pub detail: Option<String>,
}

impl PacketPathCollectorReport {
    pub fn source(&self) -> PacketPathSource {
        self.stamp.source
    }

    pub fn generation(&self) -> &PacketPathGeneration {
        &self.stamp.generation
    }

    pub fn attempt(&self) -> u64 {
        self.stamp.attempt
    }
}

fn collector_report<T>(
    collector: &Collector<T>,
    item_count: usize,
    error_count: usize,
    fingerprint: Option<String>,
) -> PacketPathCollectorReport {
    PacketPathCollectorReport {
        stamp: collector.stamp().clone(),
        status: collector.status(),
        item_count,
        error_count,
        fingerprint,
        detail: collector.failure().map(|failure| failure.reason),
    }
}

/// Checks that every offered stamp belongs to one generation *and* one
/// network namespace (the netns is part of the generation identity).
#[derive(Clone, Debug)]
pub struct PacketPathMerge {
    generation: PacketPathGeneration,
    accepted: usize,
    rejected: usize,
}

impl PacketPathMerge {
    pub fn new(generation: &PacketPathGeneration) -> Self {
        Self {
            generation: generation.clone(),
            accepted: 0,
            rejected: 0,
        }
    }

    pub fn offer(&mut self, stamp: &PacketPathStamp) -> bool {
        if stamp.belongs_to(&self.generation) && stamp.same_netns(&self.generation) {
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

/// Alias matching the host-observation vocabulary.
pub type GenerationMerge = PacketPathMerge;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketPathEvidenceStatus {
    Complete,
    Partial,
    Failed,
}

impl PacketPathEvidenceStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Complete => "COMPLETE",
            Self::Partial => "PARTIAL",
            Self::Failed => "FAILED",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketPathVerdict {
    Consistent,
    Findings,
    Inconclusive,
}

impl PacketPathVerdict {
    pub fn label(self) -> &'static str {
        match self {
            Self::Consistent => "CONSISTENT",
            Self::Findings => "FINDINGS",
            Self::Inconclusive => "INCONCLUSIVE",
        }
    }
}

/// Final immutable report shared by the packet-path scanners and main.
#[derive(Clone, Debug)]
pub struct PacketPathReport {
    generation: PacketPathGeneration,
    collectors: Vec<PacketPathCollectorReport>,
    merge: PacketPathMerge,
    findings: Vec<PacketPathFinding>,
    observations: Vec<PacketPathObservation>,
}

impl PacketPathReport {
    pub fn generation(&self) -> &PacketPathGeneration {
        &self.generation
    }

    pub fn netns(&self) -> &NetnsId {
        self.generation.netns()
    }

    pub fn collector(&self, source: PacketPathSource) -> Option<&PacketPathCollectorReport> {
        self.collectors
            .iter()
            .find(|collector| collector.source() == source)
    }

    pub fn collector_status(&self, source: PacketPathSource) -> Option<CollectorStatus> {
        self.collector(source).map(|collector| collector.status)
    }

    pub fn collector_stamp(&self, source: PacketPathSource) -> Option<PacketPathStamp> {
        self.collector(source).map(|collector| collector.stamp.clone())
    }

    pub fn findings(&self) -> &[PacketPathFinding] {
        &self.findings
    }

    pub fn observations(&self) -> &[PacketPathObservation] {
        &self.observations
    }

    pub fn same_generation(&self) -> bool {
        self.merge.same_generation()
    }

    pub fn rejected_stamps(&self) -> usize {
        self.merge.rejected()
    }

    pub fn cross_generation_evidence(&self) -> usize {
        self.rejected_stamps()
    }

    pub fn risk_findings(&self) -> &[PacketPathFinding] {
        &self.findings
    }

    /// The only merge entry point: a stamp from another generation or netns
    /// is counted as rejected, never added to this report's evidence.
    pub fn accept_stamp(&mut self, stamp: &PacketPathStamp) -> bool {
        self.merge.offer(stamp)
    }

    pub fn merged_planes(&self) -> Vec<&'static str> {
        let mut planes = Vec::new();
        if self
            .collector(PacketPathSource::Netfilter)
            .map(|collector| collector.status.is_usable())
            .unwrap_or(false)
        {
            planes.push("netfilter");
        }
        let bpf_net = self
            .collector(PacketPathSource::BpfNet)
            .map(|collector| collector.status.is_usable())
            .unwrap_or(false);
        let bpf_programs = self
            .collector(PacketPathSource::BpfPrograms)
            .map(|collector| collector.status.is_usable())
            .unwrap_or(false);
        if bpf_net || bpf_programs {
            planes.push("bpf");
        }
        planes
    }

    pub fn merged_domains(&self) -> Vec<&'static str> {
        self.merged_planes()
    }

    pub fn evidence_status(&self) -> PacketPathEvidenceStatus {
        let usable = self
            .collectors
            .iter()
            .any(|collector| collector.status.is_usable());
        let complete = self
            .collectors
            .iter()
            .all(|collector| collector.status == CollectorStatus::Complete);
        if !usable {
            PacketPathEvidenceStatus::Failed
        } else if complete && self.same_generation() && self.generation.netns().is_known() {
            PacketPathEvidenceStatus::Complete
        } else {
            PacketPathEvidenceStatus::Partial
        }
    }

    pub fn verdict(&self) -> PacketPathVerdict {
        let any_usable = self
            .collectors
            .iter()
            .any(|collector| collector.status.is_usable());
        let all_complete = self
            .collectors
            .iter()
            .all(|collector| collector.status == CollectorStatus::Complete);
        if !any_usable || !self.same_generation() || !self.generation.netns().is_known() {
            PacketPathVerdict::Inconclusive
        } else if !self.findings.is_empty() {
            PacketPathVerdict::Findings
        } else if all_complete {
            PacketPathVerdict::Consistent
        } else {
            PacketPathVerdict::Inconclusive
        }
    }

    /// Render the stable report block appended after all scanners.
    pub fn render_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("generation={}", self.generation.label()),
            format!(
                "netns={} netns_inum={}",
                self.generation.netns().label(),
                self.generation.netns_inum()
            ),
        ];
        if let Some(err) = self.generation.netns_error() {
            lines.push(format!("netns_error={}", sanitize(err)));
        }

        for collector in &self.collectors {
            let mut line = format!(
                "{}={} attempt={} items={} errors={}",
                collector.source().label(),
                collector.status.label(),
                collector.attempt(),
                collector.item_count,
                collector.error_count
            );
            if let Some(detail) = &collector.detail {
                line.push_str(&format!(" reason={}", sanitize(detail)));
            }
            if let Some(fingerprint) = &collector.fingerprint {
                line.push_str(&format!(" fingerprint={fingerprint}"));
            }
            lines.push(line);
        }

        for observation in &self.observations {
            lines.push(observation.render_line());
        }
        for finding in &self.findings {
            lines.push(finding.render_line());
        }

        let planes = self.merged_planes();
        lines.push(format!(
            "merged_evidence={}",
            if planes.is_empty() {
                "none".to_string()
            } else {
                planes.join("+")
            }
        ));
        lines.push(format!("same_generation={}", self.same_generation()));
        lines.push(format!(
            "cross_generation_evidence={}",
            self.rejected_stamps()
        ));
        lines.push(format!("observations={}", self.observations.len()));
        lines.push(format!("risk_findings={}", self.findings.len()));
        lines.push(format!(
            "packet_path_evidence={}",
            self.evidence_status().label()
        ));
        lines.push(format!("packet_path={}", self.verdict().label()));
        lines
    }

    pub fn render(&self) -> String {
        self.render_lines().join("\n")
    }
}

/// Convenience for callers that only have parsed snapshots.
pub fn evaluate(
    netns: NetnsId,
    netfilter: NetfilterSnapshot,
    bpf_net: BpfNetSnapshot,
    bpf_programs: BpfProgramSnapshot,
) -> PacketPathReport {
    PacketPathTransaction::from_snapshots(netns, netfilter, bpf_net, bpf_programs).report()
}

// ---------------------------------------------------------------------------
// Live collection and parsers
// ---------------------------------------------------------------------------

fn live_netns() -> Result<NetnsId, String> {
    NetnsId::current()
}

pub fn live_netfilter() -> Result<NetfilterSnapshot, PacketPathFailure> {
    let output = Command::new("nft")
        .args(["-j", "list", "ruleset"])
        .output()
        .map_err(|err| PacketPathFailure::failed(format!("failed to execute nft: {err}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(PacketPathFailure::failed(format!(
            "nft exited with {}: {}",
            output.status,
            stderr.trim()
        )));
    }
    let netns_inum = parse_netns_link(Path::new("/proc/self/ns/net")).unwrap_or(0);
    parse_netfilter_json_with_netns(&output.stdout, netns_inum)
}

pub fn live_bpf_net() -> Result<BpfNetSnapshot, PacketPathFailure> {
    let output = Command::new("bpftool")
        .args(["-j", "net", "list"])
        .output()
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                PacketPathFailure::failed(
                    "bpftool not available to inspect XDP/TC programs".to_string(),
                )
            } else {
                PacketPathFailure::failed(format!("failed to execute bpftool net list: {err}"))
            }
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(PacketPathFailure::failed(format!(
            "bpftool net list exited with {}: {}",
            output.status,
            stderr.trim()
        )));
    }
    let netns_inum = parse_netns_link(Path::new("/proc/self/ns/net")).unwrap_or(0);
    parse_bpftool_net_json_with_netns(&output.stdout, netns_inum)
}

pub fn live_bpf_programs() -> Result<BpfProgramSnapshot, PacketPathFailure> {
    let output = Command::new("bpftool")
        .args(["-j", "prog", "list"])
        .output()
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                PacketPathFailure::failed(
                    "bpftool not available to inventory XDP/TC programs".to_string(),
                )
            } else {
                PacketPathFailure::failed(format!("failed to execute bpftool prog list: {err}"))
            }
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(PacketPathFailure::failed(format!(
            "bpftool prog list exited with {}: {}",
            output.status,
            stderr.trim()
        )));
    }
    let netns_inum = parse_netns_link(Path::new("/proc/self/ns/net")).unwrap_or(0);
    parse_bpftool_prog_json_with_netns(&output.stdout, netns_inum)
}

fn fingerprint(bytes: &[u8]) -> String {
    // Small deterministic FNV-1a fingerprint, enough to distinguish snapshots
    // without pulling a digest implementation into the hot path.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("fnv1a64:{hash:016x}")
}

pub fn parse_netfilter_json(raw: &[u8]) -> Result<NetfilterSnapshot, PacketPathFailure> {
    parse_netfilter_json_with_netns(raw, 0)
}

pub fn parse_netfilter_json_with_netns(
    raw: &[u8],
    netns_inum: u32,
) -> Result<NetfilterSnapshot, PacketPathFailure> {
    let root: Value = serde_json::from_slice(raw).map_err(|err| {
        PacketPathFailure::failed(format!("failed to parse nftables JSON: {err}"))
    })?;
    let entries = root
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(|| PacketPathFailure::failed("nftables JSON has no nftables array"))?;

    #[derive(Default)]
    struct ChainAccumulator {
        chain_type: Option<String>,
        hook: Option<String>,
        priority: Option<i64>,
        policy: Option<String>,
        rule_count: usize,
        interfaces: BTreeSet<String>,
        jump_targets: BTreeSet<String>,
        set_refs: BTreeSet<String>,
    }

    let mut tables: BTreeSet<TableId> = BTreeSet::new();
    let mut sets: BTreeSet<ScopedSet> = BTreeSet::new();
    let mut chains: BTreeMap<ChainId, ChainAccumulator> = BTreeMap::new();
    for entry in entries {
        let object = match entry.as_object() {
            Some(object) => object,
            None => continue,
        };

        if let Some(table) = object.get("table").and_then(Value::as_object) {
            if let (Some(family), Some(name)) = (
                table.get("family").and_then(Value::as_str),
                table.get("name").and_then(Value::as_str),
            ) {
                tables.insert(TableId {
                    family: family.to_string(),
                    table: name.to_string(),
                });
            }
        }

        if let Some(chain) = object.get("chain").and_then(Value::as_object) {
            if let (Some(family), Some(table), Some(name)) = (
                chain.get("family").and_then(Value::as_str),
                chain.get("table").and_then(Value::as_str),
                chain.get("name").and_then(Value::as_str),
            ) {
                tables.insert(TableId {
                    family: family.to_string(),
                    table: table.to_string(),
                });
                let accumulator = chains
                    .entry(ChainId {
                        family: family.to_string(),
                        table: table.to_string(),
                        chain: name.to_string(),
                    })
                    .or_default();
                accumulator.chain_type = chain
                    .get("type")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                accumulator.hook = chain
                    .get("hook")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                accumulator.priority = chain.get("prio").and_then(value_as_i64);
                accumulator.policy = chain
                    .get("policy")
                    .and_then(Value::as_str)
                    .map(str::to_string);
            }
        }

        if let Some(rule) = object.get("rule").and_then(Value::as_object) {
            if let (Some(family), Some(table), Some(chain_name)) = (
                rule.get("family").and_then(Value::as_str),
                rule.get("table").and_then(Value::as_str),
                rule.get("chain").and_then(Value::as_str),
            ) {
                tables.insert(TableId {
                    family: family.to_string(),
                    table: table.to_string(),
                });
                let accumulator = chains
                    .entry(ChainId {
                        family: family.to_string(),
                        table: table.to_string(),
                        chain: chain_name.to_string(),
                    })
                    .or_default();
                accumulator.rule_count += 1;
                if let Some(expression) = rule.get("expr") {
                    walk_expression(
                        expression,
                        false,
                        &mut accumulator.interfaces,
                        &mut accumulator.jump_targets,
                        &mut accumulator.set_refs,
                    );
                }
            }
        }

        if let Some(set) = object.get("set").and_then(Value::as_object) {
            if let (Some(family), Some(table), Some(name)) = (
                set.get("family").and_then(Value::as_str),
                set.get("table").and_then(Value::as_str),
                set.get("name").and_then(Value::as_str),
            ) {
                sets.insert(ScopedSet {
                    family: family.to_string(),
                    table: table.to_string(),
                    name: name.to_string(),
                });
            }
        }

        if let Some(map) = object.get("map").and_then(Value::as_object) {
            if let (Some(family), Some(table), Some(name)) = (
                map.get("family").and_then(Value::as_str),
                map.get("table").and_then(Value::as_str),
                map.get("name").and_then(Value::as_str),
            ) {
                sets.insert(ScopedSet {
                    family: family.to_string(),
                    table: table.to_string(),
                    name: name.to_string(),
                });
            }
        }
    }

    let mut chain_list = Vec::new();
    for (id, accumulator) in chains {
        chain_list.push(NetfilterChain {
            family: id.family,
            table: id.table,
            chain: id.chain,
            chain_type: accumulator.chain_type,
            hook: accumulator.hook,
            priority: accumulator.priority,
            policy: accumulator.policy,
            rule_count: accumulator.rule_count,
            interfaces: accumulator.interfaces,
            jump_targets: accumulator.jump_targets,
            set_refs: accumulator.set_refs,
        });
    }
    chain_list.sort_by(|left, right| left.id().cmp(&right.id()));

    Ok(NetfilterSnapshot {
        netns_inum,
        fingerprint: fingerprint(raw),
        source: "nft -j list ruleset".to_string(),
        tables,
        chains: chain_list,
        sets,
        errors: Vec::new(),
    })
}

fn value_as_i64(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|text| text.parse::<i64>().ok()))
}

fn value_as_u32(value: Option<&Value>) -> Option<u32> {
    value.and_then(|value| {
        value
            .as_u64()
            .map(|number| number.min(u64::from(u32::MAX)) as u32)
            .or_else(|| {
                value
                    .as_str()
                    .and_then(|text| text.parse::<u32>().ok())
            })
    })
}

fn value_as_u64(value: Option<&Value>) -> Option<u64> {
    value.and_then(|value| {
        value
            .as_u64()
            .or_else(|| value.as_str().and_then(|text| text.parse::<u64>().ok()))
    })
}

fn value_as_string(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::to_string)
        .or_else(|| value.as_u64().map(|number| number.to_string()))
}

fn walk_expression(
    value: &Value,
    set_context: bool,
    interfaces: &mut BTreeSet<String>,
    jumps: &mut BTreeSet<String>,
    sets: &mut BTreeSet<String>,
) {
    match value {
        Value::Object(map) => {
            if let Some(jump) = map.get("jump").or_else(|| map.get("goto")) {
                if let Some(target) = jump
                    .get("target")
                    .and_then(Value::as_str)
                    .or_else(|| jump.as_str())
                {
                    jumps.insert(target.to_string());
                }
            }
            if let Some(lookup) = map.get("lookup") {
                walk_expression(lookup, true, interfaces, jumps, sets);
            }
            if let Some(set) = map.get("set") {
                if set_context {
                    record_set_reference(set, sets);
                } else if let Some(name) = set.as_str() {
                    if name.starts_with('@') {
                        record_set_reference(set, sets);
                    }
                }
            }
            if let Some(map_value) = map.get("map") {
                if set_context {
                    record_set_reference(map_value, sets);
                }
            }
            if let Some(match_value) = map.get("match") {
                record_interfaces(match_value, interfaces);
                // Recurse for named-set references in the match body while
                // keeping interface literals out of the set inventory.
                walk_expression(match_value, set_context, interfaces, jumps, sets);
            }
            for (key, nested) in map {
                if key.as_str() == "jump" || key.as_str() == "goto" {
                    continue;
                }
                if matches!(key.as_str(), "lookup" | "match") {
                    continue;
                }
                walk_expression(nested, set_context, interfaces, jumps, sets);
            }
        }
        Value::Array(items) => {
            for item in items {
                walk_expression(item, set_context, interfaces, jumps, sets);
            }
        }
        Value::String(text) => {
            if let Some(name) = text.strip_prefix('@') {
                if !name.is_empty() {
                    sets.insert(name.to_string());
                }
            }
        }
        _ => {}
    }
}

fn record_set_reference(value: &Value, sets: &mut BTreeSet<String>) {
    match value {
        Value::String(text) => {
            let name = text.strip_prefix('@').unwrap_or(text);
            if !name.is_empty() {
                sets.insert(name.to_string());
            }
        }
        Value::Object(map) => {
            if let Some(name) = map.get("name").and_then(Value::as_str) {
                let name = name.strip_prefix('@').unwrap_or(name);
                if !name.is_empty() {
                    sets.insert(name.to_string());
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                record_set_reference(item, sets);
            }
        }
        _ => {}
    }
}

fn record_interfaces(match_value: &Value, interfaces: &mut BTreeSet<String>) {
    if let Some(operator) = match_value.get("op").and_then(Value::as_str) {
        if operator == "!=" {
            return;
        }
    }
    let key = match_value
        .get("left")
        .and_then(|left| left.get("meta"))
        .and_then(|meta| meta.get("key"))
        .and_then(Value::as_str);
    let key = match key {
        Some(key) => key,
        None => return,
    };
    if !matches!(key, "iifname" | "oifname" | "iif" | "oif") {
        return;
    }
    if let Some(right) = match_value.get("right") {
        collect_interface_values(right, interfaces);
    }
}

fn collect_interface_values(value: &Value, interfaces: &mut BTreeSet<String>) {
    match value {
        Value::String(text) => {
            if !text.starts_with('@') && !text.is_empty() && text.len() < 128 {
                interfaces.insert(text.to_string());
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_interface_values(item, interfaces);
            }
        }
        Value::Object(map) => {
            if let Some(prefix) = map.get("prefix").and_then(Value::as_str) {
                if !prefix.is_empty() {
                    interfaces.insert(format!("{prefix}*"));
                }
            } else if let Some(set) = map.get("set") {
                collect_interface_values(set, interfaces);
            }
        }
        _ => {}
    }
}

pub fn parse_bpftool_net_json(raw: &[u8]) -> Result<BpfNetSnapshot, PacketPathFailure> {
    parse_bpftool_net_json_with_netns(raw, 0)
}

pub fn parse_bpftool_net_json_with_netns(
    raw: &[u8],
    netns_inum: u32,
) -> Result<BpfNetSnapshot, PacketPathFailure> {
    if raw.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Ok(BpfNetSnapshot {
            netns_inum,
            fingerprint: fingerprint(raw),
            source: "bpftool -j net list".to_string(),
            available: true,
            ..BpfNetSnapshot::default()
        });
    }

    let root: Value = serde_json::from_slice(raw)
        .map_err(|err| PacketPathFailure::failed(format!("failed to parse bpftool net JSON: {err}")))?;
    let mut snapshot = BpfNetSnapshot {
        netns_inum,
        fingerprint: fingerprint(raw),
        source: "bpftool -j net list".to_string(),
        available: true,
        ..BpfNetSnapshot::default()
    };

    let devices = root
        .get("netdev")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for device in devices {
        let object = match device.as_object() {
            Some(object) => object,
            None => continue,
        };
        let ifindex = value_as_u32(object.get("ifindex"));
        let ifname = object
            .get("ifname")
            .or_else(|| object.get("devname"))
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        snapshot.interfaces.insert(InterfaceRef {
            ifindex,
            ifname: ifname.clone(),
        });

        for (kind, hook, default_direction) in [
            ("xdp", "xdp", "ingress"),
            ("tc", "tc", "ingress"),
        ] {
            let entries = object
                .get(kind)
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for entry in entries {
                let entry_object = match entry.as_object() {
                    Some(object) => object,
                    None => continue,
                };
                let explicit_direction = entry_object
                    .get("direction")
                    .and_then(Value::as_str)
                    .map(|direction| direction.to_ascii_lowercase());
                let attach_type = entry_object
                    .get("attach_type")
                    .and_then(Value::as_str)
                    .unwrap_or(default_direction)
                    .to_ascii_lowercase();
                let direction = match explicit_direction.as_deref() {
                    Some("ingress") => "ingress".to_string(),
                    Some("egress") => "egress".to_string(),
                    _ => match attach_type.as_str() {
                        "ingress" | "egress" => attach_type.clone(),
                        _ => default_direction.to_string(),
                    },
                };
                let entry_ifindex =
                    value_as_u32(entry_object.get("ifindex")).or(ifindex);
                let entry_ifname = entry_object
                    .get("ifname")
                    .or_else(|| entry_object.get("devname"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap_or_else(|| ifname.clone());
                let attachment = BpfAttachment {
                    ifindex: entry_ifindex,
                    ifname: entry_ifname,
                    program_id: value_as_u64(
                        entry_object
                            .get("prog_id")
                            .or_else(|| entry_object.get("id")),
                    ),
                    program_name: entry_object
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("unnamed")
                        .to_string(),
                    program_tag: entry_object
                        .get("tag")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    attach_type,
                    hook: hook.to_string(),
                    direction,
                    family: "any".to_string(),
                    mode: entry_object
                        .get("mode")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    priority: entry_object.get("priority").and_then(value_as_i64),
                };
                snapshot.interfaces.insert(InterfaceRef {
                    ifindex: attachment.ifindex,
                    ifname: attachment.ifname.clone(),
                });
                snapshot.attachments.push(attachment);
            }
        }
    }

    let netfilter_entries = root
        .get("netfilter")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for entry in netfilter_entries {
        let object = match entry.as_object() {
            Some(object) => object,
            None => continue,
        };
        let hook = object
            .get("hook")
            .map(netfilter_hook_name)
            .unwrap_or_else(|| "netfilter".to_string());
        let family = object
            .get("pf")
            .or_else(|| object.get("family"))
            .map(netfilter_family_name)
            .unwrap_or_else(|| "any".to_string());
        snapshot.attachments.push(BpfAttachment {
            ifindex: None,
            ifname: "any".to_string(),
            program_id: value_as_u64(object.get("prog_id").or_else(|| object.get("id"))),
            program_name: object
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("unnamed")
                .to_string(),
            program_tag: object
                .get("tag")
                .and_then(Value::as_str)
                .map(str::to_string),
            attach_type: "netfilter".to_string(),
            direction: hook_group(&hook).to_string(),
            hook,
            family,
            mode: None,
            priority: object.get("prio").and_then(value_as_i64),
        });
    }

    Ok(snapshot)
}

fn netfilter_hook_name(value: &Value) -> String {
    if let Some(text) = value.as_str() {
        return text.to_ascii_lowercase();
    }
    match value.as_u64() {
        Some(0) => "prerouting".to_string(),
        Some(1) => "input".to_string(),
        Some(2) => "forward".to_string(),
        Some(3) => "output".to_string(),
        Some(4) => "postrouting".to_string(),
        Some(5) => "ingress".to_string(),
        Some(6) => "egress".to_string(),
        Some(other) => format!("hook{other}"),
        None => "netfilter".to_string(),
    }
}

fn netfilter_family_name(value: &Value) -> String {
    if let Some(text) = value.as_str() {
        return text.to_ascii_lowercase();
    }
    match value.as_u64() {
        Some(2) => "ip".to_string(),
        Some(10) => "ip6".to_string(),
        Some(7) => "bridge".to_string(),
        Some(1) => "inet".to_string(),
        Some(other) => format!("pf{other}"),
        None => "any".to_string(),
    }
}

pub fn parse_bpftool_prog_json(raw: &[u8]) -> Result<BpfProgramSnapshot, PacketPathFailure> {
    parse_bpftool_prog_json_with_netns(raw, 0)
}

pub fn parse_bpftool_prog_json_with_netns(
    raw: &[u8],
    netns_inum: u32,
) -> Result<BpfProgramSnapshot, PacketPathFailure> {
    if raw.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Ok(BpfProgramSnapshot {
            netns_inum,
            fingerprint: fingerprint(raw),
            source: "bpftool -j prog list".to_string(),
            available: true,
            ..BpfProgramSnapshot::default()
        });
    }

    let root: Value = serde_json::from_slice(raw).map_err(|err| {
        PacketPathFailure::failed(format!("failed to parse bpftool prog JSON: {err}"))
    })?;
    let entries = match &root {
        Value::Array(items) => items.clone(),
        Value::Object(map) => map
            .get("programs")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        _ => Vec::new(),
    };

    let mut programs = Vec::new();
    for entry in entries {
        let object = match entry.as_object() {
            Some(object) => object,
            None => continue,
        };
        programs.push(BpfProgram {
            id: value_as_u64(object.get("id").or_else(|| object.get("prog_id"))),
            name: object
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("unnamed")
                .to_string(),
            tag: object
                .get("tag")
                .and_then(Value::as_str)
                .map(str::to_string),
            program_type: object
                .get("type")
                .and_then(value_as_string)
                .unwrap_or_else(|| "unknown".to_string()),
            ifindex: value_as_u32(object.get("ifindex")),
            ifname: object
                .get("ifname")
                .and_then(Value::as_str)
                .map(str::to_string),
            pinned: object
                .get("pinned")
                .map(|value| value.as_bool().unwrap_or_else(|| value.as_str().is_some()))
                .unwrap_or(false),
            loaded: true,
        });
    }
    programs.sort();

    Ok(BpfProgramSnapshot {
        netns_inum,
        fingerprint: fingerprint(raw),
        source: "bpftool -j prog list".to_string(),
        available: true,
        programs,
        errors: Vec::new(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    static RETRY_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn netns() -> NetnsId {
        NetnsId::new(4026531840, "net:[4026531840]")
    }

    #[test]
    fn parses_netns_link_target() {
        assert_eq!(
            parse_netns_link_target("net:[4026531840]").expect("netns link"),
            4026531840
        );
        assert!(parse_netns_link_target("not-a-netns").is_err());
    }

    fn chain(
        family: &str,
        table: &str,
        name: &str,
        chain_type: Option<&str>,
        hook: Option<&str>,
        interfaces: &[&str],
        rule_count: usize,
        jumps: &[&str],
    ) -> NetfilterChain {
        NetfilterChain {
            family: family.to_string(),
            table: table.to_string(),
            chain: name.to_string(),
            chain_type: chain_type.map(str::to_string),
            hook: hook.map(str::to_string),
            priority: None,
            policy: None,
            rule_count,
            interfaces: interfaces.iter().map(|value| value.to_string()).collect(),
            jump_targets: jumps.iter().map(|value| value.to_string()).collect(),
            set_refs: BTreeSet::new(),
        }
    }

    fn netfilter(chains: Vec<NetfilterChain>) -> NetfilterSnapshot {
        let mut tables = BTreeSet::new();
        for item in &chains {
            tables.insert(TableId {
                family: item.family.clone(),
                table: item.table.clone(),
            });
        }
        NetfilterSnapshot {
            netns_inum: netns().inum,
            fingerprint: "test-netfilter".to_string(),
            source: "test".to_string(),
            tables,
            chains,
            sets: BTreeSet::new(),
            errors: Vec::new(),
        }
    }

    fn attachment(
        ifname: &str,
        ifindex: u32,
        program_id: u64,
        program_name: &str,
        hook: &str,
        direction: &str,
    ) -> BpfAttachment {
        BpfAttachment {
            ifindex: Some(ifindex),
            ifname: ifname.to_string(),
            program_id: Some(program_id),
            program_name: program_name.to_string(),
            program_tag: None,
            attach_type: direction.to_string(),
            hook: hook.to_string(),
            direction: direction.to_string(),
            family: "any".to_string(),
            mode: Some("native".to_string()),
            priority: None,
        }
    }

    fn bpf_net(attachments: Vec<BpfAttachment>) -> BpfNetSnapshot {
        let mut interfaces = BTreeSet::new();
        for item in &attachments {
            interfaces.insert(InterfaceRef {
                ifindex: item.ifindex,
                ifname: item.ifname.clone(),
            });
        }
        BpfNetSnapshot {
            netns_inum: netns().inum,
            fingerprint: "test-bpf-net".to_string(),
            source: "test".to_string(),
            available: true,
            interfaces,
            attachments,
            errors: Vec::new(),
        }
    }

    fn programs(entries: Vec<(u64, &str, &str)>) -> BpfProgramSnapshot {
        BpfProgramSnapshot {
            netns_inum: netns().inum,
            fingerprint: "test-programs".to_string(),
            source: "test".to_string(),
            available: true,
            programs: entries
                .into_iter()
                .map(|(id, name, kind)| BpfProgram {
                    id: Some(id),
                    name: name.to_string(),
                    tag: None,
                    program_type: kind.to_string(),
                    ifindex: None,
                    ifname: None,
                    pinned: false,
                    loaded: true,
                })
                .collect(),
            errors: Vec::new(),
        }
    }

    fn clean_snapshots() -> (NetfilterSnapshot, BpfNetSnapshot, BpfProgramSnapshot) {
        let netfilter = netfilter(vec![
            chain("ip", "filter", "INPUT", Some("filter"), Some("input"), &["eth0"], 2, &[]),
            chain("ip6", "filter", "INPUT", Some("filter"), Some("input"), &["eth0"], 1, &[]),
            chain("inet", "nft", "input", Some("filter"), Some("input"), &["eth0"], 0, &[]),
            // A legal empty regular chain, not referenced by any jump.
            chain("ip", "filter", "EMPTY", None, None, &[], 0, &[]),
        ]);
        let bpf_net = bpf_net(vec![
            attachment("eth0", 2, 101, "xdp_pass", "xdp", "ingress"),
            attachment("eth0", 2, 102, "tc_filter", "tc", "egress"),
            attachment("eth1", 3, 103, "tc_ingress", "tc", "ingress"),
        ]);
        let programs = programs(vec![
            (101, "xdp_pass", "xdp"),
            (102, "tc_filter", "sched_cls"),
            (103, "tc_ingress", "sched_cls"),
        ]);
        (netfilter, bpf_net, programs)
    }

    #[test]
    fn legitimate_ipv4_ipv6_iptables_nftables_xdp_tc_and_empty_chains_are_clean() {
        let (netfilter, bpf_net, programs) = clean_snapshots();
        let report = evaluate(netns(), netfilter, bpf_net, programs);

        assert!(report.findings().is_empty(), "unexpected findings: {:?}", report.findings());
        assert_eq!(report.verdict(), PacketPathVerdict::Consistent);
        assert!(report.same_generation());
        assert!(!report.observations().is_empty());
        assert!(report.merged_planes().contains(&"netfilter"));
        assert!(report.merged_planes().contains(&"bpf"));
    }

    #[test]
    fn empty_regular_chain_is_never_a_finding() {
        let netfilter = netfilter(vec![
            chain("ip", "filter", "INPUT", Some("filter"), Some("input"), &["eth0"], 0, &[]),
            chain("ip", "filter", "UNUSED", None, None, &[], 0, &[]),
        ]);
        let report = evaluate(netns(), netfilter, BpfNetSnapshot::default(), BpfProgramSnapshot::default());
        assert!(report.findings().is_empty());
    }

    #[test]
    fn orphan_base_chain_missing_jump_and_unresolved_set_keep_attribution() {
        let mut with_set = chain(
            "ip",
            "filter",
            "INPUT",
            Some("filter"),
            Some("input"),
            &["eth0"],
            2,
            &["missing_chain"],
        );
        with_set.set_refs.insert("undefined_set".to_string());
        let netfilter = netfilter(vec![
            chain("ip", "filter", "BROKEN", Some("filter"), None, &[], 1, &[]),
            with_set,
        ]);
        let report = evaluate(
            netns(),
            netfilter,
            BpfNetSnapshot {
                netns_inum: netns().inum,
                ..BpfNetSnapshot::default()
            },
            BpfProgramSnapshot {
                netns_inum: netns().inum,
                ..BpfProgramSnapshot::default()
            },
        );

        let kinds: BTreeSet<&str> = report
            .findings()
            .iter()
            .map(|finding| finding.kind.label())
            .collect();
        assert!(kinds.contains("orphan_base_chain"));
        assert!(kinds.contains("jump_to_missing_handle"));
        assert!(kinds.contains("anon_set_unresolved"));
        for finding in report.findings() {
            assert_eq!(finding.netns_inum, netns().inum);
            assert_eq!(finding.program, "none");
            assert_eq!(finding.table, "ip");
        }
    }

    #[test]
    fn old_cloaking_chain_and_new_xdp_program_never_share_a_path() {
        // The incident: the hook moved from table `old` to table `new`.  The
        // old table still has a non-empty regular cloaking chain; XDP was
        // attached to eth0 just after the migration.
        let netfilter = netfilter(vec![
            chain("inet", "old", "cloak", None, None, &[], 3, &[]),
            chain("inet", "new", "input", Some("filter"), Some("input"), &["eth0"], 4, &[]),
        ]);
        let bpf_net = bpf_net(vec![attachment("eth0", 2, 201, "xdp_migrated", "xdp", "ingress")]);
        let programs = programs(vec![(201, "xdp_migrated", "xdp")]);
        let report = evaluate(netns(), netfilter, bpf_net, programs);

        let cloak = report
            .findings()
            .iter()
            .find(|finding| finding.kind == FindingKind::CloakedChain)
            .expect("cloaking chain finding");
        assert_eq!(cloak.table, "old");
        assert_eq!(cloak.chain, "cloak");
        assert_eq!(cloak.plane, PathPlane::Netfilter);
        assert!(cloak.path.starts_with("netfilter:"));

        let joint = report
            .observations()
            .iter()
            .find(|observation| observation.interface == "eth0")
            .expect("joint path for new table and XDP");
        assert!(joint.path.starts_with("joint:"));
        assert!(joint.tables.contains(&"inet/new".to_string()));
        assert!(
            !joint.tables.contains(&"inet/old".to_string()),
            "the orphaned old chain must not be attributed to the XDP path"
        );
        assert_ne!(cloak.path, joint.path);
        for observation in report.observations() {
            assert_ne!(cloak.path, observation.path);
        }
    }

    #[test]
    fn each_finding_attributes_netns_table_interface_program_and_finding() {
        let netfilter = netfilter(vec![
            chain("inet", "old", "cloak", None, None, &[], 1, &[]),
        ]);
        let report = evaluate(
            netns(),
            netfilter,
            BpfNetSnapshot::default(),
            BpfProgramSnapshot::default(),
        );
        let line = report.findings()[0].render_line();
        for field in [
            "netns=",
            "table=",
            "chain=",
            "hook=",
            "interface=",
            "program=",
            "finding=",
            "generation=",
        ] {
            assert!(line.contains(field), "missing {field} in {line}");
        }
        assert!(line.contains("finding=cloaked_chain"));
        assert!(line.contains("table=old"));
        assert!(line.contains("program=none"));
    }

    #[test]
    fn cross_generation_and_cross_netns_stamps_are_rejected() {
        let first = PacketPathTransaction::from_snapshots(
            netns(),
            netfilter(vec![chain("ip", "filter", "INPUT", Some("filter"), Some("input"), &[], 0, &[])]),
            BpfNetSnapshot::default(),
            BpfProgramSnapshot::default(),
        );
        let second = PacketPathTransaction::from_snapshots(
            netns(),
            netfilter(vec![chain("ip", "filter", "INPUT", Some("filter"), Some("input"), &[], 0, &[])]),
            BpfNetSnapshot::default(),
            BpfProgramSnapshot::default(),
        );
        let mut report = second.report();
        let stale = first.source_stamp(PacketPathSource::Netfilter);
        assert!(!report.accept_stamp(&stale));
        assert_eq!(report.rejected_stamps(), 1);
        assert!(!report.same_generation());
        assert_eq!(report.verdict(), PacketPathVerdict::Inconclusive);

        let other_netns = NetnsId::new(4026531999, "net:[4026531999]");
        let foreign = PacketPathTransaction::from_snapshots(
            other_netns,
            NetfilterSnapshot {
                netns_inum: 4026531999,
                ..NetfilterSnapshot::default()
            },
            BpfNetSnapshot {
                netns_inum: 4026531999,
                ..BpfNetSnapshot::default()
            },
            BpfProgramSnapshot {
                netns_inum: 4026531999,
                ..BpfProgramSnapshot::default()
            },
        );
        let foreign_stamp = foreign.source_stamp(PacketPathSource::Netfilter);
        assert!(!report.accept_stamp(&foreign_stamp));
        assert_eq!(report.rejected_stamps(), 2);
    }

    #[test]
    fn second_entry_point_gets_a_distinct_generation_and_cannot_mix() {
        let first = PacketPathTransaction::start_with(PacketPathBackend {
            netns: test_netns,
            netfilter: ok_old_netfilter,
            bpf_net: empty_bpf_net,
            bpf_programs: empty_programs,
        });
        let second = PacketPathTransaction::start_with(PacketPathBackend {
            netns: test_netns,
            netfilter: ok_new_netfilter,
            bpf_net: ok_xdp_net,
            bpf_programs: ok_xdp_programs,
        });

        assert_ne!(first.generation().label(), second.generation().label());
        assert!(first
            .findings()
            .iter()
            .all(|finding| finding.table != "new"));
        assert!(second
            .findings()
            .iter()
            .all(|finding| finding.table != "old"));
    }

    #[test]
    fn rule_hot_update_between_rounds_does_not_leak_old_evidence() {
        let old_round = PacketPathTransaction::start_with(PacketPathBackend {
            netns: test_netns,
            netfilter: ok_old_netfilter,
            bpf_net: empty_bpf_net,
            bpf_programs: empty_programs,
        });
        let new_round = PacketPathTransaction::start_with(PacketPathBackend {
            netns: test_netns,
            netfilter: ok_new_netfilter,
            bpf_net: ok_xdp_net,
            bpf_programs: ok_xdp_programs,
        });

        assert!(old_round.findings().iter().any(|finding| finding.table == "old"));
        assert!(!new_round.findings().iter().any(|finding| finding.table == "old"));
        let mut report = new_round.report();
        assert!(!report.accept_stamp(&old_round.source_stamp(PacketPathSource::Netfilter)));
        assert_eq!(report.rejected_stamps(), 1);
    }

    #[test]
    fn retry_restarts_every_plane_in_a_new_generation() {
        RETRY_CALLS.store(0, AtomicOrdering::SeqCst);
        let mut transaction = PacketPathTransaction::start_with(PacketPathBackend {
            netns: test_netns,
            netfilter: flaky_netfilter,
            bpf_net: ok_xdp_net,
            bpf_programs: ok_xdp_programs,
        });
        let first_generation = transaction.generation().label();
        assert_eq!(transaction.source_status(PacketPathSource::Netfilter), CollectorStatus::Failed);
        assert_eq!(transaction.source_status(PacketPathSource::BpfNet), CollectorStatus::Complete);

        let status = transaction
            .retry_failed(PacketPathSource::Netfilter)
            .expect("retry restarts the transaction");
        assert_eq!(status, CollectorStatus::Complete);
        assert_ne!(first_generation, transaction.generation().label());
        // The successful BPF plane was also recollected, so the report only
        // sees stamps from the new generation.
        assert!(transaction.report().same_generation());
        assert_eq!(transaction.source_stamp(PacketPathSource::BpfNet).attempt, 1);
    }

    #[test]
    fn successful_plane_cannot_be_replaced_by_retry() {
        let mut transaction = PacketPathTransaction::start_with(PacketPathBackend {
            netns: test_netns,
            netfilter: ok_new_netfilter,
            bpf_net: ok_xdp_net,
            bpf_programs: ok_xdp_programs,
        });
        assert!(transaction
            .retry_failed(PacketPathSource::Netfilter)
            .is_err());
        assert_eq!(
            transaction.source_status(PacketPathSource::Netfilter),
            CollectorStatus::Complete
        );
    }

    #[test]
    fn failed_or_partial_plane_cannot_publish_a_clean_packet_path() {
        let transaction = PacketPathTransaction::start_with(PacketPathBackend {
            netns: test_netns,
            netfilter: ok_new_netfilter,
            bpf_net: ok_xdp_net,
            bpf_programs: failed_programs,
        });
        let report = transaction.report();
        assert_eq!(
            transaction.source_status(PacketPathSource::BpfPrograms),
            CollectorStatus::Failed
        );
        assert_eq!(report.verdict(), PacketPathVerdict::Inconclusive);
        assert_eq!(report.evidence_status(), PacketPathEvidenceStatus::Partial);
    }

    #[test]
    fn cancel_drops_previous_value_and_retry_cannot_revive_it_in_place() {
        let mut transaction = PacketPathTransaction::start_with(PacketPathBackend {
            netns: test_netns,
            netfilter: ok_new_netfilter,
            bpf_net: ok_xdp_net,
            bpf_programs: ok_xdp_programs,
        });
        assert!(transaction.bpf_net().is_ok());
        transaction.cancel(PacketPathSource::BpfNet, "operator cancelled");
        assert!(transaction.bpf_net().is_err());
        assert_eq!(
            transaction.source_status(PacketPathSource::BpfNet),
            CollectorStatus::Cancelled
        );
        // Even a retry starts a new generation; it cannot resurrect the
        // cancelled value under the old stamp.
        let old_generation = transaction.generation().label();
        let _ = transaction.retry_failed(PacketPathSource::BpfNet);
        assert_ne!(old_generation, transaction.generation().label());
    }

    #[test]
    fn foreign_netns_snapshot_is_rejected_instead_of_joined() {
        let transaction = PacketPathTransaction::from_snapshots(
            netns(),
            NetfilterSnapshot {
                netns_inum: 1,
                ..NetfilterSnapshot::default()
            },
            BpfNetSnapshot {
                netns_inum: 1,
                ..BpfNetSnapshot::default()
            },
            BpfProgramSnapshot {
                netns_inum: 1,
                ..BpfProgramSnapshot::default()
            },
        );
        assert!(transaction.netfilter().is_err());
        assert!(transaction.bpf_net().is_err());
        assert_eq!(
            transaction.source_status(PacketPathSource::Netfilter),
            CollectorStatus::Failed
        );
    }

    #[test]
    fn attachment_without_interface_is_attributed_to_the_program() {
        let mut attached = attachment("", 0, 301, "xdp_orphan", "xdp", "ingress");
        attached.ifindex = None;
        attached.ifname = String::new();
        let report = evaluate(
            netns(),
            NetfilterSnapshot {
                netns_inum: netns().inum,
                ..NetfilterSnapshot::default()
            },
            bpf_net(vec![attached]),
            programs(vec![(301, "xdp_orphan", "xdp")]),
        );
        let finding = report
            .findings()
            .iter()
            .find(|finding| finding.kind == FindingKind::AttachmentWithoutInterface)
            .expect("attachment without interface");
        assert_eq!(finding.program, "xdp_orphan");
        assert_eq!(finding.interface, "none");
        assert_eq!(finding.table, "none");
        assert_eq!(finding.program_id, Some(301));
    }

    #[test]
    fn loaded_xdp_program_without_an_attachment_is_reported_as_detached() {
        let report = evaluate(
            netns(),
            NetfilterSnapshot {
                netns_inum: netns().inum,
                ..NetfilterSnapshot::default()
            },
            BpfNetSnapshot {
                netns_inum: netns().inum,
                ..BpfNetSnapshot::default()
            },
            programs(vec![(501, "xdp_stray", "xdp")]),
        );
        let finding = report
            .findings()
            .iter()
            .find(|finding| finding.kind == FindingKind::DetachedProgram)
            .expect("detached program");
        assert_eq!(finding.program, "xdp_stray");
        assert_eq!(finding.program_id, Some(501));
        assert_eq!(finding.interface, "none");
        assert_eq!(finding.table, "none");
        assert!(finding.path.starts_with("bpf:"));
    }

    #[test]
    fn empty_bpftool_output_is_a_clean_legitimate_no_program_state() {
        let net = parse_bpftool_net_json(b"").expect("empty net list");
        assert!(net.is_empty());
        let report = evaluate(
            netns(),
            NetfilterSnapshot {
                netns_inum: netns().inum,
                ..NetfilterSnapshot::default()
            },
            net,
            BpfProgramSnapshot {
                netns_inum: netns().inum,
                ..BpfProgramSnapshot::default()
            },
        );
        assert!(report.findings().is_empty());
    }

    #[test]
    fn parser_keeps_ipv4_ipv6_and_migration_tables_separate() {
        let raw = br#"{
          "nftables": [
            {"metainfo": {"version": "1.0.9"}},
            {"table": {"family": "ip", "name": "filter"}},
            {"chain": {"family": "ip", "table": "filter", "name": "INPUT", "type": "filter", "hook": "input", "prio": 0}},
            {"rule": {"family": "ip", "table": "filter", "chain": "INPUT", "expr": [
              {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "eth0"}}
            ]}},
            {"table": {"family": "ip6", "name": "filter"}},
            {"chain": {"family": "ip6", "table": "filter", "name": "INPUT", "type": "filter", "hook": "input", "prio": 0}},
            {"table": {"family": "inet", "name": "old"}},
            {"chain": {"family": "inet", "table": "old", "name": "cloak"}},
            {"rule": {"family": "inet", "table": "old", "chain": "cloak", "expr": [{"counter": {}}]}},
            {"table": {"family": "inet", "name": "new"}},
            {"chain": {"family": "inet", "table": "new", "name": "input", "type": "filter", "hook": "input", "prio": 0}}
          ]
        }"#;
        let snapshot = parse_netfilter_json_with_netns(raw, netns().inum).expect("parse");
        assert_eq!(snapshot.chain_count(), 4);
        let expected_interfaces: BTreeSet<String> =
            ["eth0".to_string()].into_iter().collect();
        assert_eq!(
            snapshot
                .find_chain("ip", "filter", "INPUT")
                .expect("ipv4 chain")
                .interfaces,
            expected_interfaces
        );
        assert!(snapshot.find_chain("ip6", "filter", "INPUT").is_some());
        let old = snapshot
            .find_chain("inet", "old", "cloak")
            .expect("old cloaking chain");
        assert!(old.is_regular());
        assert_eq!(old.rule_count, 1);
        assert!(snapshot.find_chain("inet", "new", "input").is_some());
    }

    #[test]
    fn bpftool_parser_attributes_xdp_and_tc_programs_to_interfaces() {
        let net_raw = br#"{
          "netdev": [
            {
              "ifindex": 2,
              "ifname": "eth0",
              "xdp": [{"prog_id": 10, "name": "xdp_pass", "tag": "aa", "mode": "native"}],
              "tc": [{"prog_id": 11, "name": "tc_drop", "tag": "bb", "attach_type": "egress"}]
            }
          ]
        }"#;
        let net = parse_bpftool_net_json_with_netns(net_raw, netns().inum).expect("net json");
        assert_eq!(net.interface_count(), 1);
        assert_eq!(net.xdp_tc_count(), 2);
        assert_eq!(net.attachments[0].program_name, "xdp_pass");
        assert_eq!(net.attachments[0].ifname.as_str(), "eth0");
        assert_eq!(net.attachments[1].direction.as_str(), "egress");

        let prog_raw = br#"[
          {"id": 10, "name": "xdp_pass", "type": "xdp", "tag": "aa"},
          {"id": 11, "name": "tc_drop", "type": "sched_cls", "tag": "bb"}
        ]"#;
        let programs = parse_bpftool_prog_json_with_netns(prog_raw, netns().inum).expect("prog json");
        assert_eq!(programs.programs.len(), 2);
        assert!(programs.available);

        let report = evaluate(
            netns(),
            NetfilterSnapshot {
                netns_inum: netns().inum,
                ..NetfilterSnapshot::default()
            },
            net,
            programs,
        );
        assert!(report.findings().is_empty());
    }

    fn test_netns() -> Result<NetnsId, String> {
        Ok(netns())
    }

    fn ok_old_netfilter() -> Result<NetfilterSnapshot, PacketPathFailure> {
        Ok(netfilter(vec![
            chain("inet", "old", "cloak", None, None, &[], 2, &[]),
        ]))
    }

    fn ok_new_netfilter() -> Result<NetfilterSnapshot, PacketPathFailure> {
        Ok(netfilter(vec![
            chain("inet", "new", "input", Some("filter"), Some("input"), &["eth0"], 2, &[]),
        ]))
    }

    fn empty_bpf_net() -> Result<BpfNetSnapshot, PacketPathFailure> {
        Ok(BpfNetSnapshot {
            netns_inum: netns().inum,
            ..BpfNetSnapshot::default()
        })
    }

    fn empty_programs() -> Result<BpfProgramSnapshot, PacketPathFailure> {
        Ok(BpfProgramSnapshot {
            netns_inum: netns().inum,
            ..BpfProgramSnapshot::default()
        })
    }

    fn ok_xdp_net() -> Result<BpfNetSnapshot, PacketPathFailure> {
        Ok(bpf_net(vec![attachment(
            "eth0",
            2,
            401,
            "xdp_new",
            "xdp",
            "ingress",
        )]))
    }

    fn ok_xdp_programs() -> Result<BpfProgramSnapshot, PacketPathFailure> {
        Ok(programs(vec![(401, "xdp_new", "xdp")]))
    }

    fn failed_programs() -> Result<BpfProgramSnapshot, PacketPathFailure> {
        Err(PacketPathFailure::failed(
            "bpftool prog list is not available",
        ))
    }

    fn flaky_netfilter() -> Result<NetfilterSnapshot, PacketPathFailure> {
        if RETRY_CALLS.fetch_add(1, AtomicOrdering::SeqCst) == 0 {
            Err(PacketPathFailure::failed("first netfilter attempt failed"))
        } else {
            ok_new_netfilter()
        }
    }
}
