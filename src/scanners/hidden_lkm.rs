use crate::{
    kernel_evidence::{current_or_collect, KernelEvidence},
    ScanOutcome,
};
use std::collections::{BTreeSet, HashMap, HashSet};

pub fn run() -> ScanOutcome {
    // KERNEL_EVIDENCE is the one boot_id/kernel_release generation.
    let evidence = current_or_collect();
    run_with_evidence(&evidence)
}

/// Compare module inventories from the one boot-scoped collection generation.
pub fn run_with_evidence(evidence: &KernelEvidence) -> ScanOutcome {
    if let Some(unknown) = evidence.unknown_outcome("hidden_lkm") {
        return Ok(Some(unknown));
    }
    if !evidence.module_sources_current() {
        return Ok(Some(format!(
            "collector=hidden_lkm state=unknown reason=module_evidence_generation_mismatch generation={}",
            evidence.generation().label()
        )));
    }

    let mut collections: Vec<(&str, &BTreeSet<String>)> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    for (name, result) in [
        ("proc_modules", collect_proc_modules(evidence)),
        ("sysfs", collect_sysfs_modules(evidence)),
        ("kallsyms", collect_kallsyms_modules(evidence)),
    ] {
        match result {
            Ok(set) => collections.push((name, set)),
            Err(err) => errors.push(format!("{name}: {err}")),
        }
    }

    if collections.is_empty() {
        return Err(format!(
            "failed to collect module lists: {}",
            errors.join("; ")
        ));
    }

    let mut presence: HashMap<String, HashSet<&str>> = HashMap::new();
    for (source, modules) in &collections {
        for module in modules.iter() {
            presence.entry(module.clone()).or_default().insert(*source);
        }
    }

    let sources: Vec<&str> = collections.iter().map(|(name, _)| *name).collect();
    let mut findings: Vec<String> = Vec::new();

    for (module, seen_in) in presence {
        if seen_in.len() < sources.len() {
            if seen_in.len() == 1 && seen_in.contains("sysfs") {
                continue;
            }

            let mut missing: Vec<&str> = sources
                .iter()
                .copied()
                .filter(|name| !seen_in.contains(name))
                .collect();
            missing.sort();

            findings.push(format!("{module} missing_in={}", missing.join(",")));
        }
    }

    findings.sort();

    let mut message_parts = Vec::new();
    if !findings.is_empty() {
        message_parts.push(findings.join("\n"));
    }

    if !errors.is_empty() {
        message_parts.push(format!("collection_errors={}", errors.join(", ")));
    }

    if message_parts.is_empty() {
        Ok(None)
    } else {
        Ok(Some(message_parts.join("\n")))
    }
}

fn collect_proc_modules<'a>(
    evidence: &'a KernelEvidence,
) -> Result<&'a BTreeSet<String>, &'a String> {
    evidence.module_sources().proc_modules.as_ref()
}

fn collect_sysfs_modules<'a>(
    evidence: &'a KernelEvidence,
) -> Result<&'a BTreeSet<String>, &'a String> {
    evidence.module_sources().sysfs_modules.as_ref()
}

fn collect_kallsyms_modules<'a>(
    evidence: &'a KernelEvidence,
) -> Result<&'a BTreeSet<String>, &'a String> {
    evidence.module_sources().kallsyms_modules.as_ref()
}

/// Alias used by front ends that name the shared observation explicitly.
pub fn run_with_kernel_evidence(evidence: &KernelEvidence) -> ScanOutcome {
    run_with_evidence(evidence)
}

/// Short alias for [`run_with_kernel_evidence`].
pub fn run_with_kernel(evidence: &KernelEvidence) -> ScanOutcome {
    run_with_evidence(evidence)
}
