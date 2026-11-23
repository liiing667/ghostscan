use crate::{
    kernel_evidence::{current_or_collect, KernelEvidence},
    ScanOutcome,
};
use std::collections::BTreeSet;

pub fn run() -> ScanOutcome {
    // KERNEL_EVIDENCE is the one boot_id/kernel_release generation.
    let evidence = current_or_collect();
    run_with_evidence(&evidence)
}

/// Compare `/proc/modules` and `/sys/module` from the same boot generation.
pub fn run_with_evidence(evidence: &KernelEvidence) -> ScanOutcome {
    if let Some(unknown) = evidence.unknown_outcome("module_list_linkage_tamper") {
        return Ok(Some(unknown));
    }
    if !evidence.module_sources_current() {
        return Ok(Some(format!(
            "collector=module_list_linkage_tamper state=unknown reason=module_evidence_generation_mismatch generation={}",
            evidence.generation().label()
        )));
    }

    let mut findings = Vec::new();
    let mut errors = Vec::new();
    let sources = evidence.module_sources();
    let sys_modules: BTreeSet<String> = match read_sys_modules(evidence) {
        Ok(set) => set.clone(),
        Err(err) => return Err(format!("failed to read /sys/module: {err}")),
    };

    let proc_modules: Vec<String> = match read_proc_modules(evidence) {
        Ok(set) => set.iter().cloned().collect(),
        Err(err) => {
            errors.push(format!("/proc/modules: {err}"));
            Vec::new()
        }
    };

    for module in &proc_modules {
        if !sys_modules.contains(module) {
            findings.push(format!(
                "module_name={}, this_ptr=unknown, prev_ptr=unknown, next_ptr=unknown, anomaly=null_gap",
                module
            ));
        }
    }

    errors.extend(sources.holder_errors.iter().cloned());
    for module in &sys_modules {
        if let Some(holders) = sources.sysfs_holders.get(module) {
            if holders.contains(module) {
                findings.push(format!(
                    "module_name={}, this_ptr=unknown, prev_ptr=unknown, next_ptr=unknown, anomaly=self_loop",
                    module
                ));
            }
        }
    }

    if findings.is_empty() {
        if errors.is_empty() {
            Ok(None)
        } else {
            Err(errors.join(", "))
        }
    } else {
        findings.sort();
        if !errors.is_empty() {
            findings.push(format!("collection_errors={}", errors.join(", ")));
        }
        Ok(Some(findings.join("\n")))
    }
}

fn read_sys_modules<'a>(
    evidence: &'a KernelEvidence,
) -> Result<&'a BTreeSet<String>, &'a String> {
    evidence.module_sources().sysfs_modules.as_ref()
}

fn read_proc_modules<'a>(
    evidence: &'a KernelEvidence,
) -> Result<&'a BTreeSet<String>, &'a String> {
    evidence.module_sources().proc_modules.as_ref()
}

/// Alias used by front ends that name the shared observation explicitly.
pub fn run_with_kernel_evidence(evidence: &KernelEvidence) -> ScanOutcome {
    run_with_evidence(evidence)
}

/// Short alias for [`run_with_kernel_evidence`].
pub fn run_with_kernel(evidence: &KernelEvidence) -> ScanOutcome {
    run_with_evidence(evidence)
}
