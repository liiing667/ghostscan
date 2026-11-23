use crate::{
    kernel_evidence::{current_or_collect, KernelEvidence, SymbolResult, SymbolSource},
    ScanOutcome,
};

pub fn run() -> ScanOutcome {
    // KERNEL_EVIDENCE is the one boot_id/kernel_release generation.
    let evidence = current_or_collect();
    run_with_evidence(&evidence)
}

/// Resolve `sys_call_table` only from sources belonging to the same boot and
/// kernel release as the module evidence.
pub fn run_with_evidence(evidence: &KernelEvidence) -> ScanOutcome {
    if let Some(unknown) = evidence.unknown_outcome("syscall_table") {
        return Ok(Some(unknown));
    }

    let mut addresses: Vec<Resolution> = Vec::new();
    let mut violations: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    for symbol in evidence.symbols() {
        if !symbol.generation.same_generation(evidence.generation()) {
            violations.push(format!(
                "source={} issue=stale_generation evidence_generation={} current_generation={}",
                symbol.label(),
                symbol.generation.label(),
                evidence.generation().label()
            ));
            continue;
        }

        if matches!(&symbol.result, SymbolResult::Failed(_)) {
            if let SymbolResult::Failed(err) = &symbol.result {
                errors.push(format!("{}: {}", symbol.label(), err));
            }
            continue;
        }

        if let Some(reason) = symbol.foreign_release_reason(evidence.generation()) {
            // Keep the source visible as a finding, but never put its address
            // into the current boot's address set.
            violations.push(reason);
            continue;
        }

        match &symbol.result {
            SymbolResult::Found(address) => {
                let resolution = Resolution {
                    source: symbol.label(),
                    address: *address,
                };
                if *address == 0 {
                    if matches!(&symbol.source, SymbolSource::Kallsyms) {
                        errors.push(format!(
                            "{} returned zero address (likely kptr_restrict)",
                            resolution.source
                        ));
                    } else {
                        errors.push(format!("{} returned zero address", resolution.source));
                    }
                } else {
                    addresses.push(resolution);
                }
            }
            SymbolResult::Missing => {
                violations.push(format!(
                    "source={} issue=missing_sys_call_table",
                    symbol.label()
                ));
            }
            SymbolResult::Failed(_) => {}
        }
    }

    if !addresses.is_empty() {
        if let Some((mismatch_sources, values)) = detect_address_mismatch(&addresses) {
            violations.push(format!(
                "inconsistent_addresses sources={} addresses={}",
                mismatch_sources.join("|"),
                values
                    .iter()
                    .map(|addr| format!("0x{addr:016x}"))
                    .collect::<Vec<_>>()
                    .join("|")
            ));
        }
    }

    if violations.is_empty() {
        if errors.is_empty() {
            Ok(None)
        } else {
            Err(errors.join(", "))
        }
    } else {
        let mut message_parts = Vec::new();
        message_parts.push(violations.join("\n"));
        if !errors.is_empty() {
            message_parts.push(format!("collection_errors={}", errors.join(", ")));
        }
        Ok(Some(message_parts.join("\n")))
    }
}

#[derive(Clone)]
struct Resolution {
    source: String,
    address: u64,
}

fn detect_address_mismatch(resolutions: &[Resolution]) -> Option<(Vec<String>, Vec<u64>)> {
    let mut unique_addresses: Vec<(String, u64)> = Vec::new();

    for resolution in resolutions {
        if unique_addresses
            .iter()
            .any(|(_, addr)| *addr == resolution.address)
        {
            continue;
        }
        unique_addresses.push((resolution.source.clone(), resolution.address));
    }

    if unique_addresses.len() > 1 {
        let (sources, values): (Vec<_>, Vec<_>) = unique_addresses.into_iter().unzip();
        Some((sources, values))
    } else {
        None
    }
}

/// `/proc/kallsyms` evidence from the shared generation.
pub fn resolve_from_kallsyms(evidence: &KernelEvidence) -> Option<&SymbolEvidence> {
    evidence
        .symbols()
        .iter()
        .find(|symbol| matches!(&symbol.source, SymbolSource::Kallsyms))
}

/// Every `System.map` source considered in the shared generation.
pub fn resolve_from_system_map(evidence: &KernelEvidence) -> Vec<&SymbolEvidence> {
    evidence
        .symbols()
        .iter()
        .filter(|symbol| matches!(&symbol.source, SymbolSource::SystemMap { .. }))
        .collect()
}

/// Alias used by front ends that name the shared observation explicitly.
pub fn run_with_kernel_evidence(evidence: &KernelEvidence) -> ScanOutcome {
    run_with_evidence(evidence)
}

/// Short alias for [`run_with_kernel_evidence`].
pub fn run_with_kernel(evidence: &KernelEvidence) -> ScanOutcome {
    run_with_evidence(evidence)
}
