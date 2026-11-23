use crate::bpf_lifecycle::{
    conflict_error, dump_program_xlated, scanner_error, verify_program_tag, BpfSnapshot,
    BpfTransaction, CollectorKind, ProgramRecord, BPF_TRANSACTION,
};
use crate::ScanOutcome;
use std::collections::BTreeSet;

pub fn run() -> ScanOutcome {
    run_with_bpf(&BPF_TRANSACTION)
}

/// Sensitive-kfunc scan sharing the caller's lifecycle transaction.
///
/// Program ids come from the transaction snapshot and every dump is checked
/// against the snapshot tag before its symbols are published.  If the id was
/// detached and reused while the dump was running, the evidence is discarded
/// instead of being attached to the earlier program.
pub fn run_with_bpf(transaction: &BpfTransaction) -> ScanOutcome {
    let snapshot = transaction.snapshot();
    run_with_snapshot(&snapshot)
}

pub fn run_with_snapshot(snapshot: &BpfSnapshot) -> ScanOutcome {
    if let Some(error) = scanner_error(
        snapshot,
        CollectorKind::Programs,
        "bpftool not available to inspect kfunc usage",
    ) {
        return Err(error);
    }

    if let Some(error) = conflict_error(snapshot) {
        return Err(error);
    }

    let mut findings = Vec::new();
    let mut errors = Vec::new();

    for program in &snapshot.programs {
        match inspect_program(program) {
            Ok(kfuncs) if !kfuncs.is_empty() => {
                let joined = kfuncs.into_iter().collect::<Vec<_>>().join("|");
                findings.push(format!(
                    "prog_id={}, name={}, kfuncs={}, tag={}, generation={}, boot_id={}",
                    program.id,
                    program.name,
                    joined,
                    program.tag,
                    program.stamp.label(),
                    program.stamp.boot_id
                ));
            }
            Ok(_) => {}
            Err(err) => errors.push(format!("prog_id={}: {}", program.id, err)),
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

fn inspect_program(program: &ProgramRecord) -> Result<BTreeSet<String>, String> {
    let text = dump_program_xlated(program.id)?;
    let mut matches = BTreeSet::new();

    for line in text.lines() {
        if let Some(symbol) = extract_called_symbol(line) {
            if is_sensitive_symbol(&symbol) {
                matches.insert(symbol);
            }
        }
    }

    // `prog dump xlated id N` only carries the numeric id.  Re-read that id
    // after the dump and compare the tag with the transaction record; a
    // different tag means the old program was detached and the id was reused.
    if !matches.is_empty() {
        verify_program_tag(program.id, &program.tag)?;
    }

    Ok(matches)
}

fn extract_called_symbol(line: &str) -> Option<String> {
    let mut tokens = line.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "call" {
            if let Some(target) = tokens.next() {
                let cleaned = target.trim_matches(',');
                if cleaned.chars().all(|c| c.is_numeric()) {
                    return None;
                }
                if cleaned.is_empty() {
                    return None;
                }
                return Some(cleaned.trim().to_string());
            }
        }
    }
    None
}

fn is_sensitive_symbol(symbol: &str) -> bool {
    let lower = symbol.to_ascii_lowercase();
    lower.contains("task")
        || lower.contains("cred")
        || lower.starts_with("security_")
        || (lower.starts_with("bpf_") && lower.contains("_override"))
}
