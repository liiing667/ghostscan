use crate::{
    kernel_evidence::{current_or_collect, KernelEvidence},
    ScanOutcome,
};
pub fn run() -> ScanOutcome {
    // KERNEL_EVIDENCE is the one boot_id/kernel_release generation.
    let evidence = current_or_collect();
    run_with_evidence(&evidence)
}

/// Interpret the taint value from the same boot generation as the modules.
pub fn run_with_evidence(evidence: &KernelEvidence) -> ScanOutcome {
    if let Some(unknown) = evidence.unknown_outcome("kernel_taint") {
        return Ok(Some(unknown));
    }
    if !evidence.taint_current() {
        return Ok(Some(format!(
            "collector=kernel_taint state=unknown reason=taint_evidence_generation_mismatch generation={}",
            evidence.generation().label()
        )));
    }

    let taint_value = match &evidence.taint().value {
        Ok(value) => *value,
        Err(err) => return Err(err.clone()),
    };

    if taint_value == 0 {
        return Ok(None);
    }

    let module_taints = match collect_module_taint_letters(evidence) {
        Ok(module_taints) => module_taints,
        Err(err) => return Err(err.clone()),
    };

    let mut active_flags = Vec::new();
    let mut missing_module_flags = Vec::new();

    for flag in TAINT_FLAGS {
        if (taint_value & (1u64 << flag.bit)) != 0 {
            active_flags.push(flag);
            if flag.module_related && !module_taints.contains_key(&flag.letter) {
                missing_module_flags.push(flag);
            }
        }
    }

    if missing_module_flags.is_empty() {
        return Ok(None);
    }

    let active_letters: String = active_flags.iter().map(|flag| flag.letter).collect();
    let missing_descriptions: Vec<String> = missing_module_flags
        .iter()
        .map(|flag| format!("{} ({})", flag.letter, flag.description))
        .collect();

    let mut message = format!(
        "tainted={} active_flags={}",
        taint_value,
        if active_letters.is_empty() {
            "none"
        } else {
            active_letters.as_str()
        }
    );

    message.push_str(" missing_module_flags=");
    message.push_str(&missing_descriptions.join(", "));

    if !module_taints.is_empty() {
        let mut visible: Vec<String> = module_taints
            .iter()
            .map(|(letter, modules)| {
                let mut modules = modules.clone();
                modules.sort();
                format!("{} -> {}", letter, modules.join("|"))
            })
            .collect();
        visible.sort();
        message.push_str(" visible=");
        message.push_str(&visible.join("; "));
    }

    Ok(Some(message))
}

fn collect_module_taint_letters(
    evidence: &KernelEvidence,
) -> Result<&std::collections::BTreeMap<char, Vec<String>>, &String> {
    evidence.taint().module_letters.as_ref()
}

/// Alias used by front ends that name the shared observation explicitly.
pub fn run_with_kernel_evidence(evidence: &KernelEvidence) -> ScanOutcome {
    run_with_evidence(evidence)
}

/// Short alias for [`run_with_kernel_evidence`].
pub fn run_with_kernel(evidence: &KernelEvidence) -> ScanOutcome {
    run_with_evidence(evidence)
}

#[derive(Clone, Copy)]
struct TaintFlag {
    bit: u32,
    letter: char,
    description: &'static str,
    module_related: bool,
}

const TAINT_FLAGS: &[TaintFlag] = &[
    TaintFlag {
        bit: 0,
        letter: 'P',
        description: "proprietary module was loaded",
        module_related: true,
    },
    TaintFlag {
        bit: 1,
        letter: 'F',
        description: "module was force-loaded",
        module_related: true,
    },
    TaintFlag {
        bit: 2,
        letter: 'S',
        description: "SMP with unsupported hardware",
        module_related: false,
    },
    TaintFlag {
        bit: 3,
        letter: 'R',
        description: "module was forcibly removed",
        module_related: true,
    },
    TaintFlag {
        bit: 4,
        letter: 'M',
        description: "machine check occurred",
        module_related: false,
    },
    TaintFlag {
        bit: 5,
        letter: 'B',
        description: "kernel detected bad page",
        module_related: false,
    },
    TaintFlag {
        bit: 6,
        letter: 'U',
        description: "user forced taint",
        module_related: false,
    },
    TaintFlag {
        bit: 7,
        letter: 'D',
        description: "kernel oops or BUG",
        module_related: false,
    },
    TaintFlag {
        bit: 8,
        letter: 'A',
        description: "ACPI table override",
        module_related: false,
    },
    TaintFlag {
        bit: 9,
        letter: 'W',
        description: "kernel issued warning",
        module_related: false,
    },
    TaintFlag {
        bit: 10,
        letter: 'C',
        description: "staging driver loaded",
        module_related: true,
    },
    TaintFlag {
        bit: 11,
        letter: 'I',
        description: "firmware workaround in effect",
        module_related: false,
    },
    TaintFlag {
        bit: 12,
        letter: 'O',
        description: "out-of-tree module loaded",
        module_related: true,
    },
    TaintFlag {
        bit: 13,
        letter: 'E',
        description: "unsigned module loaded",
        module_related: true,
    },
    TaintFlag {
        bit: 14,
        letter: 'L',
        description: "soft lockup or similar condition",
        module_related: false,
    },
    TaintFlag {
        bit: 15,
        letter: 'K',
        description: "livepatch applied",
        module_related: false,
    },
    TaintFlag {
        bit: 16,
        letter: 'X',
        description: "auxiliary taint flag",
        module_related: false,
    },
    TaintFlag {
        bit: 17,
        letter: 'T',
        description: "test kernel or test taint",
        module_related: false,
    },
];
