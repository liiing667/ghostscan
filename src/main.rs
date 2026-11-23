pub type ScanOutcome = Result<Option<String>, String>;

mod scanners;
mod scan_summary;

use scanners::{
    audit_disabled, bpf_kprobe_attachments, bpf_lsm, core_pattern_pipeline, cron_ghost,
    deleted_memfd, fanotify_watchers, ftrace_redirection, hidden_bind_mounts, hidden_listeners,
    hidden_lkm, hidden_pids, host_net_ns, host_pid_ns, journal_gaps, kernel_cmdline,
    kernel_message_suppression, kernel_taint, kernel_text_ro, kernel_thread_masquerade, large_rx,
    ld_audit, ld_so_preload, library_search_hijack, live_ld_preload, local_port_backdoors,
    modprobe_hotplug, module_list_linkage_tamper, netfilter_cloaking, netfilter_hook_drift,
    netlink_vs_proc, overlay_lowerdir, overlayfs_whiteouts, ownerless_bpf_objects,
    ownerless_sockets, pam_nss, pins_non_bpffs, scripts_d, seccomp_user_notify,
    sensitive_host_mounts, sensitive_kfunc, sockmap_sockhash, ssh_footholds, sudoers,
    suspicious_ptrace, syscall_table, systemd_ghost, task_list_mismatch, unknown_kprobes,
    xdp_tc_detached,
};
use scan_summary::ScanSummary;
use std::io::Write;
use std::process::ExitCode;

const COLOR_GREEN: &str = "\x1b[32m";
const COLOR_RED: &str = "\x1b[31m";
const COLOR_RESET: &str = "\x1b[0m";

struct Scanner {
    name: &'static str,
    func: fn() -> ScanOutcome,
}

impl Scanner {
    fn run(&self) -> ScanOutcome {
        (self.func)()
    }
}

const SCANNERS: &[Scanner] = &[
    Scanner {
        name: "Hidden LKM (proc/sysfs vs kallsyms clusters)",
        func: hidden_lkm::run,
    },
    Scanner {
        name: "Kernel taint with no visible cause",
        func: kernel_taint::run,
    },
    Scanner {
        name: "Ftrace redirection on critical paths",
        func: ftrace_redirection::run,
    },
    Scanner {
        name: "Unknown kprobes on sensitive symbols",
        func: unknown_kprobes::run,
    },
    Scanner {
        name: "Syscall table pointer integrity",
        func: syscall_table::run,
    },
    Scanner {
        name: "modprobe helper tamper",
        func: modprobe_hotplug::run,
    },
    Scanner {
        name: "Netfilter hook drift (orphans/invalid jumps)",
        func: netfilter_hook_drift::run,
    },
    Scanner {
        name: "Module list linkage tamper",
        func: module_list_linkage_tamper::run,
    },
    Scanner {
        name: "Ownerless BPF objects",
        func: ownerless_bpf_objects::run,
    },
    Scanner {
        name: "BPF kprobe attachments to sensitive symbols",
        func: bpf_kprobe_attachments::run,
    },
    Scanner {
        name: "BPF LSM present",
        func: bpf_lsm::run,
    },
    Scanner {
        name: "XDP/TC detached programs",
        func: xdp_tc_detached::run,
    },
    Scanner {
        name: "Sockmap/Sockhash verdict without owners",
        func: sockmap_sockhash::run,
    },
    Scanner {
        name: "Sensitive kfunc usage",
        func: sensitive_kfunc::run,
    },
    Scanner {
        name: "Pins on non-bpffs mounts",
        func: pins_non_bpffs::run,
    },
    Scanner {
        name: "Netlink vs /proc/net sockets",
        func: netlink_vs_proc::run,
    },
    Scanner {
        name: "Task list mismatch (BPF vs /proc)",
        func: task_list_mismatch::run,
    },
    Scanner {
        name: "Hidden PIDs (bpf-only)",
        func: hidden_pids::run,
    },
    Scanner {
        name: "Kernel thread masquerade",
        func: kernel_thread_masquerade::run,
    },
    Scanner {
        name: "Suspicious ptrace edges",
        func: suspicious_ptrace::run,
    },
    Scanner {
        name: "Seccomp user-notify responders",
        func: seccomp_user_notify::run,
    },
    Scanner {
        name: "Deleted-binary or memfd processes",
        func: deleted_memfd::run,
    },
    Scanner {
        name: "Core dump pipeline tamper",
        func: core_pattern_pipeline::run,
    },
    Scanner {
        name: "Hidden listeners (netlink-only)",
        func: hidden_listeners::run,
    },
    Scanner {
        name: "Ownerless sockets",
        func: ownerless_sockets::run,
    },
    Scanner {
        name: "Netfilter cloaking artifacts",
        func: netfilter_cloaking::run,
    },
    Scanner {
        name: "Local port backdoors (tmp/deleted)",
        func: local_port_backdoors::run,
    },
    Scanner {
        name: "ld.so.preload tamper",
        func: ld_so_preload::run,
    },
    Scanner {
        name: "Cron/anacron/at ghost jobs",
        func: cron_ghost::run,
    },
    Scanner {
        name: "systemd ghost units (exec in tmp/deleted)",
        func: systemd_ghost::run,
    },
    Scanner {
        name: "SSH footholds (forced/wildcard/insecure)",
        func: ssh_footholds::run,
    },
    Scanner {
        name: "OverlayFS whiteouts / opaque",
        func: overlayfs_whiteouts::run,
    },
    Scanner {
        name: "Hidden bind/immutable mounts",
        func: hidden_bind_mounts::run,
    },
    Scanner {
        name: "Fanotify watchers on sensitive mounts",
        func: fanotify_watchers::run,
    },
    Scanner {
        name: "PAM/NSS modules from non-system paths",
        func: pam_nss::run,
    },
    Scanner {
        name: "Live LD_PRELOAD to deleted/writable libs",
        func: live_ld_preload::run,
    },
    Scanner {
        name: "Library search hijack (SUID/priv)",
        func: library_search_hijack::run,
    },
    Scanner {
        name: "LD_AUDIT in daemons (no TTY)",
        func: ld_audit::run,
    },
    Scanner {
        name: "Large RX-anonymous regions in daemons (non-JIT)",
        func: large_rx::run,
    },
    Scanner {
        name: "Kernel text not RO (best-effort)",
        func: kernel_text_ro::run,
    },
    Scanner {
        name: "scripts.d executable from tmp/non-root",
        func: scripts_d::run,
    },
    Scanner {
        name: "sudoers dangerous entries",
        func: sudoers::run,
    },
    Scanner {
        name: "Kernel cmdline disables auditing/lockdown/IMA",
        func: kernel_cmdline::run,
    },
    Scanner {
        name: "Sensitive host mounts into containers",
        func: sensitive_host_mounts::run,
    },
    Scanner {
        name: "Host PID namespace shared",
        func: host_pid_ns::run,
    },
    Scanner {
        name: "Host net namespace shared",
        func: host_net_ns::run,
    },
    Scanner {
        name: "Overlay lowerdir outside storage root",
        func: overlay_lowerdir::run,
    },
    Scanner {
        name: "Audit disabled or dropping",
        func: audit_disabled::run,
    },
    Scanner {
        name: "Journal gaps (current boot)",
        func: journal_gaps::run,
    },
    Scanner {
        name: "Kernel message suppression",
        func: kernel_message_suppression::run,
    },
];

fn main() -> ExitCode {
    // One transaction for the whole round. The outcome set, collector
    // coverage, finding list, failure list, verdict and exit code all live in
    // this single summary, so they can never diverge from each other.
    let mut summary = ScanSummary::new();

    for scanner in SCANNERS {
        println!("[{}]", scanner.name);

        // A collector that aborts (panic) is still recorded as a failed
        // collector rather than taking the whole process down and skipping the
        // summary, which would otherwise hide coverage behind a non-clean
        // crash without any failure list.
        let outcome = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            scanner.run()
        })) {
            Ok(outcome) => outcome,
            Err(panic) => {
                let reason = panic_message(&panic);
                eprintln!("collector '{}' aborted: {reason}", scanner.name);
                summary.record_aborted(scanner.name, format!("collector aborted: {reason}"));
                continue;
            }
        };

        // The per-scanner text is kept exactly as before: findings and errors
        // in red, clean collectors as green OK.
        match &outcome {
            Ok(Some(finding)) => {
                for line in finding.lines() {
                    if line.is_empty() {
                        println!();
                    } else {
                        println!("{}{}{}", COLOR_RED, line, COLOR_RESET);
                    }
                }
            }
            Ok(None) => println!("{}OK{}", COLOR_GREEN, COLOR_RESET),
            Err(err) => {
                for line in err.lines() {
                    if line.is_empty() {
                        println!();
                    } else {
                        println!("{}{}{}", COLOR_RED, line, COLOR_RESET);
                    }
                }
            }
        }

        summary.record(scanner.name, &outcome);
    }

    // Build the full report before writing it: a report write failure can
    // therefore never leave a partial or clean-looking round, and the exit
    // code below always comes from the same summary as the report.
    let report = summary.render();
    if let Err(err) = write_all(&report) {
        eprintln!("failed to write scan summary: {err}");
    }

    ExitCode::from(summary.exit_code())
}

fn write_all(report: &str) -> std::io::Result<()> {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    handle.write_all(report.as_bytes())?;
    handle.flush()
}

fn panic_message(panic: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = panic.downcast_ref::<&'static str>() {
        return (*message).to_string();
    }
    if let Some(message) = panic.downcast_ref::<String>() {
        return message.clone();
    }
    "unknown panic".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_registry_is_fully_covered_by_the_summary_round() {
        // The summary must receive exactly one record per registered
        // collector, so coverage counting always accounts for the full set.
        let mut summary = ScanSummary::new();
        for scanner in SCANNERS {
            summary.record(scanner.name, &Ok(None));
        }
        assert_eq!(summary.total(), SCANNERS.len());
        assert_eq!(summary.covered(), SCANNERS.len());
        assert_eq!(summary.failure_count(), 0);
        assert_eq!(summary.verdict(), scan_summary::Verdict::Clean);
        assert_eq!(summary.exit_code(), 0);
    }
}
