pub type ScanOutcome = Result<Option<String>, String>;

pub mod packet_path;
mod scanners;

use packet_path::PacketPathTransaction;
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

const COLOR_GREEN: &str = "\x1b[32m";
const COLOR_RED: &str = "\x1b[31m";
const COLOR_RESET: &str = "\x1b[0m";

struct Scanner {
    name: &'static str,
    func: fn() -> ScanOutcome,
}

impl Scanner {
    fn run(&self, path: &PacketPathTransaction) -> ScanOutcome {
        for &(name, func) in PACKET_PATH_SCANNERS {
            if name == self.name {
                return func(path);
            }
        }
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

/// Scanners that consume the shared packet-path transaction instead of
/// collecting their own netfilter or XDP/TC snapshot.
///
/// The names are the public scanner-registry contract; keeping the mapping
/// here preserves the existing scanner list, ordering and output headings.
const PACKET_PATH_SCANNERS: &[(&str, fn(&PacketPathTransaction) -> ScanOutcome)] = &[
    (
        "Netfilter hook drift (orphans/invalid jumps)",
        netfilter_hook_drift::run_with_path,
    ),
    (
        "Netfilter cloaking artifacts",
        netfilter_cloaking::run_with_path,
    ),
    (
        "XDP/TC detached programs",
        xdp_tc_detached::run_with_path,
    ),
];

fn main() {
    // The generation, netns and all three packet-path planes are fixed before
    // the first scanner runs.  Every packet-path scanner and the final report
    // share this transaction; no scanner performs its own collection.
    let path = PacketPathTransaction::start();

    for scanner in SCANNERS {
        println!("[{}]", scanner.name);
        match scanner.run(&path) {
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
    }

    print_packet_path(&path);
}

/// Print the shared packet-path transaction and risk report.
///
/// This is the only place the whole packet path gets a verdict: it requires
/// the netfilter, interface and eBPF program planes to carry stamps from the
/// same generation and network namespace.
fn print_packet_path(path: &PacketPathTransaction) {
    println!("[Packet path transaction]");
    for line in path.report().render_lines() {
        if line.contains("finding=") && !line.contains("finding=packet_path_observed") {
            println!("{}{}{}", COLOR_RED, line, COLOR_RESET);
        } else if line.starts_with("packet_path=CONSISTENT")
            || line.starts_with("same_generation=true")
        {
            println!("{}{}{}", COLOR_GREEN, line, COLOR_RESET);
        } else {
            println!("{line}");
        }
    }
}

/// Alias kept for symmetry with the other report helpers.
#[allow(dead_code)]
fn print_packet_path_report(path: &PacketPathTransaction) {
    print_packet_path(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_path_scanner_mapping_only_references_registered_scanners() {
        assert_eq!(PACKET_PATH_SCANNERS.len(), 3);
        for &(name, _) in PACKET_PATH_SCANNERS {
            assert!(
                SCANNERS.iter().any(|scanner| scanner.name == name),
                "packet-path scanner {name:?} is not in SCANNERS"
            );
        }
    }

    #[test]
    fn scanner_registry_order_and_size_are_unchanged() {
        assert_eq!(SCANNERS.len(), 50);
        assert_eq!(
            SCANNERS.first().map(|scanner| scanner.name),
            Some("Hidden LKM (proc/sysfs vs kallsyms clusters)")
        );
        assert_eq!(
            SCANNERS.last().map(|scanner| scanner.name),
            Some("Kernel message suppression")
        );
    }

    #[test]
    fn packet_path_scanners_are_the_three_shared_transaction_consumers() {
        let names: Vec<&str> = PACKET_PATH_SCANNERS
            .iter()
            .map(|&(name, _)| name)
            .collect();
        assert!(names.contains(&"Netfilter hook drift (orphans/invalid jumps)"));
        assert!(names.contains(&"Netfilter cloaking artifacts"));
        assert!(names.contains(&"XDP/TC detached programs"));
    }
}
