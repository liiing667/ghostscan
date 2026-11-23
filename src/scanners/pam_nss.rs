use crate::persistence;
use crate::ScanOutcome;

/// PAM modules (and PAM `@include` chains) plus NSS service paths all read the
/// same captured generation as the SSH/sudo/systemd scanners.
pub fn run() -> ScanOutcome {
    let snapshot = persistence::PERSISTENCE.snapshot();
    persistence::pam_nss_outcome(&snapshot)
}
