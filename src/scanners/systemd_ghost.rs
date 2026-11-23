use crate::persistence::{self, PersistenceSource};
use crate::ScanOutcome;

/// systemd unit findings (including drop-in semantics and masked units) come
/// from the shared persistence observation.
pub fn run() -> ScanOutcome {
    let snapshot = persistence::PERSISTENCE.snapshot();
    persistence::outcome(&snapshot, PersistenceSource::Systemd)
}
