use crate::persistence::{self, PersistenceSource};
use crate::ScanOutcome;

/// SSH foothold findings read the authorized_keys files captured once by the
/// shared persistence observation.  The scanner never stats or reads a file
/// itself, so an include/config rotation between scanners cannot splice two
/// generations into one host story.
pub fn run() -> ScanOutcome {
    let snapshot = persistence::PERSISTENCE.snapshot();
    persistence::outcome(&snapshot, PersistenceSource::Ssh)
}
