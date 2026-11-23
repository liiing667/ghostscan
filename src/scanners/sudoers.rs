use crate::persistence::{self, PersistenceSource};
use crate::ScanOutcome;

/// Sudoers findings (including `#include`/`#includedir` chains) come from the
/// shared persistence observation captured before any scanner runs.
pub fn run() -> ScanOutcome {
    let snapshot = persistence::PERSISTENCE.snapshot();
    persistence::outcome(&snapshot, PersistenceSource::Sudo)
}
