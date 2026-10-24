use pouw_types::{BlockId, CumWork, Height, U256};

use super::{ChainTip, better};

fn tip(height: u64, work: u64) -> ChainTip {
    ChainTip {
        id: BlockId::ZERO,
        height: Height(height),
        cumulative_work: CumWork(U256::from(work)),
    }
}

#[test]
fn more_cumulative_work_wins() {
    assert!(better(&tip(1, 5), &tip(1, 6)));
    assert!(!better(&tip(1, 6), &tip(1, 5)));
}

#[test]
fn a_tie_keeps_the_current_tip() {
    assert!(!better(&tip(1, 5), &tip(1, 5)));
    assert!(!better(&tip(1, 5), &tip(9, 5)));
}

#[test]
fn work_decides_and_height_does_not() {
    assert!(better(&tip(9, 5), &tip(2, 6)));
    assert!(!better(&tip(2, 6), &tip(9, 5)));
}
