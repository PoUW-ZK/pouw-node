//! Chain state (accounts, circuit registry, usage counters) and the diff that one
//! block makes to it. A diff records the value before and after every key it touches,
//! so the same record applies a block and, inverted, reverts it.

use std::collections::BTreeMap;
use std::hash::Hash;

use borsh::{BorshDeserialize, BorshSerialize};
use pouw_crypto::Address;
use pouw_types::{Account, CircuitEntry, CircuitId, FastMap, UsageCounter};
use thiserror::Error;

/// A read of the state failed for a reason outside the rules, such as a disk error.
/// It never makes a block or transaction invalid.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StateError {
    /// The stored state contradicts itself.
    #[error("corrupt state: {0}")]
    Corrupt(String),
    /// The backend failed, such as an I/O error.
    #[error("state backend failure: {0}")]
    Backend(String),
}

/// Read access to the state at one block.
pub trait StateView {
    /// `None` for an address the chain has not seen.
    fn account(&self, address: &Address) -> Result<Option<Account>, StateError>;

    /// `None` for an unregistered circuit. The entry holds the circuit and verifying
    /// key, up to megabytes, so it is lent and never copied.
    fn circuit(&self, id: &CircuitId) -> Result<Option<&CircuitEntry>, StateError>;

    /// The counter of the last proof of `miner` for `circuit`, `None` before the first.
    fn usage_counter(
        &self,
        miner: &Address,
        circuit: &CircuitId,
    ) -> Result<Option<UsageCounter>, StateError>;
}

/// Value of one key before and after a diff. `None` is an absent key.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Change<T> {
    /// Value in the state the diff applies to.
    pub before: Option<T>,
    /// Value the diff leaves.
    pub after: Option<T>,
}

impl<T: Clone> Change<T> {
    fn inverse(&self) -> Self {
        Self {
            before: self.after.clone(),
            after: self.before.clone(),
        }
    }
}

/// Every state change of one block. The store writes it with the block and keeps it
/// to revert the block on a reorganization.
#[derive(Debug, Clone, PartialEq, Eq, Default, BorshSerialize, BorshDeserialize)]
pub struct StateDiff {
    /// Balances and nonces.
    pub accounts: BTreeMap<Address, Change<Account>>,
    /// Registry entries.
    pub circuits: BTreeMap<CircuitId, Change<CircuitEntry>>,
    /// Usage counters per (miner, circuit).
    pub usage_counters: BTreeMap<(Address, CircuitId), Change<UsageCounter>>,
}

impl StateDiff {
    /// The diff that undoes this one.
    #[must_use]
    pub fn inverse(&self) -> Self {
        fn invert<K: Clone + Ord, T: Clone>(
            map: &BTreeMap<K, Change<T>>,
        ) -> BTreeMap<K, Change<T>> {
            map.iter().map(|(k, c)| (k.clone(), c.inverse())).collect()
        }
        Self {
            accounts: invert(&self.accounts),
            circuits: invert(&self.circuits),
            usage_counters: invert(&self.usage_counters),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty() && self.circuits.is_empty() && self.usage_counters.is_empty()
    }
}

/// A diff whose `before` values differ from the state it is applied to.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("the diff does not apply: {key} differs from its recorded before value")]
pub struct DiffMismatch {
    /// The first key that differs.
    pub key: String,
}

/// The state as plain maps, for tests and for the in-memory store.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MemState {
    pub accounts: FastMap<Address, Account>,
    pub circuits: FastMap<CircuitId, CircuitEntry>,
    pub usage_counters: FastMap<(Address, CircuitId), UsageCounter>,
}

/// Applies `diff` after checking every `before` against the current value. On a
/// mismatch nothing is written.
pub fn apply(state: &mut MemState, diff: &StateDiff) -> Result<(), DiffMismatch> {
    fn check<K: Ord + Hash + std::fmt::Debug, T: PartialEq>(
        map: &FastMap<K, T>,
        changes: &BTreeMap<K, Change<T>>,
    ) -> Result<(), DiffMismatch> {
        match changes
            .iter()
            .find(|(key, change)| map.get(*key) != change.before.as_ref())
        {
            Some((key, _)) => Err(DiffMismatch {
                key: format!("{key:?}"),
            }),
            None => Ok(()),
        }
    }
    fn write<K: Ord + Hash + Clone, T: Clone>(
        map: &mut FastMap<K, T>,
        changes: &BTreeMap<K, Change<T>>,
    ) {
        for (key, change) in changes {
            match &change.after {
                Some(value) => map.insert(key.clone(), value.clone()),
                None => map.remove(key),
            };
        }
    }
    check(&state.accounts, &diff.accounts)?;
    check(&state.circuits, &diff.circuits)?;
    check(&state.usage_counters, &diff.usage_counters)?;
    write(&mut state.accounts, &diff.accounts);
    write(&mut state.circuits, &diff.circuits);
    write(&mut state.usage_counters, &diff.usage_counters);
    Ok(())
}

impl StateView for MemState {
    fn account(&self, address: &Address) -> Result<Option<Account>, StateError> {
        Ok(self.accounts.get(address).cloned())
    }

    fn circuit(&self, id: &CircuitId) -> Result<Option<&CircuitEntry>, StateError> {
        Ok(self.circuits.get(id))
    }

    fn usage_counter(
        &self,
        miner: &Address,
        circuit: &CircuitId,
    ) -> Result<Option<UsageCounter>, StateError> {
        Ok(self.usage_counters.get(&(*miner, *circuit)).copied())
    }
}

/// Pending changes over a read-only base state. The state transition of a block or a
/// transaction runs against it, then its `diff` goes to the
/// store, or the overlay is dropped when the block is invalid.
#[derive(Debug)]
pub struct ChainState<'a, V: ?Sized> {
    pub base: &'a V,
    pub diff: StateDiff,
}

fn current<T: Clone>(
    pending: Option<&Change<T>>,
    base: impl FnOnce() -> Result<Option<T>, StateError>,
) -> Result<Option<T>, StateError> {
    match pending {
        Some(change) => Ok(change.after.clone()),
        None => base(),
    }
}

fn record<K: Ord, T>(
    changes: &mut BTreeMap<K, Change<T>>,
    key: K,
    value: T,
    base: impl FnOnce() -> Result<Option<T>, StateError>,
) -> Result<(), StateError> {
    if let Some(change) = changes.get_mut(&key) {
        change.after = Some(value);
    } else {
        let before = base()?;
        changes.insert(
            key,
            Change {
                before,
                after: Some(value),
            },
        );
    }
    Ok(())
}

pub fn set_account<V: StateView + ?Sized>(
    overlay: &mut ChainState<'_, V>,
    address: Address,
    account: Account,
) -> Result<(), StateError> {
    let base = overlay.base;
    record(&mut overlay.diff.accounts, address, account, || {
        base.account(&address)
    })
}

/// Adds or replaces a registry entry.
pub fn set_circuit<V: StateView + ?Sized>(
    overlay: &mut ChainState<'_, V>,
    entry: CircuitEntry,
) -> Result<(), StateError> {
    let base = overlay.base;
    let id = entry.id;
    record(&mut overlay.diff.circuits, id, entry, || {
        base.circuit(&id).map(Option::<&CircuitEntry>::cloned)
    })
}

/// Sets the usage counter of (`miner`, `circuit`).
pub fn set_usage_counter<V: StateView + ?Sized>(
    overlay: &mut ChainState<'_, V>,
    miner: Address,
    circuit: CircuitId,
    counter: UsageCounter,
) -> Result<(), StateError> {
    let base = overlay.base;
    record(
        &mut overlay.diff.usage_counters,
        (miner, circuit),
        counter,
        || base.usage_counter(&miner, &circuit),
    )
}

impl<V: StateView + ?Sized> StateView for ChainState<'_, V> {
    fn account(&self, address: &Address) -> Result<Option<Account>, StateError> {
        current(self.diff.accounts.get(address), || {
            self.base.account(address)
        })
    }

    fn circuit(&self, id: &CircuitId) -> Result<Option<&CircuitEntry>, StateError> {
        match self.diff.circuits.get(id) {
            Some(change) => Ok(change.after.as_ref()),
            None => self.base.circuit(id),
        }
    }

    fn usage_counter(
        &self,
        miner: &Address,
        circuit: &CircuitId,
    ) -> Result<Option<UsageCounter>, StateError> {
        current(self.diff.usage_counters.get(&(*miner, *circuit)), || {
            self.base.usage_counter(miner, circuit)
        })
    }
}

#[cfg(test)]
#[expect(
    clippy::arithmetic_side_effects,
    reason = "test fixtures build small values"
)]
mod tests {
    use pouw_crypto::Hash32;
    use pouw_types::{Amount, ConstraintCount, Height, Nonce, ProofSystem, TxId};

    use super::*;

    fn account(balance: u64, nonce: u64) -> Account {
        Account {
            balance: Amount(balance),
            nonce: Nonce(nonce),
        }
    }

    fn entry(n: u8) -> CircuitEntry {
        CircuitEntry {
            id: CircuitId(TxId(Hash32([n; 32]))),
            system: ProofSystem::Groth16,
            constraint_count: ConstraintCount(10),
            owner: Address([n; 32]),
            registered_at: Height(1),
            verifying_key: Box::from([n]),
            circuit: Box::from([n]),
        }
    }

    fn block_diff(state: &MemState, n: u8) -> StateDiff {
        let mut overlay = ChainState {
            base: state,
            diff: StateDiff::default(),
        };
        let alice = Address([1; 32]);
        let previous = overlay.account(&alice).unwrap().unwrap_or_default();
        set_account(
            &mut overlay,
            alice,
            account(previous.balance.0 + 10, previous.nonce.0 + 1),
        )
        .unwrap();
        set_account(&mut overlay, Address([n; 32]), account(5, 0)).unwrap();
        set_circuit(&mut overlay, entry(n)).unwrap();
        set_usage_counter(&mut overlay, alice, entry(n).id, UsageCounter(u64::from(n))).unwrap();
        overlay.diff
    }

    #[test]
    fn three_blocks_applied_and_reverted_restore_the_state() {
        let mut state = MemState::default();
        apply(
            &mut state,
            &StateDiff {
                accounts: BTreeMap::from([(
                    Address([1; 32]),
                    Change {
                        before: None,
                        after: Some(account(100, 0)),
                    },
                )]),
                ..StateDiff::default()
            },
        )
        .unwrap();
        let original = state.clone();

        let mut diffs = Vec::new();
        for n in 2..5 {
            let diff = block_diff(&state, n);
            apply(&mut state, &diff).unwrap();
            diffs.push(diff);
        }
        assert_eq!(
            state.account(&Address([1; 32])).unwrap(),
            Some(account(130, 3))
        );
        for diff in diffs.iter().rev() {
            apply(&mut state, &diff.inverse()).unwrap();
        }
        assert_eq!(state, original);
    }

    #[test]
    fn a_diff_does_not_apply_twice() {
        let mut state = MemState::default();
        let diff = block_diff(&state, 2);
        apply(&mut state, &diff).unwrap();
        let after = state.clone();
        assert!(apply(&mut state, &diff).is_err());
        assert_eq!(state, after);
    }

    #[test]
    fn the_overlay_reads_its_own_writes_and_keeps_the_first_before() {
        let state = MemState::default();
        let mut overlay = ChainState {
            base: &state,
            diff: StateDiff::default(),
        };
        let bob = Address([9; 32]);
        set_account(&mut overlay, bob, account(1, 0)).unwrap();
        set_account(&mut overlay, bob, account(2, 1)).unwrap();
        assert_eq!(overlay.account(&bob).unwrap(), Some(account(2, 1)));
        assert_eq!(state.account(&bob).unwrap(), None);
        let change = &overlay.diff.accounts[&bob];
        assert_eq!(change.before, None);
        assert_eq!(change.after, Some(account(2, 1)));
    }

    #[test]
    fn a_circuit_is_read_as_a_borrow_of_the_stored_entry() {
        let mut state = MemState::default();
        let diff = block_diff(&state, 2);
        apply(&mut state, &diff).unwrap();
        let id = entry(2).id;
        let from_state: &CircuitEntry = state.circuit(&id).unwrap().unwrap();
        assert_eq!(from_state, &entry(2));
        assert!(std::ptr::eq(
            from_state,
            std::ptr::from_ref(&state.circuits[&id])
        ));

        let mut overlay = ChainState {
            base: &state,
            diff: StateDiff::default(),
        };
        let from_base: &CircuitEntry = overlay.circuit(&id).unwrap().unwrap();
        assert!(std::ptr::eq(
            from_base,
            std::ptr::from_ref(&state.circuits[&id])
        ));
        set_circuit(&mut overlay, entry(3)).unwrap();
        let written: &CircuitEntry = overlay.circuit(&entry(3).id).unwrap().unwrap();
        assert!(std::ptr::eq(
            written,
            std::ptr::from_ref(overlay.diff.circuits[&entry(3).id].after.as_ref().unwrap())
        ));
    }

    #[test]
    fn a_diff_round_trips_through_borsh() {
        let diff = block_diff(&MemState::default(), 3);
        let bytes = borsh::to_vec(&diff).unwrap();
        assert_eq!(borsh::from_slice::<StateDiff>(&bytes).unwrap(), diff);
    }
}
