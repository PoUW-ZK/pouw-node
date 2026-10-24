use pouw_crypto::{Hash32, sha256};
use thiserror::Error;

use crate::protocol::{DOMAIN_COUNT, DOMAIN_LEAF, DOMAIN_NODE};

/// Why an inclusion proof cannot be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MerkleError {
    /// The index is not a leaf of the tree.
    #[error("leaf index {index} is out of range for {leaf_count} leaves")]
    IndexOutOfRange {
        /// Requested leaf.
        index: usize,
        /// Leaves in the tree.
        leaf_count: usize,
    },
}

fn leaf_hash(id: &Hash32) -> Hash32 {
    sha256(&[&[DOMAIN_LEAF], id.as_ref()])
}

fn node_hash(left: &Hash32, right: &Hash32) -> Hash32 {
    sha256(&[&[DOMAIN_NODE], left.as_ref(), right.as_ref()])
}

fn empty_root() -> Hash32 {
    sha256(&[&[DOMAIN_LEAF]])
}

fn next_level(level: &[Hash32]) -> Vec<Hash32> {
    level
        .chunks(2)
        .filter_map(|pair| match pair {
            [left, right] => Some(node_hash(left, right)),
            [lone] => Some(*lone),
            _ => None,
        })
        .collect()
}

fn is_promoted(idx: usize, level_len: usize) -> bool {
    level_len % 2 == 1 && idx.checked_add(1) == Some(level_len)
}

fn levels(ids: &[Hash32]) -> Vec<Vec<Hash32>> {
    let mut levels = vec![ids.iter().map(leaf_hash).collect::<Vec<_>>()];
    while let Some(level) = levels.last().filter(|level| level.len() > 1) {
        let next = next_level(level);
        levels.push(next);
    }
    levels
}

/// Root of the tree over `ids`. A leaf is `sha256(0x00 || id)`, a node is
/// `sha256(0x01 || left || right)`, and a lone last node of an odd level is promoted
/// unchanged. The empty tree has the root `sha256(0x00)`.
pub fn merkle_root(ids: &[Hash32]) -> Hash32 {
    root_in_place(&mut ids.to_vec())
}

/// [`merkle_root`] over leaf ids the caller already owns, folded in the same buffer.
/// The buffer is left holding the last level, its capacity ready for the next call.
pub(crate) fn root_in_place(level: &mut Vec<Hash32>) -> Hash32 {
    for id in level.iter_mut() {
        *id = leaf_hash(id);
    }
    while level.len() > 1 {
        for read in (0..level.len()).step_by(2) {
            level[read / 2] = match level[read..] {
                [ref left, ref right, ..] => node_hash(left, right),
                _ => level[read],
            };
        }
        level.truncate(level.len().div_ceil(2));
    }
    level.first().copied().unwrap_or_else(empty_root)
}

/// Leaf count as the `u32` the bound root hashes. Counts above `u32::MAX` saturate:
/// they are far above [`crate::protocol::MAX_TXS_PER_BLOCK`], so such a block fails
/// the size rule before its root is compared.
pub fn leaf_count_u32(leaf_count: usize) -> u32 {
    u32::try_from(leaf_count).unwrap_or(u32::MAX)
}

/// The header `tx_root`: `sha256(0x02 || u32le(leaf_count) || merkle_root)`. Binding the
/// count lets an inclusion proof carry it and still verify against the header alone.
pub fn bound_root(leaf_count: u32, merkle_root: &Hash32) -> Hash32 {
    sha256(&[
        &[DOMAIN_COUNT],
        &leaf_count.to_le_bytes(),
        merkle_root.as_ref(),
    ])
}

/// What a light client needs, besides the header `tx_root` and the leaf id, to check
/// that a leaf is in a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionPath {
    /// Position of the leaf.
    pub index: u32,
    /// Leaves of the tree, committed by `tx_root`.
    pub leaf_count: u32,
    /// Sibling hashes from the leaf up, skipping the levels where the node is promoted.
    pub siblings: Vec<Hash32>,
}

/// The path of leaf `index` of the tree over `ids`, with the leaf count.
pub fn inclusion_proof(ids: &[Hash32], index: usize) -> Result<InclusionPath, MerkleError> {
    let out_of_range = || MerkleError::IndexOutOfRange {
        index,
        leaf_count: ids.len(),
    };
    if index >= ids.len() {
        return Err(out_of_range());
    }
    let Ok(path_index) = u32::try_from(index) else {
        return Err(out_of_range());
    };
    let mut idx = index;
    let mut siblings = Vec::new();
    for level in levels(ids).iter().filter(|level| level.len() > 1) {
        if !is_promoted(idx, level.len()) {
            siblings.push(level[idx ^ 1]);
        }
        idx /= 2;
    }
    Ok(InclusionPath {
        index: path_index,
        leaf_count: leaf_count_u32(ids.len()),
        siblings,
    })
}

/// Checks a leaf against a header `tx_root`. Rejects `index >= leaf_count`, folds the
/// siblings over the leaf hash under the claimed `leaf_count` and accepts when
/// [`bound_root`] of the claimed count and the folded root equals `tx_root`. At each
/// level a promoted node consumes no sibling, any other node consumes one on the side
/// given by the index parity. All siblings must be consumed, and a wrong count fails
/// because `tx_root` commits to the true one.
pub fn verify_inclusion(
    tx_root: &Hash32,
    leaf_id: &Hash32,
    index: u32,
    leaf_count: u32,
    siblings: &[Hash32],
) -> bool {
    if index >= leaf_count {
        return false;
    }
    let mut hash = leaf_hash(leaf_id);
    let mut idx = index as usize;
    let mut n = leaf_count as usize;
    let mut rest = siblings.iter();
    while n > 1 {
        if !is_promoted(idx, n) {
            let Some(sibling) = rest.next() else {
                return false;
            };
            hash = if idx % 2 == 1 {
                node_hash(sibling, &hash)
            } else {
                node_hash(&hash, sibling)
            };
        }
        idx /= 2;
        n = n.div_ceil(2);
    }
    rest.next().is_none() && bound_root(leaf_count, &hash) == *tx_root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> Hash32 {
        sha256(&[&[n]])
    }

    fn leaf(n: u8) -> Hash32 {
        sha256(&[&[0x00], id(n).as_ref()])
    }

    fn node(l: &Hash32, r: &Hash32) -> Hash32 {
        sha256(&[&[0x01], l.as_ref(), r.as_ref()])
    }

    fn empty() -> Hash32 {
        sha256(&[&[0x00]])
    }

    fn ids(count: u8) -> Vec<Hash32> {
        (1..=count).map(id).collect()
    }

    #[test]
    fn empty_root_is_sha256_of_zero_byte() {
        assert_eq!(merkle_root(&[]), empty());
        assert_eq!(
            merkle_root(&[]).to_string(),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
    }

    #[test]
    fn root_of_one_two_three_four_leaves() {
        let ids = ids(4);
        assert_eq!(merkle_root(&ids[..1]), leaf(1));
        let two = node(&leaf(1), &leaf(2));
        assert_eq!(merkle_root(&ids[..2]), two);
        assert_eq!(merkle_root(&ids[..3]), node(&two, &leaf(3)));
        let four = node(&two, &node(&leaf(3), &leaf(4)));
        assert_eq!(merkle_root(&ids[..4]), four);
    }

    fn bound(count: usize) -> Hash32 {
        let ids = ids(u8::try_from(count).unwrap());
        bound_root(leaf_count_u32(count), &merkle_root(&ids))
    }

    fn verifies(ids: &[Hash32], index: usize, claimed_index: u32, claimed_count: u32) -> bool {
        let path = inclusion_proof(ids, index).unwrap();
        let root = bound_root(leaf_count_u32(ids.len()), &merkle_root(ids));
        verify_inclusion(
            &root,
            &ids[index],
            claimed_index,
            claimed_count,
            &path.siblings,
        )
    }

    #[test]
    fn bound_root_hashes_domain_count_and_root() {
        let root = merkle_root(&ids(3));
        let by_hand = sha256(&[&[0x02], &3u32.to_le_bytes(), root.as_ref()]);
        assert_eq!(bound_root(3, &root), by_hand);
        assert_ne!(bound_root(3, &root), bound_root(4, &root));
    }

    #[test]
    fn leaf_count_saturates() {
        assert_eq!(leaf_count_u32(7), 7);
        assert_eq!(leaf_count_u32(usize::MAX), u32::MAX);
    }

    #[test]
    fn inclusion_proofs_verify_for_every_index_and_count() {
        for count in 1..=39u8 {
            let ids = ids(count);
            for index in 0..ids.len() {
                let path = inclusion_proof(&ids, index).unwrap();
                assert_eq!(path.leaf_count, u32::from(count));
                assert_eq!(path.index as usize, index);
                assert!(verifies(&ids, index, path.index, path.leaf_count));
            }
        }
    }

    #[test]
    fn a_promoted_leaf_has_a_shorter_proof() {
        let three = ids(3);
        assert_eq!(inclusion_proof(&three, 2).unwrap().siblings.len(), 1);
        assert_eq!(inclusion_proof(&three, 0).unwrap().siblings.len(), 2);
        assert_eq!(inclusion_proof(&ids(1), 0).unwrap().siblings.len(), 0);
    }

    #[test]
    fn a_proof_for_two_leaves_does_not_verify_as_three() {
        let ids = ids(2);
        assert!(verifies(&ids, 1, 1, 2));
        assert!(!verifies(&ids, 1, 2, 3));
    }

    #[test]
    fn no_wrong_index_or_count_verifies() {
        let mut accepted = 0;
        for count in 1..=17u8 {
            let ids = ids(count);
            let root = bound(usize::from(count));
            for index in 0..ids.len() {
                let siblings = inclusion_proof(&ids, index).unwrap().siblings;
                for claimed_count in 1..36u32 {
                    for claimed_index in 0..claimed_count {
                        let is_true =
                            claimed_count == u32::from(count) && claimed_index as usize == index;
                        let ok = verify_inclusion(
                            &root,
                            &ids[index],
                            claimed_index,
                            claimed_count,
                            &siblings,
                        );
                        accepted += usize::from(ok && !is_true);
                    }
                }
            }
        }
        assert_eq!(accepted, 0);
    }

    #[test]
    fn wrong_leaf_or_root_fails() {
        let ids = ids(5);
        let root = bound(5);
        let path = inclusion_proof(&ids, 2).unwrap();
        assert!(verify_inclusion(&root, &ids[2], 2, 5, &path.siblings));
        assert!(!verify_inclusion(&root, &ids[1], 2, 5, &path.siblings));
        assert!(!verify_inclusion(
            &Hash32([0; 32]),
            &ids[2],
            2,
            5,
            &path.siblings
        ));
        assert!(!verify_inclusion(
            &merkle_root(&ids),
            &ids[2],
            2,
            5,
            &path.siblings
        ));
    }

    #[test]
    fn index_at_or_above_the_count_fails() {
        let ids = ids(5);
        let root = bound(5);
        let path = inclusion_proof(&ids, 2).unwrap();
        for index in [5, 6, u32::MAX] {
            assert!(!verify_inclusion(&root, &ids[2], index, 5, &path.siblings));
        }
        assert!(!verify_inclusion(&bound(0), &ids[0], 0, 0, &[]));
    }

    #[test]
    fn missing_or_extra_sibling_fails() {
        let ids = ids(5);
        let root = bound(5);
        let siblings = inclusion_proof(&ids, 2).unwrap().siblings;
        assert!(!verify_inclusion(&root, &ids[2], 2, 5, &siblings[1..]));
        assert!(!verify_inclusion(&root, &ids[2], 2, 5, &siblings[..2]));
        let mut extra = siblings.clone();
        extra.push(empty());
        assert!(!verify_inclusion(&root, &ids[2], 2, 5, &extra));
        assert!(!verify_inclusion(&root, &ids[2], 2, 5, &[]));
    }

    #[test]
    fn proof_for_missing_index_is_an_error() {
        assert_eq!(
            inclusion_proof(&[id(1)], 1),
            Err(MerkleError::IndexOutOfRange {
                index: 1,
                leaf_count: 1
            })
        );
    }
}
