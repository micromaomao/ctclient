use std::ops::Range;
use crate::Error;
use crate::internal::get_json;
use crate::jsons::AuditProof;
use std::convert::TryInto;
use crate::utils::{combine_tree_hash, u8_to_hex};

/// Returns an array of `Range<u64>`s. Each x..y denotes that this part
/// of the proof should be the hash of the subtree formed by leafs with number [x, y).
///
/// # Panics
///
/// If `index` >= `tree_size`.
///
/// # Examples
///
/// ```
/// # use ctclient::internal::inclusion_proof_parts;
/// // Examples from https://tools.ietf.org/html/rfc6962#section-2.1.3
/// assert_eq!(inclusion_proof_parts(7, 0), vec![1..2, 2..4, 4..7]);
/// assert_eq!(inclusion_proof_parts(7, 3), vec![2..3, 0..2, 4..7]);
/// assert_eq!(inclusion_proof_parts(7, 4), vec![5..6, 6..7, 0..4]);
/// assert_eq!(inclusion_proof_parts(7, 6), vec![4..6, 0..4]);
/// ```
pub fn inclusion_proof_parts(tree_size: u64, index: u64) -> Vec<Range<u64>> {
  assert!(index < tree_size);
  let mut current_subtree = index..(index + 1);
  let mut result = Vec::new();
  while current_subtree.end - current_subtree.start < tree_size {
    let next_subtree_len = (current_subtree.end - current_subtree.start) * 2;
    let next_subtree_start = current_subtree.start / next_subtree_len * next_subtree_len;
    let next_subtree = next_subtree_start..(next_subtree_start + next_subtree_len);
    let mid = next_subtree_start + next_subtree_len / 2;
    if index < mid {
      // hash right
      if mid < tree_size {
        result.push(mid..u64::min(next_subtree.end, tree_size));
      } else {
        // Happens if the last part of the tree is incomplete.
        // Do nothing.
      }
    } else {
      // hash left
      result.push(next_subtree_start..mid);
    }
    current_subtree = next_subtree;
  }
  result
}

#[test]
fn test_inclusion_proof_parts() {
  assert_eq!(inclusion_proof_parts(1, 0), vec![]);
  assert_eq!(inclusion_proof_parts(2, 0), vec![1..2]);
  assert_eq!(inclusion_proof_parts(2, 1), vec![0..1]);
  assert_eq!(inclusion_proof_parts(3, 1), vec![0..1, 2..3]);
  assert_eq!(inclusion_proof_parts(5, 0), vec![1..2, 2..4, 4..5]);
  assert_eq!(inclusion_proof_parts(5, 4), vec![0..4]);
}

/// Fetch the required inclusion proof from the server and see if it convinces us that `leaf_hash` is
/// in the tree with hash `tree_hash` and size `tree_size`. On success, return the index number of the
/// leaf corresponding with the hash.
pub fn check_inclusion_proof(client: &reqwest::blocking::Client, base_url: &reqwest::Url, tree_size: u64, tree_hash: &[u8; 32], leaf_hash: &[u8; 32]) -> Result<u64, Error> {
  let json: AuditProof = get_json(client, base_url,
      &format!("ct/v1/get-proof-by-hash?{}", serde_urlencoded::to_string(&[
        ("hash", base64::encode(leaf_hash)),
        ("tree_size", tree_size.to_string())
      ]).map_err(|e| Error::Unknown(format!("{}", e)))?)
  )?;
  let leaf_index = json.leaf_index;
  if json.leaf_index >= tree_size {
    return Err(Error::InvalidInclusionProof {tree_size, leaf_index, desc: "returned leaf_index >= tree_size.".to_owned()});
  }
  let proof_parts = inclusion_proof_parts(tree_size, leaf_index);
  if proof_parts.len() != json.audit_path.len() {
    return Err(Error::InvalidInclusionProof {tree_size, leaf_index, desc: format!("Expected proof with {} parts, got {}.", proof_parts.len(), json.audit_path.len())});
  }
  let mut provided_proof: Vec<[u8; 32]> = Vec::with_capacity(proof_parts.len());
  for i in 0..proof_parts.len() {
    let hash = base64::decode(&json.audit_path[i]).map_err(|e| {
      Error::MalformedResponseBody(format!("Unable to decode base64 in proof: {}", e))
    })?;
    if hash.len() != 32 {
      return Err(Error::MalformedResponseBody("One or more component in the proof does not has length 32.".to_owned()));
    }
    provided_proof.push(hash[..].try_into().unwrap());
  }
  let got_hash = hash_inclusion_proof(&proof_parts, &provided_proof, leaf_hash, leaf_index);
  if &got_hash != tree_hash {
    return Err(Error::InvalidInclusionProof {tree_size, leaf_index, desc:
            format!("Expected the proof to yield a tree hash of {}, but instead got {}.", u8_to_hex(tree_hash), u8_to_hex(&got_hash))});
  }
  Ok(leaf_index)
}

/// Attempt to derive the root hash from the server provided inclusion proof and our calculated proof_parts.
///
/// Used by [`check_inclusion_proof`].
pub fn hash_inclusion_proof(proof_parts: &[Range<u64>], provided_proof: &[[u8; 32]], leaf_hash: &[u8; 32], leaf_index: u64) -> [u8; 32] {
  let mut current_hash = *leaf_hash;
  let mut current_subtree = leaf_index..leaf_index + 1;
  assert_eq!(proof_parts.len(), provided_proof.len());
  for (proof_part, proof_hash) in proof_parts.iter().zip(provided_proof.iter()) {
    if proof_part.start == current_subtree.end {
      //          .
      //       /     \
      // [current] [proof]
      current_hash = combine_tree_hash(&current_hash, proof_hash);
      current_subtree = current_subtree.start..proof_part.end;
    } else if proof_part.end == current_subtree.start {
      // [proof]   [current]
      current_hash = combine_tree_hash(proof_hash, &current_hash);
      current_subtree = proof_part.start..current_subtree.end;
    } else {
      unreachable!()
    }
  }
  current_hash
}

#[test]
fn test() {
}
