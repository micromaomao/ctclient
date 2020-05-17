use std::convert::TryInto;

use log::trace;
use crate::Error;
use crate::internal::get_json;
use crate::jsons;
use crate::utils::{combine_tree_hash, largest_power_of_2_smaller_than, u8_to_hex};

/// Function used by
/// [`verify_consistency_proof`](crate::internal::verify_consistency_proof) to
/// construct a consistency proof client side (which is used to check against the
/// server proof)
///
/// Returns an array of (u64, u64)s. Each (x: u64, y: u64) denotes that this part
/// of the proof should be the hash of the subtree formed by leafs with number [x, y).
///
/// This function is only useful to those who want to do some custom proof
/// handling. You should probably use
/// [`verify_consistency_proof`](crate::internal::verify_consistency_proof)
/// instead.
///
/// Will not omit the first component even if it's the same as `prev_tree_hash`
/// (the server will). This means that the subtree represented by ret\[0] will always be
/// contained within (0, from_size) (i.e. already known).
///
/// # Example
///
/// ```
/// # use ctclient::internal::consistency_proof_partial;
/// // Examples from RFC 6962 2.1.3 (https://tools.ietf.org/html/rfc6962#section-2.1.3)
/// assert_eq!(consistency_proof_partial(3, 7), vec![(2, 3), (3, 4), (0, 2), (4, 7)]);
/// assert_eq!(consistency_proof_partial(4, 7), vec![(0, 4), (4, 7)]);
/// assert_eq!(consistency_proof_partial(6, 7), vec![(4, 6), (6, 7), (0, 4)]);
/// ```
pub fn consistency_proof_partial(from_size: u64, to_size: u64) -> Vec<(u64, u64)> {
  // The function 'verify_consistency_proof' contains detailed comments about the nature of consistency proofs.

  fn inner(result_store: &mut Vec<(u64, u64)>, subtree: (u64, u64), from_size: u64) {
    assert!(subtree.0 < subtree.1);
    assert!(from_size <= subtree.1);
    if from_size == subtree.1 {
      result_store.push(subtree);
      return;
    }
    let subtree_size = subtree.1 - subtree.0;
    let start_of_right_branch = largest_power_of_2_smaller_than(subtree_size);
    if from_size - subtree.0 <= start_of_right_branch { // go left
      result_store.push((subtree.0 + start_of_right_branch, subtree.1));
      inner(result_store, (subtree.0, subtree.0 + start_of_right_branch), from_size);
    } else { // go right
      result_store.push((subtree.0, subtree.0 + start_of_right_branch));
      inner(result_store, (subtree.0 + start_of_right_branch, subtree.1), from_size);
    }
  }
  let mut result_store = Vec::new();
  inner(&mut result_store, (0, to_size), from_size);
  result_store.reverse();
  result_store
}

#[test]
fn consistency_proof_partial_test() {
  assert_eq!(consistency_proof_partial(753913835, 753913848).len(), 25);
  assert_eq!(consistency_proof_partial(6, 6), vec![(0, 6)]);
  assert_eq!(consistency_proof_partial(7, 7), vec![(0, 7)]);

  assert_eq!(consistency_proof_partial(4, 7), vec![(0, 4), (4, 7)]);
}

/// A subtree hash provided by the server in a consistency proof.
pub struct ConsistencyProofPart {
  /// (start, non-inclusive end)
  pub subtree: (u64, u64),

  /// The hash of this subtree as from the proof
  pub server_hash: [u8; 32],
}

/// Verify that the consistency proof given by `server_provided_proof` gets us
/// from `perv_root` to `next_root`, returning an `Ok(Vec<ConsistencyProofPart>)`
/// if the proof checks, otherwise a `Err(String)` describing why the proof is
/// invalid.
///
/// This function is only useful to those who want to do some custom API calling.
/// If you're using a [`CTClient`](crate::CTClient), it will handle proof
/// checking for you.
///
/// To fetch the consistency proof from the server and verifies it, call
/// [`check_consistency_proof`](crate::internal::check_consistency_proof).
///
/// # `Ok(Vec<ConsistencyProofPart>)`
///
/// The `Ok` result of this function contains all components of the proof which
/// describes a new tree (that's not in the previous tree). This can be useful if
/// you want to then get all the new certificates and verify that those forms the
/// new tree.
///
/// To do this, calculate the leaf hash of all the new certificates, and call
/// `ConsistencyProofPart::verify` with the array of leaf hashes. See its
/// documentation for more info.
///
/// # Panic
///
/// `verify_consistency_proof` panics if `perv_size` > `next_size`.
///
pub fn verify_consistency_proof(perv_size: u64, next_size: u64, server_provided_proof: &[[u8; 32]], perv_root: &[u8; 32], next_root: &[u8; 32]) -> Result<Vec<ConsistencyProofPart>, String> {
  // todo: add test for this.

  if perv_size > next_size {
    panic!("perv_size must be <= next_size");
  }
  if perv_size == next_size {
    return Ok(Vec::new());
  }
  if perv_size == 0 {
    // An empty tree is a subtree of every tree. No need to prove.
    return Ok(vec![ConsistencyProofPart{
      subtree: (0, next_size),
      server_hash: *next_root
    }]);
  }

  // A consistency proof is an array of hashes of some subtrees of the current
  // tree. These subtrees will entirely cover the previous tree, and will also
  // include some new parts which is only in the current tree. To validate the
  // proof, we attempt to derive the new root hash based on these provided
  // hashes. If we got the same hash as the server signed tree hash, we know that
  // the previous tree is entirely contained in the new tree. In addition, we
  // also need to check that the hashes which corresponds to subtrees that
  // contains previous nodes are genuine. We do this by attempting to construct
  // the previous root hash based on these hashes, and see if we came up with a
  // hash that is the same as the `perv_root` provided by the caller.

  // A subtree is represented with (u64, u64), where the first number is the
  // starting index, and the second number is the non-inclusive ending index. For
  // example, (2, 4) denote the 2-level subtree made by the nodes with index 2
  // and 3, which looks like this:
  //
  //      23
  //     /  \
  //    2    3

  // Calculate the proof ourselves first so that we know how to use the server
  // provided proof.
  let calculated_proof = consistency_proof_partial(perv_size, next_size);

  // The server will omit the first hash if it will otherwise simply be the
  // previous root hash. This happens when previous tree is a complete balanced
  // tree, sitting in the bottom-left corner of the current tree. Since these
  // trees always start at 0, we only need to check if the size is a power of 2
  // (hence a balanced tree)
  let omit_first = u64::is_power_of_two(perv_size);

  let mut expected_proof_len = calculated_proof.len();
  if omit_first {
    expected_proof_len -= 1;
  }
  if server_provided_proof.len() != expected_proof_len {
    return Err(format!("wrong proof length: expected {}, got {}", expected_proof_len, server_provided_proof.len()));
  }

  let mut hashes = Vec::new();
  hashes.reserve(calculated_proof.len());
  if omit_first {
    hashes.push(perv_root.clone());
  }
  hashes.extend_from_slice(server_provided_proof);
  assert_eq!(hashes.len(), calculated_proof.len());

  // Now each element of `hashes` and `calculated_proof` match up
  // (hash[i] is the hash of the subtree calculated_proof[i]), we could start to
  // do our hashing, and try to derive the new root hash.

  let mut derived_new_hash = hashes[0];
  let mut derived_new_hash_subtree = calculated_proof[0];
  for (subtree, hash) in (1..hashes.len()).map(|i| (calculated_proof[i], &hashes[i])) {
    // Proof can't have overlapping subtrees
    assert_ne!(derived_new_hash_subtree.0, subtree.0);
    // Two possibilities: either the current proof part represent a subtree which
    // exists in the previous tree, or it represents an entirely new subtree. Proof entries
    // can't represent overlapping trees/trees that cover both old and new nodes (otherwise there is
    // no way to derive the hash of the old tree because the hashes to some part of the old tree is "mixed" together
    // with some part of the new tree).
    //
    // In the first case, it will always be the "left" branch, and in the second case, "right" branch.
    //
    // We need to combine the hashes in the right order:
    //  Left branch (previous branch) first, then right branch (new branch).
    if subtree.0 > derived_new_hash_subtree.0 {
      // Right branch
      assert_eq!(subtree.0, derived_new_hash_subtree.1);
      derived_new_hash = combine_tree_hash(&derived_new_hash, hash);
      derived_new_hash_subtree = (derived_new_hash_subtree.0, subtree.1);
    } else {
      // Left branch
      assert_eq!(subtree.1, derived_new_hash_subtree.0);
      derived_new_hash = combine_tree_hash(hash, &derived_new_hash);
      derived_new_hash_subtree = (subtree.0, derived_new_hash_subtree.1);
    }
  }
  if derived_new_hash != *next_root {
    return Err(format!("calculated tree root {} does not match given tree root {}", u8_to_hex(&derived_new_hash), u8_to_hex(next_root)));
  }

  // Now make sure we can derive the hash of the previous tree from this proof.
  if omit_first {
    // we are sure that last tree is included in the new tree, because we used last tree's hash to calculate the new hash.
    trace!("consistency checked from {} to {}; previous tree is complete.", &u8_to_hex(perv_root), &u8_to_hex(next_root));
    Ok(hashes.iter().zip(calculated_proof.iter()).skip(1).map(|(hash, subtree)| ConsistencyProofPart{subtree: *subtree, server_hash: *hash}).collect())
  } else {
    // First component of proof is always a part of the previous tree.
    assert!(calculated_proof[0].1 <= perv_size);
    let mut derived_old_hash: [u8; 32] = hashes[0];
    let mut derived_old_hash_subtree: (u64, u64) = calculated_proof[0];
    let mut new_parts = Vec::new();
    for (subtree, hash) in (1..hashes.len()).map(|i| (calculated_proof[i], &hashes[i])) {
      if subtree.1 <= perv_size { // if next_subtree is part of the previous tree...
        if subtree.0 > derived_old_hash_subtree.0 {
          assert_eq!(subtree.0, derived_old_hash_subtree.1);
          derived_old_hash = combine_tree_hash(&derived_old_hash, hash);
          derived_old_hash_subtree = (derived_old_hash_subtree.0, subtree.1);
        } else {
          assert_eq!(subtree.1, derived_old_hash_subtree.0);
          derived_old_hash = combine_tree_hash(hash, &derived_old_hash);
          derived_old_hash_subtree = (subtree.0, derived_old_hash_subtree.1);
        }
      } else {
        // Proof entries is either entirely new tree or entirely old tree.
        assert!(subtree.0 >= perv_size);
        new_parts.push(ConsistencyProofPart{
          subtree,
          server_hash: *hash,
        });
      }
    }
    if derived_old_hash != *perv_root {
      return Err(format!("calculated perv_root {} does not match given perv_root {}", u8_to_hex(&derived_old_hash), u8_to_hex(perv_root)));
    }

    trace!("consistency checked from {} to {}", &u8_to_hex(perv_root), &u8_to_hex(next_root));
    Ok(new_parts)
  }
}

impl ConsistencyProofPart {
  /// Verify that an array of leaf_hashes could reconstruct this subtree's
  /// `server_hash`, returning `Ok(())` when success and `Err(String)` when
  /// failure, with a string describing the reason of failure.
  ///
  /// This function is only useful to those who want to do some custom API calling.
  /// If you're using a [`CTClient`](crate::CTClient), it will handle proof
  /// checking for you.
  ///
  /// # Panic
  ///
  /// `verify` panics when `leaf_hashes` does not have the right length, which
  /// should be `subtree.1 - subtree.0`.
  pub fn verify(&self, leaf_hashes: &[[u8; 32]]) -> Result<(), String> {
    let subtree_size = self.subtree.1 - self.subtree.0;
    if leaf_hashes.len() as u64 != subtree_size {
      panic!("expected leaf_hashes to have length {}, got {}", subtree_size, leaf_hashes.len());
    }
    if subtree_size == 1 {
      return if leaf_hashes[0] != self.server_hash {
        Err(format!("expected leaf_hashes to be [{}], got [{}]", u8_to_hex(&self.server_hash), u8_to_hex(&leaf_hashes[0])))
      } else {
        Ok(())
      }
    }
    let mut round_hashes = Vec::from(leaf_hashes);
    loop {
      let mut new_round_hashes = Vec::new();
      new_round_hashes.reserve(round_hashes.len() / 2);
      for i in 0..(round_hashes.len() / 2) {
        let hash_left = round_hashes[2*i];
        let hash_right = round_hashes[2*i + 1];
        new_round_hashes.push(combine_tree_hash(&hash_left, &hash_right));
      }
      if round_hashes.len() % 2 != 0 {
        new_round_hashes.push(*round_hashes.last().unwrap());
      }
      round_hashes = new_round_hashes;
      if round_hashes.len() == 1 {
        break;
      }
    }
    assert_eq!(round_hashes.len(), 1);
    let calculated_hash = round_hashes[0];
    if self.server_hash == calculated_hash {
      Ok(())
    } else {
      Err(format!("Subtree {:?}: calculated that tree hash should be {}, but got {} from consistency check.", &self.subtree, u8_to_hex(&calculated_hash), u8_to_hex(&self.server_hash)))
    }
  }
}

#[test]
fn verify_consistency_proof_new_tree_leaf_hashes_test() {
  fn h(s: &str) -> [u8; 32] {
    sha256(s.as_bytes())
  }
  fn c(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    combine_tree_hash(a, b)
  }

  (ConsistencyProofPart{
    subtree: (0, 1),
    server_hash: h("a")
  }).verify(&[h("a")]).unwrap();

  (ConsistencyProofPart{
    subtree: (0, 1),
    server_hash: h("a")
  }).verify(&[h("b")]).expect_err("!");

  (ConsistencyProofPart{
    subtree: (2, 4),
    server_hash: c(&h("c"), &h("d"))
  }).verify(&[h("c"), h("d")]).unwrap();

  (ConsistencyProofPart{
    subtree: (0, 6),
    server_hash: c(&c(&c(&h("a"), &h("b")), &c(&h("c"), &h("d"))), &c(&h("e"), &h("f")))
  }).verify(&[h("a"), h("b"), h("c"), h("d"), h("e"), h("f")]).unwrap();

  (ConsistencyProofPart{
    subtree: (0, 6),
    server_hash: c(&c(&c(&h("a"), &h("b")), &c(&h("c"), &h("d"))), &c(&h("e"), &h("f")))
  }).verify(&[h("a"), h("b"), h("c"), h("g"), h("e"), h("f")]).expect_err("!");

  (ConsistencyProofPart{
    subtree: (0, 6),
    server_hash: c(&c(&c(&h("a"), &h("b")), &c(&h("c"), &h("d"))), &c(&h("e"), &h("f")))
  }).verify(&[h("a"), h("b"), h("c"), h("d"), h("e"), h("g")]).expect_err("!");

  (ConsistencyProofPart{
    subtree: (0, 4),
    server_hash: c(&c(&h("a"), &h("b")), &c(&h("c"), &h("d")))
  }).verify(&[h("a"), h("b"), h("c"), h("d")]).unwrap();

  (ConsistencyProofPart{
    subtree: (0, 4),
    server_hash: c(&c(&h("a"), &h("b")), &c(&h("c"), &h("d")))
  }).verify(&[h("c"), h("d"), h("a"), h("b")]).expect_err("!");
}

/// Fetch the consistency proof from prev_size to next_size from the server and
/// verifies it, returning a `Vec<ConsistencyProofPart>` if successful, which can later be
/// used to verify the integrity of certificates downloaded from the server
/// later. An `Err(...)` is returned if the proof is invalid, or some network
/// error happened during the request.
///
/// # `Ok(Vec<ConsistencyProofPart>)`
///
/// The `Ok` result of this function contains all components of the proof which
/// describes a new tree (that's not in the previous tree). This can be useful if
/// you want to then get all the new certificates and verify that those forms the
/// new tree.
///
/// To do this, calculate the leaf hash of all the new certificates, and call
/// [`ConsistencyProofPart::verify`] with the array of leaf hashes. See its
/// documentation for more info.
///
/// # Panics
///
/// ...if prev_size >= next_size
pub fn check_consistency_proof(client: &reqwest::blocking::Client, base_url: &reqwest::Url, perv_size: u64, next_size: u64, perv_root: &[u8; 32], next_root: &[u8; 32]) -> Result<Vec<ConsistencyProofPart>, Error> {
  assert!(perv_size < next_size);
  let server_consistency_proof: jsons::ConsistencyProof = get_json(client, base_url, &format!("ct/v1/get-sth-consistency?first={}&second={}", perv_size, next_size))?;
  let server_consistency_proof = server_consistency_proof.consistency;
  let mut parsed_server_proof: Vec<[u8; 32]> = Vec::new();
  parsed_server_proof.reserve(server_consistency_proof.len());
  let mut n = 0;
  for i in server_consistency_proof.into_iter() {
    n += 1;
    let decoded = base64::decode(&i).map_err(|e| Error::MalformedResponseBody(format!("Can not base64 decode consistency proof element: {}", &e)))?;
    if decoded.len() != 32 {
      return Err(Error::MalformedResponseBody("Consistency proof element has length other than 32.".to_owned()));
    }
    parsed_server_proof.push(decoded[..].try_into().unwrap());
  }
  assert_eq!(parsed_server_proof.len(), n);
  verify_consistency_proof(perv_size, next_size, &parsed_server_proof, perv_root, next_root).map_err(|e| Error::InvalidConsistencyProof(perv_size, next_size, e))
}
