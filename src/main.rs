//! Certificate Transparency stuff with some detailed explanation.

// First, serveral utility functions

mod utils;
use utils::{hex_to_u8, sha256, u8_to_hex};

pub fn combine_tree_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
	let mut buf = Vec::new();
	buf.reserve(32 + 32 + 1);
	buf.push(1);
	buf.extend_from_slice(left);
	buf.extend_from_slice(right);
	sha256(&buf[..])
}

fn largest_power_of_2_smaller_than(mut n: u64) -> u64 {
	if n <= 1 {
		return 0;
	}
	if n == 2 {
		return 1;
	}
	n -= 1;
	// I'm sure compiler will optimize this suitably.
	let mut pow: u64 = 1;
	loop {
		n /= 2;
		pow *= 2;
		if n == 1 {
			return pow;
		}
	}
}

#[test]
fn test_largest_power_of_2_smaller_than() {
	assert_eq!(largest_power_of_2_smaller_than(0), 0);
	assert_eq!(largest_power_of_2_smaller_than(1), 0);
	assert_eq!(largest_power_of_2_smaller_than(2), 1);
	assert_eq!(largest_power_of_2_smaller_than(3), 2);
	assert_eq!(largest_power_of_2_smaller_than(4), 2);
	assert_eq!(largest_power_of_2_smaller_than(5), 4);
	assert_eq!(largest_power_of_2_smaller_than(6), 4);
	assert_eq!(largest_power_of_2_smaller_than(7), 4);
	assert_eq!(largest_power_of_2_smaller_than(8), 4);
	assert_eq!(largest_power_of_2_smaller_than(9), 8);

	assert_eq!(largest_power_of_2_smaller_than(1u64<<33u64), 1u64<<32u64);
	assert_eq!(largest_power_of_2_smaller_than((1u64<<34u64) - 100u64), 1u64<<33u64);
}

// Consistency proof

/// Goes from top to bottom, adding proof components to `result_store`.
fn consistency_proof_partial(result_store: &mut Vec<(u64, u64)>, subtree: (u64, u64), perv_size: u64) {
	assert!(subtree.0 < subtree.1);
	assert!(perv_size <= subtree.1);
	if perv_size == subtree.1 {
		result_store.push(subtree);
		return;
	}
	let subtree_size = subtree.1 - subtree.0;
	let start_of_right_branch = largest_power_of_2_smaller_than(subtree_size);
	if perv_size - subtree.0 <= start_of_right_branch { // go left
		result_store.push((subtree.0 + start_of_right_branch, subtree.1));
		consistency_proof_partial(result_store, (subtree.0, subtree.0 + start_of_right_branch), perv_size);
	} else { // go right
		result_store.push((subtree.0, subtree.0 + start_of_right_branch));
		consistency_proof_partial(result_store, (subtree.0 + start_of_right_branch, subtree.1), perv_size);
	}
}

#[test]
fn consistency_proof_partial_test() {
	fn invoke(perv_size: u64, size: u64) -> Vec<(u64, u64)> {
		let mut result_store = Vec::new();
		consistency_proof_partial(&mut result_store, (0, size), perv_size);
		result_store.reverse();
		result_store
	};

	// Examples from RFC 6962 2.1.3 (https://tools.ietf.org/html/rfc6962#section-2.1.3)
	assert_eq!(invoke(3, 7), vec![(2, 3), (3, 4), (0, 2), (4, 7)]);
	assert_eq!(invoke(4, 7), vec![(0, 4), (4, 7)]);
	assert_eq!(invoke(6, 7), vec![(4, 6), (6, 7), (0, 4)]);

	assert_eq!(invoke(753913835, 753913848).len(), 25);
}

/// A subtree hash provided by the server in a consistency proof.
pub struct ConsistencyProofPart {
	/// (start, non-inclusive end)
	pub subtree: (u64, u64),

	/// The hash of this subtree as from the proof
	pub server_hash: [u8; 32],
}

/// Check that the consistency proof given by `server_provided_proof` gets us
/// from `perv_root` to `next_root`, returning an `Ok(Vec<ConsistencyProofPart>)`
/// if the proof checks, otherwise a `Err(String)` describing why the proof is
/// invalid.
///
/// ## `Ok(Vec<ConsistencyProofPart>)`
///
/// The `Ok` result of this function contains all components of the proof which
/// describes a new tree (that's not in the pervious tree). This can be useful if
/// you want to then get all the new certificates and verify that those forms the
/// new tree.
///
/// To do this, calculate the leaf hash of all the new certificates, and call
/// `ConsistencyProofPart::verify` with the array of leaf hashes. See its
/// documentation for more info.
///
/// ## Panic
///
/// `check_consistency_proof` panics if `perv_size` > `next_size`.
///
/// ## TODO
///
/// * Add test
pub fn check_consistency_proof(perv_size: u64, next_size: u64, server_provided_proof: &Vec<[u8; 32]>, perv_root: &[u8; 32], next_root: &[u8; 32]) -> Result<Vec<ConsistencyProofPart>, String> {
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
	// tree. These subtrees will entirely cover the pervious tree, and will also
	// include some new parts which is only in the current tree. To validate the
	// proof, we attempt to derive the new root hash based on these provided
	// hashes. If we got the same hash as the server signed tree hash, we know that
	// the pervious tree is entirely contained in the new tree. In addition, we
	// also need to check that the hashes which corrosponds to subtrees that
	// contains pervious nodes are genuine. We do this by attempting to construct
	// the pervious root hash based on these hashes, and see if we came up with a
	// hash that is the same as the `perv_root` provided by the caller.

	// Calculate the proof ourselve first so that we know how to use the server
	// provided proof. At the end of this, `result_store` should be the subtree
	// corrosponding to each server hash, except if `omit_first` is true (see
	// below).
	//
	// A subtree is reprsented with (u64, u64), where the first number is the
	// starting index, and the second number is the non-inclusive ending index. For
	// example, (2, 4) denote the 2-level subtree made by the nodes with index 2
	// and 3, which looks like this:
	//
	//      23
	//     /  \
	//    2    3
	let mut result_store = Vec::new();
	result_store.reserve(server_provided_proof.len() + 1);
	consistency_proof_partial(&mut result_store, (0, next_size), perv_size);
	// So that `result_store` is in bottom-to-up order.
	result_store.reverse();

	// The server will omit the first hash if it will otherwise simply be the
	// pervious root hash. This happens when pervious tree is a complete balanced
	// tree, sitting in the bottom-left corner of the current tree. Since these
	// trees always start at 0, we only need to check if the size is a power of 2
	// (hence a balanced tree)
	let omit_first = u64::is_power_of_two(perv_size);

	let mut expected_proof_len = result_store.len();
	if omit_first {
		expected_proof_len -= 1;
	}
	if server_provided_proof.len() != expected_proof_len {
		return Err(format!("wrong proof length: expected {}, got {}", expected_proof_len, server_provided_proof.len()));
	}

	let mut hashes = Vec::new();
	hashes.reserve(result_store.len());
	if omit_first {
		hashes.push(perv_root.clone());
	}
	hashes.extend_from_slice(&server_provided_proof[..]);
	assert_eq!(hashes.len(), result_store.len());
	// now `hashes` and `result_store` match up, we could start to do our hashing,
	// and try to derive the current root hash.

	let mut current_hash = hashes[0];
	let mut current_hashed_subtree = result_store[0];
	for i in 1..hashes.len() {
		let next_subtree = result_store[i];
		let next_hash = &hashes[i];
		// We need to combine the hashes in the right order. Left branch, then right
		// branch.
		if current_hashed_subtree.0 < next_subtree.0 {
			current_hash = combine_tree_hash(&current_hash, next_hash);
			assert_eq!(current_hashed_subtree.1, next_subtree.0);
			current_hashed_subtree = (current_hashed_subtree.0, next_subtree.1);
		} else {
			current_hash = combine_tree_hash(next_hash, &current_hash);
			assert_eq!(next_subtree.1, current_hashed_subtree.0);
			current_hashed_subtree = (next_subtree.0, current_hashed_subtree.1);
		}
	}
	if current_hash == *next_root {
		if omit_first {
			// we are sure that last tree is included in current tree, because we used last tree's hash to calculate current hash.
			Ok(hashes.iter().zip(result_store.iter()).skip(1).map(|(hash, subtree)| ConsistencyProofPart{subtree: *subtree, server_hash: *hash}).collect())
		} else {
			// verify that the hashes in the proof given could reconstruct the last root
			// hash, therefore that the log didn't just made up these hashes.
			let mut current_hash: Option<[u8; 32]> = None;
			let mut current_hashed_subtree: Option<(u64, u64)> = None;
			let mut new_parts = Vec::new();
			for i in 0..hashes.len() {
				let next_subtree = result_store[i];
				let next_hash = &hashes[i];
				if next_subtree.1 <= perv_size { // if next_subtree is part of the pervious tree...
					if current_hash.is_none() {
						assert!(current_hashed_subtree.is_none());
						current_hashed_subtree = Some(next_subtree);
						current_hash = Some(*next_hash)
					} else {
						let next_current_hash;
						let next_current_subtree;
						{
							let current_hash = current_hash.as_ref().unwrap();
							let current_hashed_subtree = current_hashed_subtree.unwrap();
							if current_hashed_subtree.0 < next_subtree.0 {
								next_current_hash = combine_tree_hash(current_hash, next_hash);
								assert_eq!(current_hashed_subtree.1, next_subtree.0);
								next_current_subtree = (current_hashed_subtree.0, next_subtree.1);
							} else {
								next_current_hash = combine_tree_hash(next_hash, current_hash);
								assert_eq!(next_subtree.1, current_hashed_subtree.0);
								next_current_subtree = (next_subtree.0, current_hashed_subtree.1);
							}
						}
						current_hash = Some(next_current_hash);
						current_hashed_subtree = Some(next_current_subtree);
					}
				} else {
					assert!(next_subtree.0 >= perv_size);
					new_parts.push(ConsistencyProofPart{
						subtree: next_subtree,
						server_hash: *next_hash,
					});
				}
			}
			let current_hash = current_hash.unwrap();
			if current_hash == *perv_root {
				Ok(new_parts)
			} else {
				Err(format!("calculated perv_root {} does not match given perv_root {}", u8_to_hex(&current_hash), u8_to_hex(perv_root)))
			}
		}
	} else {
		Err(format!("calculated tree root {} does not match given tree root {}", u8_to_hex(&current_hash), u8_to_hex(next_root)))
	}
}

impl ConsistencyProofPart {
	/// Verify that an array of leaf_hashes could reconstruct this subtree's
	/// `server_hash`, returning `Ok(())` when success and `Err(String)` when
	/// failure, with a string describing the reason of failure.
	///
	/// ## Panic
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

fn main() {
	use std::env;
	use std::str::FromStr;
	let args: Vec<String> = env::args().skip(1).collect();
	assert_eq!(args.len(), 4);
	let perv_size = u64::from_str(&args[0]).unwrap();
	let curr_size = u64::from_str(&args[1]).unwrap();
	let perv_root = hex_to_u8(&args[2]);
	let curr_root = hex_to_u8(&args[3]);
	assert_eq!(perv_root.len(), 32);
	assert_eq!(curr_root.len(), 32);
	let perv_root = unsafe { *(&perv_root[..] as *const [u8] as *const [u8; 32]) };
	let curr_root = unsafe { *(&curr_root[..] as *const [u8] as *const [u8; 32]) };
	use std::io;
	use std::io::Read;
	let mut stdin = io::stdin();
	let mut read_buf = String::new();
	stdin.read_to_string(&mut read_buf).unwrap();
	let srv_proof: Vec<Vec<u8>> = read_buf.lines().filter(|l| *l != "").map(|l| hex_to_u8(l)).collect();
	if let Err(verify_err) = check_consistency_proof(perv_size, curr_size, &srv_proof.iter().map(|arr| {
		assert_eq!(arr.len(), 32);
		unsafe { *(&arr[..] as *const [u8] as *const [u8; 32]) }
	}).collect(), &perv_root, &curr_root) {
		eprintln!("unable to verify: {}", verify_err);
		std::process::exit(1);
	}
	println!("verified: {} + proof => {}", u8_to_hex(&perv_root), u8_to_hex(&curr_root));
}
