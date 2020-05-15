//! Things that are only useful if you are doing your own API calling.

use openssl::pkey::PKey;
use crate::{jsons, utils, Error};
use std::convert::{TryFrom, TryInto};
use log::trace;
use std::fmt;

/// Construct a new [reqwest::Client](reqwest::Client) to be used with the
/// functions in this module. You don't necessary need to use this.
///
/// The client constructed will not store cookie or follow redirect.
pub fn new_http_client() -> Result<reqwest::blocking::Client, Error> {
	use std::time;
	let mut def_headers = reqwest::header::HeaderMap::new();
	def_headers.insert("User-Agent", reqwest::header::HeaderValue::from_static("rust-ctclient"));
	match reqwest::blocking::Client::builder()
		.connect_timeout(time::Duration::from_secs(5))
		.tcp_nodelay()
		.gzip(true)
		.default_headers(def_headers)
		.redirect(reqwest::redirect::Policy::none())
		.build() {
			Ok(r) => Ok(r),
			Err(e) => Err(Error::Unknown(format!("{}", &e)))
		}
}

/// Verifies a TLS digitally-signed struct (see [the TLS
/// RFC](https://tools.ietf.org/html/rfc5246#section-4.7) for more info.)
///
/// This function is only useful to those who want to do some custom CT API
/// calling. [`CTClient`](crate::CTClient) will automatically verify all
/// signature.
///
/// ## Params
///
/// * `dss`: the `DigitallySigned` struct. Often returned as a
/// base64 "signature" json field by the CT server. De-base64 yourself before
/// calling.
///
/// * `pub_key`: use
/// [openssl::pkey::PKey::public_key_from_der](openssl::pkey::PKey::public_key_from_der)
/// to turn the key provided by google's ct log list into openssl key object.
///
/// * `data`: the stuff to verify against. Server should have signed this.
pub fn verify_dss(dss: &[u8], pub_key: &PKey<openssl::pkey::Public>, data: &[u8]) -> Result<(), Error> {
	// rustls crate contain code that parses this structure:
	// 	https://docs.rs/rustls/0.15.2/src/rustls/msgs/handshake.rs.html#1546
	// It shows that the struct begins with two bytes denoting the signature scheme, and
	// then follows a 2-byte length of the rest of the struct.

  if dss.len() > (1usize << 16usize) + 3 {
    return Err(Error::InvalidSignature(format!("dss too long. (len = {})", dss.len())));
  }

	if dss.len() < 4 {
		return Err(Error::InvalidSignature(format!("Invalid dss: {}\n  Too short. Expected at least 4 bytes.", &utils::u8_to_hex(dss))));
	}
	let sig_type = u16::from_be_bytes([dss[0], dss[1]]);
	let length = u16::from_be_bytes([dss[2], dss[3]]);
	let rest = &dss[4..];
	if rest.len() != length as usize {
		return Err(Error::InvalidSignature(format!("Invalid dss: {}\n  It says there that there are {} bytes in the signature part, but I see {}.", &utils::u8_to_hex(dss), length, rest.len())));
	}

	// https://docs.rs/rustls/0.15.2/src/rustls/msgs/enums.rs.html#720
  // We only need to handle these two cases because RFC says so.
	const SIGSCHEME_ECDSA_NISTP256_SHA256: u16 = 0x0403;
	const SIGSCHEME_RSA_PKCS1_SHA256: u16 = 0x0401;
	match sig_type {
		SIGSCHEME_ECDSA_NISTP256_SHA256 => {
			if pub_key.id() != openssl::pkey::Id::EC {
				return Err(Error::InvalidSignature(format!("dss says signature is EC, but key is {:?}", pub_key.id())));
			}
		}
		SIGSCHEME_RSA_PKCS1_SHA256 => {
			if pub_key.id() != openssl::pkey::Id::RSA {
				return Err(Error::InvalidSignature(format!("dss says signature is RSA, but key is {:?}", pub_key.id())));
			}
		}
		_ => {
			return Err(Error::InvalidSignature(format!("Unknow signature scheme {:2x}", sig_type)));
		}
	}

	let mut verifier = openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), pub_key).map_err(|e| Error::Unknown(format!("EVP_DigestVerifyInit: {}", &e)))?;
	if sig_type == SIGSCHEME_RSA_PKCS1_SHA256 {
		verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1).map_err(|e| Error::Unknown(format!("EVP_PKEY_CTX_set_rsa_padding: {}", &e)))?;
	}
	verifier.update(data).map_err(|e| Error::Unknown(format!("EVP_DigestUpdate: {}", &e)))?;
	if !verifier.verify(rest).map_err(|e| Error::InvalidSignature(format!("EVP_DigestVerifyFinal: {}", &e)))? {
		return Err(Error::InvalidSignature(format!("Signature is invalid: signature = {}, data = {}.", &utils::u8_to_hex(rest), &utils::u8_to_hex(data))));
	}

  trace!("Signature checked for data {} - signature is {}", &utils::u8_to_hex(data), &utils::u8_to_hex(dss));

	Ok(())
}

#[test]
fn verify_dss_test() {
	let key = PKey::public_key_from_der(&utils::hex_to_u8("3056301006072a8648ce3d020106052b8104000a0342000412c022d1b5cab048f419d46f111743cea4fcd54a05228d14cecd9cc1d120e4cc3e22e8481e5ccc3db16273a8d981ac144306d644a4227468fccd6580563ec8bd")[..]).unwrap();
	verify_dss(&utils::hex_to_u8("040300473045022100ba6da0fb4d4440965dd1d096212da95880320113320ddc5202a0b280ac518349022005bb17637d4ed06facb4af5b4b9b9083210474998ac33809a6e10c9352032055"), &key, b"hello").unwrap();
	verify_dss(&utils::hex_to_u8("0403004830460221009857dc5e2bcc0b67059a5bde9ead6a36614ab315423c0b2e4762ba7aca3f0181022100eab3af33367cb89d556c17c1ce7de1c2b8c2b80d709d0c3cbb45c8acc6809d1d"), &key, b"not hello").unwrap();
	verify_dss(&utils::hex_to_u8("0403004830460221009857dc5e2bcc0b67059a5bde9ead6a36614ab315423c0b2e4762ba7aca3f0181022100eab3af33367cb89d556c17c1ce7de1c2b8c2b80d709d0c3cbb45c8acc6809d1d"), &key, b"hello").expect_err("");

	// Don't panic.
	verify_dss(&utils::hex_to_u8(""), &key, b"hello").expect_err("");
	verify_dss(&utils::hex_to_u8("00"), &key, b"hello").expect_err("");
	verify_dss(&utils::hex_to_u8("0001"), &key, b"hello").expect_err("");
	verify_dss(&utils::hex_to_u8("000102"), &key, b"hello").expect_err("");
	verify_dss(&utils::hex_to_u8("00010203"), &key, b"hello").expect_err("");
	verify_dss(&utils::hex_to_u8("0001020304"), &key, b"hello").expect_err("");
	verify_dss(&utils::hex_to_u8("000102030405"), &key, b"hello").expect_err("");
}

/// Perform a GET request and parse the result as a JSON.
pub fn get_json<J: serde::de::DeserializeOwned>(client: &reqwest::blocking::Client, base_url: &reqwest::Url, path: &str) -> Result<J, Error> {
  let url = base_url.join(path).unwrap();
  let url_str = url.as_str().to_owned();
	let response = client.get(url).send().map_err(Error::NetIO)?;
	if response.status().as_u16() != 200 {
    trace!("GET {} -> {}", &url_str, response.status());
		return Err(Error::InvalidResponseStatus(response.status()));
	}
  let response = response.text().map_err(Error::NetIO)?;
  if response.len() > 150 {
    trace!("GET {} -> {:?}...", &url_str, &response[..150]);
  } else {
    trace!("GET {} -> {:?}", &url_str, &response);
  }
  let json = serde_json::from_str(&response).map_err(|e| Error::MalformedResponseBody(format!("Unable to decode JSON: {} (response is {:?})", &e, &response)))?;
  Ok(json)
}

/// Check, verify and return the latest tree head information from the CT log at
/// `base_url`.
///
/// This function is only useful to those who want to do some custom CT API
/// calling. [`CTClient`](crate::CTClient) will automatically update its cache of
/// tree root. If you use `CTClient`, call
/// [`CTClient::get_checked_tree_head`](crate::CTClient::get_checked_tree_head)
/// instead.
///
/// ## Params
///
/// * `client`: A [`reqwest::Client`](reqwest::Client) instance. See
/// [`CTClient::get_reqwest_client`](crate::CTClient::get_reqwest_client)
pub fn check_tree_head(client: &reqwest::blocking::Client, base_url: &reqwest::Url, pub_key: &PKey<openssl::pkey::Public>) -> Result<(u64, [u8; 32]), Error> {
	let response: jsons::STH = get_json(client, base_url, "ct/v1/get-sth")?;
	let mut verify_body: Vec<u8> = Vec::new();
	/*
		From go source:
		type TreeHeadSignature struct {
			Version        Version       `tls:"maxval:255"`
			SignatureType  SignatureType `tls:"maxval:255"` // == TreeHashSignatureType
			Timestamp      uint64
			TreeSize       uint64
			SHA256RootHash SHA256Hash
		}
	*/
	verify_body.push(0); // Version = 0
	verify_body.push(1); // SignatureType = TreeHashSignatureType
	verify_body.extend_from_slice(&response.timestamp.to_be_bytes()); // Timestamp
	verify_body.extend_from_slice(&response.tree_size.to_be_bytes()); // TreeSize
	let root_hash = base64::decode(&response.sha256_root_hash).map_err(|e| Error::MalformedResponseBody(format!("base64 decode failure on root sha256: {} (trying to decode {:?})", &e, &response.sha256_root_hash)))?;
	if root_hash.len() != 32 {
		return Err(Error::MalformedResponseBody(format!("Invalid server response: sha256_root_hash should have length of 32. Server response is {:?}", &response)));
	}
	verify_body.extend_from_slice(&root_hash[..]);
	let dss = base64::decode(&response.tree_head_signature).map_err(|e| Error::MalformedResponseBody(format!("base64 decode failure on signature: {} (trying to decode {:?})", &e, &response.tree_head_signature)))?;
	verify_dss(&dss[..], pub_key, &verify_body[..]).map_err(|e| {
    match e {
      Error::InvalidSignature(desc) => Error::InvalidSignature(format!("When checking STH signature: {}", &desc)),
      other => other
    }
  })?;
  trace!("{} tree head now on {} {}", base_url.as_str(), response.tree_size, &utils::u8_to_hex(&root_hash));
	Ok((response.tree_size, root_hash[..].try_into().unwrap()))
}

/// Function used by
/// [`verify_consistency_proof`](crate::internal::verify_consistency_proof) to
/// construct a consistency proof client side (which is used to check against the
/// server proof)
///
/// This function is only useful to those who want to do some custom proof
/// handling. You should probably use
/// [`verify_consistency_proof`](crate::internal::verify_consistency_proof)
/// instead.
///
/// Will not omit the first component even if it's the same as `prev_tree_hash`
/// (the server will). This means that the subtree represented by ret\[0] will always be
/// contained within (0, from_size) (i.e. already known).
pub fn consistency_proof_partial(from_size: u64, to_size: u64) -> Vec<(u64, u64)> {
  fn inner(result_store: &mut Vec<(u64, u64)>, subtree: (u64, u64), from_size: u64) {
		use utils::largest_power_of_2_smaller_than;
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
  // Examples from RFC 6962 2.1.3 (https://tools.ietf.org/html/rfc6962#section-2.1.3)
  assert_eq!(consistency_proof_partial(3, 7), vec![(2, 3), (3, 4), (0, 2), (4, 7)]);
  assert_eq!(consistency_proof_partial(4, 7), vec![(0, 4), (4, 7)]);
  assert_eq!(consistency_proof_partial(6, 7), vec![(4, 6), (6, 7), (0, 4)]);

  assert_eq!(consistency_proof_partial(753913835, 753913848).len(), 25);
	assert_eq!(consistency_proof_partial(6, 6), vec![(0, 6)]);
	assert_eq!(consistency_proof_partial(7, 7), vec![(0, 7)]);
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
/// ## `Ok(Vec<ConsistencyProofPart>)`
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
/// ## Panic
///
/// `verify_consistency_proof` panics if `perv_size` > `next_size`.
///
/// ## TODO
///
/// * Add test
pub fn verify_consistency_proof(perv_size: u64, next_size: u64, server_provided_proof: &[[u8; 32]], perv_root: &[u8; 32], next_root: &[u8; 32]) -> Result<Vec<ConsistencyProofPart>, String> {
  use utils::combine_tree_hash;

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
		return Err(format!("calculated tree root {} does not match given tree root {}", utils::u8_to_hex(&derived_new_hash), utils::u8_to_hex(next_root)));
	}

  // Now make sure we can derive the hash of the previous tree from this proof.
	if omit_first {
		// we are sure that last tree is included in the new tree, because we used last tree's hash to calculate the new hash.
		trace!("consistency checked from {} to {}; previous tree is complete.", &utils::u8_to_hex(perv_root), &utils::u8_to_hex(next_root));
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
			return Err(format!("calculated perv_root {} does not match given perv_root {}", utils::u8_to_hex(&derived_old_hash), utils::u8_to_hex(perv_root)));
		}

		trace!("consistency checked from {} to {}", &utils::u8_to_hex(perv_root), &utils::u8_to_hex(next_root));
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
	/// ## Panic
	///
	/// `verify` panics when `leaf_hashes` does not have the right length, which
	/// should be `subtree.1 - subtree.0`.
	pub fn verify(&self, leaf_hashes: &[[u8; 32]]) -> Result<(), String> {
    use utils::combine_tree_hash;
		let subtree_size = self.subtree.1 - self.subtree.0;
		if leaf_hashes.len() as u64 != subtree_size {
			panic!("expected leaf_hashes to have length {}, got {}", subtree_size, leaf_hashes.len());
		}
		if subtree_size == 1 {
			return if leaf_hashes[0] != self.server_hash {
				Err(format!("expected leaf_hashes to be [{}], got [{}]", utils::u8_to_hex(&self.server_hash), utils::u8_to_hex(&leaf_hashes[0])))
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
			Err(format!("Subtree {:?}: calculated that tree hash should be {}, but got {} from consistency check.", &self.subtree, utils::u8_to_hex(&calculated_hash), utils::u8_to_hex(&self.server_hash)))
		}
	}
}

#[test]
fn verify_consistency_proof_new_tree_leaf_hashes_test() {
  use utils::{sha256, combine_tree_hash};
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
/// ## `Ok(Vec<ConsistencyProofPart>)`
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
/// ## Panics
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

use std::ops::Range;
use std::iter::Iterator;

/// An iterator over `Result<Leaf, Error>`.
///
/// After the first Err result, the iterator will not produce anything else.
pub struct GetEntriesIter<'a> {
  requested_range: Range<u64>,
  done: bool,
  last_gotten_entries: (Range<u64>, Vec<Option<jsons::LeafEntry>>),
  next_index: u64,
  batch_size: u64,

  client: &'a reqwest::blocking::Client,
  base_url: &'a reqwest::Url,
}

impl<'a> GetEntriesIter<'a> {
  fn new(range: std::ops::Range<u64>, client: &'a reqwest::blocking::Client, base_url: &'a reqwest::Url) -> Self {
    Self{
      last_gotten_entries: (range.start..range.start, Vec::new()),
      next_index: range.start,
      requested_range: range,
      done: false,
      batch_size: 500,

      client, base_url
    }
  }
}

impl<'a> Iterator for GetEntriesIter<'a> {
  type Item = Result<Leaf, Error>;

  fn next(&mut self) -> Option<Self::Item> {
    if self.done {
      return None;
    }
    if self.next_index >= self.requested_range.end {
      self.done = true;
      return None;
    }
    let (ref mut last_gotten_range, ref mut last_gotten_entries) = self.last_gotten_entries;
    assert!(self.next_index >= last_gotten_range.start);
    assert!(self.next_index <= last_gotten_range.end);
    if self.next_index == last_gotten_range.end {
      assert!(self.requested_range.end > last_gotten_range.end); // The case where there's no more to be fetched is checked at the beginning of this function.
      let mut next_sub_range = last_gotten_range.end..u64::min(last_gotten_range.end + self.batch_size, self.requested_range.end);
      let try_next_entries = get_json(self.client, self.base_url, &format!("ct/v1/get-entries?start={}&end={}", next_sub_range.start, next_sub_range.end - 1)).map(|x: jsons::GetEntries| x.entries);
      if let Ok(next_entries) = try_next_entries {
        next_sub_range.end = next_sub_range.start + next_entries.len() as u64;
        if next_entries.is_empty() {
          self.last_gotten_entries = (next_sub_range, Vec::new());
					// fixme: ???
          self.next()
        } else {
          self.last_gotten_entries = (next_sub_range, next_entries.into_iter().map(Some).collect());
          self.next_index += 1;
          let leaf_entry = self.last_gotten_entries.1[0].take().unwrap();
          match Leaf::try_from(&leaf_entry) {
            Ok(leaf) => {
              Some(Ok(leaf))
            },
            Err(e) => {
              self.done = true;
              Some(Err(e))
            }
          }
        }
      } else {
        let err = try_next_entries.unwrap_err();
        self.done = true;
        Some(Err(err))
      }
    } else {
      assert_eq!(last_gotten_entries.len() as u64, last_gotten_range.end - last_gotten_range.start);
      let leaf_entry = last_gotten_entries[(self.next_index - last_gotten_range.start) as usize].take().unwrap();
      self.next_index += 1;
      match Leaf::try_from(&leaf_entry) {
        Ok(leaf) => {
          Some(Ok(leaf))
        },
        Err(e) => {
          self.done = true;
          Some(Err(e))
        }
      }
    }
  }

  fn size_hint(&self) -> (usize, Option<usize>) {
    if self.done {
      return (0, Some(0));
    }
    let rem_size = self.requested_range.end - self.next_index;
    if rem_size >= 1 {
      (1, Some(rem_size as usize))
    } else {
      (0, Some(0))
    }
  }
}

/// Request leaf entries from the CT log. Does not verify if these entries are
/// consistent with the tree or anything like that. Returns an iterator over the
/// leaves.
///
/// After the first Err result, the iterator will not produce anything else.
///
/// Uses `O(1)` memory itself.
pub fn get_entries<'a>(client: &'a reqwest::blocking::Client, base_url: &'a reqwest::Url, range: Range<u64>) -> GetEntriesIter<'a> {
  GetEntriesIter::new(range, client, base_url)
}

/// A parsed leaf.
///
/// Parse a JSON get-entries response to this with
/// `TryFrom<&jsons::LeafEntry>::try_from`.
pub struct Leaf {
  /// What they call "leaf hash".
  pub hash: [u8; 32],
  pub is_pre_cert: bool,
  /// The first cert is the end entity cert (or pre cert, if `is_pre_cert` is
  /// true), and the last is the root CA.
  pub x509_chain: Vec<Vec<u8>>,
}

impl Leaf {
  pub fn from_raw(leaf_input: &[u8], extra_data: &[u8]) -> Result<Self, Error> {
    let mut hash_data = Vec::new();
    hash_data.reserve(1 + leaf_input.len());
    hash_data.push(0);
    hash_data.extend_from_slice(leaf_input);
    let hash = utils::sha256(&hash_data);
    let is_pre_cert;
    let mut x509_chain;
    /*
      type MerkleTreeLeaf struct {
        Version          Version           `tls:"maxval:255"`
        LeafType         MerkleLeafType    `tls:"maxval:255"`
        TimestampedEntry *TimestampedEntry `tls:"selector:LeafType,val:0"`
      }
    */
    fn err_invalid() -> Result<Leaf, Error> {
			Err(Error::MalformedResponseBody("Invalid leaf data.".to_owned()))
		}
    fn err_invalid_extra() -> Result<Leaf, Error> {
			Err(Error::MalformedResponseBody("Invalid extra data.".to_owned()))
		}
    if leaf_input.len() < 2 {
      return err_invalid();
    }
    let mut leaf_slice = &leaf_input[..];
    let version = u8::from_be_bytes([leaf_slice[0]]);
    let leaf_type = u8::from_be_bytes([leaf_slice[1]]);
    if version != 0 || leaf_type != 0 {
      return err_invalid(); // TODO should ignore.
    }
    leaf_slice = &leaf_slice[2..];
    /*
      type TimestampedEntry struct {
        Timestamp    uint64
        EntryType    LogEntryType   `tls:"maxval:65535"`
        X509Entry    *ASN1Cert      `tls:"selector:EntryType,val:0"`
        PrecertEntry *PreCert       `tls:"selector:EntryType,val:1"`
        JSONEntry    *JSONDataEntry `tls:"selector:EntryType,val:32768"`
        Extensions   CTExtensions   `tls:"minlen:0,maxlen:65535"`
      }
    */
    if leaf_slice.len() < 8 + 2 {
      return err_invalid();
    }
    let _timestamp = u64::from_be_bytes(leaf_slice[0..8].try_into().unwrap());
    leaf_slice = &leaf_slice[8..];
    let entry_type = u16::from_be_bytes([leaf_slice[0], leaf_slice[1]]);
    leaf_slice = &leaf_slice[2..];
    match entry_type {
      0 => { // x509_entry
        is_pre_cert = false;
        // len is u24
        if leaf_slice.len() < 3 {
          return err_invalid();
        }
        let len = u32::from_be_bytes([0, leaf_slice[0], leaf_slice[1], leaf_slice[2]]);
        leaf_slice = &leaf_slice[3..];
        if leaf_slice.len() < len as usize {
          return err_invalid();
        }
        let x509_end = &leaf_slice[..len as usize]; // DER certificate
        leaf_slice = &leaf_slice[len as usize..];

        // Extra data is [][]byte with all length u24.
        let mut extra_slice = &extra_data[..];
        if extra_slice.len() < 3 {
          return err_invalid_extra();
        }
        let chain_byte_len = u32::from_be_bytes([0, extra_slice[0], extra_slice[1], extra_slice[2]]);
        extra_slice = &extra_slice[3..];
        if extra_slice.len() != chain_byte_len as usize {
          return err_invalid_extra();
        }
        x509_chain = Vec::new();
        x509_chain.push(Vec::from(x509_end));
        while !extra_slice.is_empty() {
          if extra_slice.len() < 3 {
            return err_invalid_extra();
          }
          let len = u32::from_be_bytes([0, extra_slice[0], extra_slice[1], extra_slice[2]]);
          extra_slice = &extra_slice[3..];
          if extra_slice.len() < len as usize {
            return err_invalid_extra();
          }
          let data = &extra_slice[..len as usize];
          extra_slice = &extra_slice[len as usize..];
          x509_chain.push(Vec::from(data));
        }
      },
      1 => { // precert_entry
        /*
          type PreCert struct {
            IssuerKeyHash  [sha256.Size]byte
            TBSCertificate []byte `tls:"minlen:1,maxlen:16777215"` // DER-encoded TBSCertificate
          }
        */
        is_pre_cert = true;
        if leaf_slice.len() < 32 {
          return err_invalid();
        }
        let _issuer_key_hash = &leaf_slice[0..32];
        leaf_slice = &leaf_slice[32..];
        if leaf_slice.len() < 3 {
					return err_invalid();
				}
        let len = u32::from_be_bytes([0, leaf_slice[0], leaf_slice[1], leaf_slice[2]]);
        leaf_slice = &leaf_slice[3..];
        if leaf_slice.len() < len as usize {
					return err_invalid();
				}
        let _x509_end = &leaf_slice[..len as usize]; // This is a "TBS" certificate - no signature and can't be parsed by OpenSSL.
        leaf_slice = &leaf_slice[len as usize..];

        /* Extra data:
          type PrecertChainEntry struct {
            PreCertificate   ASN1Cert   `tls:"minlen:1,maxlen:16777215"`
            CertificateChain []ASN1Cert `tls:"minlen:0,maxlen:16777215"`
          }
        */

        let mut extra_slice = &extra_data[..];
        if extra_slice.len() < 3 {
          return err_invalid_extra();
        }
        let pre_cert_len = u32::from_be_bytes([0, extra_slice[0], extra_slice[1], extra_slice[2]]);
        extra_slice = &extra_slice[3..];
        if extra_slice.len() < pre_cert_len as usize {
					return err_invalid_extra();
        }
        let pre_cert_data = &extra_slice[..pre_cert_len as usize];
        extra_slice = &extra_slice[pre_cert_len as usize..];
        x509_chain = Vec::new();
        x509_chain.push(Vec::from(pre_cert_data));
        if extra_slice.len() < 3 {
					return err_invalid_extra();
        }
        let rest_len = u32::from_be_bytes([0, extra_slice[0], extra_slice[1], extra_slice[2]]);
        extra_slice = &extra_slice[3..];
        if extra_slice.len() != rest_len as usize {
					return err_invalid_extra();
        }
        while !extra_slice.is_empty() {
          if extra_slice.len() < 3 {
						return err_invalid_extra();
          }
          let len = u32::from_be_bytes([0, extra_slice[0], extra_slice[1], extra_slice[2]]);
          extra_slice = &extra_slice[3..];
          if extra_slice.len() < len as usize {
						return err_invalid_extra();
          }
          let data = &extra_slice[..len as usize];
          extra_slice = &extra_slice[len as usize..];
          x509_chain.push(Vec::from(data));
        }
      },
      _ => {
        return err_invalid(); // TODO should ignore.
      }
    }
    if leaf_slice.len() < 2 {
      return err_invalid();
    }
    let extension_len = u16::from_be_bytes([leaf_slice[0], leaf_slice[1]]);
    leaf_slice = &leaf_slice[2..];
    if leaf_slice.len() != extension_len as usize {
      return err_invalid();
    }
    Ok(Leaf{hash, is_pre_cert, x509_chain})
  }
}

impl TryFrom<&jsons::LeafEntry> for Leaf {
  type Error = Error;
  fn try_from(le: &jsons::LeafEntry) -> Result<Self, Error> {
    let leaf_input = base64::decode(&le.leaf_input).map_err(|e| Error::MalformedResponseBody(format!("base64 decode leaf_input: {}", &e)))?;
    let extra_data = base64::decode(&le.extra_data).map_err(|e| Error::MalformedResponseBody(format!("base64 decode extra_data: {}", &e)))?;
    Leaf::from_raw(&leaf_input, &extra_data)
  }
}

impl fmt::Debug for Leaf {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Leaf({})", &utils::u8_to_hex(&self.hash))?;
    if self.is_pre_cert {
      write!(f, " (pre_cert)")?;
    }
    Ok(())
  }
}
