//! Things that are only useful if you are doing your own API calling.

use base64;
use reqwest;
use openssl::pkey::PKey;
use crate::{jsons, utils, Error};

use log::{trace, warn};

use std::fmt;

/// Construct a new [reqwest::Client](reqwest::Client) to be used with the
/// functions in this module. You don't necessary need to use this.
///
/// The client constructed will not store cookie or follow redirect.
pub fn new_http_client() -> Result<reqwest::Client, Error> {
	use std::time;
	let mut def_headers = reqwest::header::HeaderMap::new();
	def_headers.insert("User-Agent", reqwest::header::HeaderValue::from_static("rust-ctclient"));
	match reqwest::Client::builder()
		.cookie_store(false)
		.connect_timeout(time::Duration::from_secs(5))
		.tcp_nodelay()
		.gzip(true)
		.use_sys_proxy()
		.default_headers(def_headers)
		.redirect(reqwest::RedirectPolicy::none())
		.build() {
			Ok(r) => Ok(r),
			Err(e) => Err(Error::Unknown(format!("{}", &e)))
		}
}

/// Verifies a tls digitally-signed struct (see [the TLS
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
	// First two byte type, second two byte length (of the rest).

  if dss.len() > (1usize << 16usize) + 3 {
    return Err(Error::InvalidSignature(format!("dss too long. (len = {})", dss.len())));
  }

	if dss.len() < 4 {
		return Err(Error::InvalidSignature(format!("Invalid dss: {}", &utils::u8_to_hex(dss))));
	}
	// Refer to https://docs.rs/rustls/0.15.2/src/rustls/msgs/handshake.rs.html#1546
	let sig_type = u16::from_be_bytes([dss[0], dss[1]]);
	let length = u16::from_be_bytes([dss[2], dss[3]]);
	let rest = &dss[4..];
	if rest.len() != length as usize {
		return Err(Error::InvalidSignature(format!("Invalid dss: {}\n  it says there that there are {} bytes in the signature part, but I see {}.", &utils::u8_to_hex(dss), length, rest.len())));
	}

	// Refer to https://docs.rs/rustls/0.15.2/src/rustls/msgs/enums.rs.html#720
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
pub fn get_json<J: serde::de::DeserializeOwned>(client: &reqwest::Client, base_url: &reqwest::Url, path: &str) -> Result<J, Error> {
  let url = base_url.join(path).unwrap();
  let url_str = url.as_str().to_owned();
	let mut response = client.get(url).send().map_err(|e| Error::NetIO(e))?;
	if response.status().as_u16() != 200 {
    trace!("GET {} -> {}", &url_str, response.status());
		return Err(Error::InvalidResponseStatus(response.status()));
	}
  let response = response.text().map_err(|e| Error::NetIO(e))?;
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
pub fn check_tree_head(client: &reqwest::Client, base_url: &reqwest::Url, pub_key: &PKey<openssl::pkey::Public>) -> Result<(u64, [u8; 32]), Error> {
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
	Ok((response.tree_size, unsafe { *(&root_hash[..] as *const [u8] as *const [u8; 32]) }))
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
/// Recursively calls itself to go from top to bottom, adding proof components to
/// `result_store`.
///
/// Outside caller should call with `subtree = (0, current_tree_size)`.
///
/// Will not omit the first component even if it's the same as `prev_tree_hash`
/// (the server will).
pub fn consistency_proof_partial(result_store: &mut Vec<(u64, u64)>, subtree: (u64, u64), perv_size: u64) {
  use utils::largest_power_of_2_smaller_than;
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
/// `verify_consistency_proof` panics if `perv_size` > `next_size`.
///
/// ## TODO
///
/// * Add test
pub fn verify_consistency_proof(perv_size: u64, next_size: u64, server_provided_proof: &Vec<[u8; 32]>, perv_root: &[u8; 32], next_root: &[u8; 32]) -> Result<Vec<ConsistencyProofPart>, String> {
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
      trace!("consistency checked from {} to {}; pervious tree is complete.", &utils::u8_to_hex(perv_root), &utils::u8_to_hex(next_root));
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
        trace!("consistency checked from {} to {}", &utils::u8_to_hex(perv_root), &utils::u8_to_hex(next_root));
				Ok(new_parts)
			} else {
				Err(format!("calculated perv_root {} does not match given perv_root {}", utils::u8_to_hex(&current_hash), utils::u8_to_hex(perv_root)))
			}
		}
	} else {
		Err(format!("calculated tree root {} does not match given tree root {}", utils::u8_to_hex(&current_hash), utils::u8_to_hex(next_root)))
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
/// verifies it, returning a `Vec<ConsistencyProofPart>` if success, which can be
/// used to verify the integrity of certificates downloaded from the server
/// later. An `Err(Error)` is returned if the proof is invalid, or some network
/// error happened during the request.
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
pub fn check_consistency_proof(client: &reqwest::Client, base_url: &reqwest::Url, perv_size: u64, next_size: u64, perv_root: &[u8; 32], next_root: &[u8; 32]) -> Result<Vec<ConsistencyProofPart>, Error> {
  let server_consistency_proof: jsons::ConsistencyProof = get_json(client, base_url, &format!("ct/v1/get-sth-consistency?first={}&second={}", perv_size, next_size))?;
  let server_consistency_proof = server_consistency_proof.consistency;
  let mut parsed_server_proof: Vec<[u8; 32]> = Vec::new();
  parsed_server_proof.reserve(server_consistency_proof.len());
  let mut n = 0;
  for i in server_consistency_proof.into_iter() {
    n += 1;
    let decoded = base64::decode(&i).map_err(|e| Error::MalformedResponseBody(format!("Can not base64 decode consistency proof element: {}", &e)))?;
    if decoded.len() != 32 {
      return Err(Error::MalformedResponseBody(format!("Consistency proof element has length other than 32.")));
    }
    parsed_server_proof.push(unsafe {*(&decoded[..] as *const [u8] as *const [u8; 32])});
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

  client: &'a reqwest::Client,
  base_url: &'a reqwest::Url,
}

impl<'a> GetEntriesIter<'a> {
  fn new(range: std::ops::Range<u64>, client: &'a reqwest::Client, base_url: &'a reqwest::Url) -> Self {
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
        if next_entries.len() == 0 {
          self.last_gotten_entries = (next_sub_range, Vec::new());
          return self.next();
        } else {
          self.last_gotten_entries = (next_sub_range, next_entries.into_iter().map(|x| Some(x)).collect());
          self.next_index += 1;
          let leaf_entry = self.last_gotten_entries.1[0].take().unwrap();
          match Leaf::try_from(&leaf_entry) {
            Ok(leaf) => {
              return Some(Ok(leaf));
            },
            Err(e) => {
              self.done = true;
              return Some(Err(e));
            }
          }
        }
      } else {
        let err = try_next_entries.unwrap_err();
        self.done = true;
        return Some(Err(err));
      }
    } else {
      assert_eq!(last_gotten_entries.len() as u64, last_gotten_range.end - last_gotten_range.start);
      let leaf_entry = last_gotten_entries[(self.next_index - last_gotten_range.start) as usize].take().unwrap();
      self.next_index += 1;
      match Leaf::try_from(&leaf_entry) {
        Ok(leaf) => {
          return Some(Ok(leaf));
        },
        Err(e) => {
          self.done = true;
          return Some(Err(e));
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
      return (1, Some(rem_size as usize))
    } else {
      return (0, Some(0))
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
pub fn get_entries<'a>(client: &'a reqwest::Client, base_url: &'a reqwest::Url, range: Range<u64>) -> GetEntriesIter<'a> {
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
    let ERR_INVALID: Result<Self, Error> = Err(Error::MalformedResponseBody(format!("Invalid leaf data.")));
    let ERR_INVALID_EXTRA: Result<Self, Error> = Err(Error::MalformedResponseBody(format!("Invalid extra data.")));
    if leaf_input.len() < 2 {
      return ERR_INVALID;
    }
    let mut leaf_slice = &leaf_input[..];
    let version = u8::from_be_bytes([leaf_slice[0]]);
    let leaf_type = u8::from_be_bytes([leaf_slice[1]]);
    if version != 0 || leaf_type != 0 {
      return ERR_INVALID; // TODO should ignore.
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
      return ERR_INVALID;
    }
    let timestamp = u64::from_be_bytes([leaf_slice[0], leaf_slice[1], leaf_slice[2], leaf_slice[3], leaf_slice[4], leaf_slice[5], leaf_slice[6], leaf_slice[7]]);
    leaf_slice = &leaf_slice[8..];
    let entry_type = u16::from_be_bytes([leaf_slice[0], leaf_slice[1]]);
    leaf_slice = &leaf_slice[2..];
    match entry_type {
      0 => { // x509_entry
        is_pre_cert = false;
        // len is u24
        if leaf_slice.len() < 3 {
          return ERR_INVALID;
        }
        let len = u32::from_be_bytes([0, leaf_slice[0], leaf_slice[1], leaf_slice[2]]);
        leaf_slice = &leaf_slice[3..];
        if leaf_slice.len() < len as usize {
          return ERR_INVALID;
        }
        let x509_end = &leaf_slice[..len as usize]; // DER certificate
        leaf_slice = &leaf_slice[len as usize..];

        // Extra data is [][]byte with all length u24.
        let mut extra_slice = &extra_data[..];
        if extra_slice.len() < 3 {
          return ERR_INVALID_EXTRA;
        }
        let chain_byte_len = u32::from_be_bytes([0, extra_slice[0], extra_slice[1], extra_slice[2]]);
        extra_slice = &extra_slice[3..];
        if extra_slice.len() != chain_byte_len as usize {
          return ERR_INVALID_EXTRA;
        }
        x509_chain = Vec::new();
        x509_chain.push(Vec::from(x509_end));
        while extra_slice.len() > 0 {
          if extra_slice.len() < 3 {
            return ERR_INVALID_EXTRA;
          }
          let len = u32::from_be_bytes([0, extra_slice[0], extra_slice[1], extra_slice[2]]);
          extra_slice = &extra_slice[3..];
          if extra_slice.len() < len as usize {
            return ERR_INVALID_EXTRA;
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
          return ERR_INVALID;
        }
        let _issuer_key_hash = &leaf_slice[0..32];
        leaf_slice = &leaf_slice[32..];
        if leaf_slice.len() < 3 {
          return ERR_INVALID;
        }
        let len = u32::from_be_bytes([0, leaf_slice[0], leaf_slice[1], leaf_slice[2]]);
        leaf_slice = &leaf_slice[3..];
        if leaf_slice.len() < len as usize {
          return ERR_INVALID;
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
          return ERR_INVALID_EXTRA;
        }
        let pre_cert_len = u32::from_be_bytes([0, extra_slice[0], extra_slice[1], extra_slice[2]]);
        extra_slice = &extra_slice[3..];
        if extra_slice.len() < pre_cert_len as usize {
          return ERR_INVALID_EXTRA;
        }
        let pre_cert_data = &extra_slice[..pre_cert_len as usize];
        extra_slice = &extra_slice[pre_cert_len as usize..];
        x509_chain = Vec::new();
        x509_chain.push(Vec::from(pre_cert_data));
        if extra_slice.len() < 3 {
          return ERR_INVALID_EXTRA;
        }
        let rest_len = u32::from_be_bytes([0, extra_slice[0], extra_slice[1], extra_slice[2]]);
        extra_slice = &extra_slice[3..];
        if extra_slice.len() != rest_len as usize {
          return ERR_INVALID_EXTRA;
        }
        while extra_slice.len() > 0 {
          if extra_slice.len() < 3 {
            return ERR_INVALID_EXTRA;
          }
          let len = u32::from_be_bytes([0, extra_slice[0], extra_slice[1], extra_slice[2]]);
          extra_slice = &extra_slice[3..];
          if extra_slice.len() < len as usize {
            return ERR_INVALID_EXTRA;
          }
          let data = &extra_slice[..len as usize];
          extra_slice = &extra_slice[len as usize..];
          x509_chain.push(Vec::from(data));
        }
      },
      _ => {
        return ERR_INVALID; // TODO should ignore.
      }
    }
    if leaf_slice.len() < 2 {
      return ERR_INVALID;
    }
    let extension_len = u16::from_be_bytes([leaf_slice[0], leaf_slice[1]]);
    leaf_slice = &leaf_slice[2..];
    if leaf_slice.len() != extension_len as usize {
      return ERR_INVALID;
    }
    Ok(Leaf{hash, is_pre_cert, x509_chain})
  }
}

use std::convert::TryFrom;

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
