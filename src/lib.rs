//! Ct log client library.
//!
//! All `pub_key` are in der format, which is the format returned by google's
//! trusted log list (you need to de-base64 yourself).
use reqwest;
use base64;
use openssl;
use openssl::pkey::PKey;
use std::{fs, path};

mod utils;

pub struct CTClient {
	base_url: reqwest::Url,
	pub_key: PKey<openssl::pkey::Public>,
	http_client: reqwest::Client,
	latest_size: u64,
	latest_tree_hash: [u8; 32],
}

use std::fmt;
impl fmt::Debug for CTClient {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "CT log {}: current root = {}, size = {}", self.base_url, utils::u8_to_hex(&self.latest_tree_hash[..]), self.latest_size)
	}
}

fn new_http_client() -> Result<reqwest::Client, String> {
	use std::time;
	let mut def_headers = reqwest::header::HeaderMap::new();
	def_headers.insert("User-Agent", reqwest::header::HeaderValue::from_static("rust-ctclient"));
	match reqwest::Client::builder()
		.cookie_store(false)
		.connect_timeout(time::Duration::from_secs(5))
		.gzip(true)
		.timeout(time::Duration::from_secs(5))
		.use_sys_proxy()
		.default_headers(def_headers)
		.redirect(reqwest::RedirectPolicy::none())
		.build() {
			Ok(r) => Ok(r),
			Err(e) => Err(format!("{}", &e))
		}
}

mod jsons;

/// Verifies a tls digitally-signed struct (I don't understand this either; see
/// RFC https://tools.ietf.org/html/rfc5246#section-4.7 for more info.)
///
/// ## Params
///
/// * `dss`: the DigitallySigned struct, encoded in binary. Often returned as a
/// base64 "signature" json field by the CT server. De-base64 yourself before
/// calling.
///
/// * `pub_key`: use
/// [openssl::pkey::PKey::public_key_from_der](openssl::pkey::PKey::public_key_from_der)
/// to turn the key provided by google's ct log list into openssl key object.
///
/// * `data`: the stuff to verify against. Server should have signed this.
fn verify_dss(dss: &[u8], pub_key: &PKey<openssl::pkey::Public>, data: &[u8]) -> Result<(), String> {
	// First two byte type, second two byte length (of the rest).

	if dss.len() < 4 {
		return Err(format!("dss.len ({}) must be at least 4.", dss.len()));
	}
	// Refer to https://docs.rs/rustls/0.15.2/src/rustls/msgs/handshake.rs.html#1546
	let sig_type = u16::from_be_bytes([dss[0], dss[1]]);
	let length = u16::from_be_bytes([dss[2], dss[3]]);
	let rest = &dss[4..];
	if rest.len() != length as usize {
		return Err(format!("it says there that there is {} bytes in the signature part, but I see {}.", length, rest.len()));
	}

	// Refer to https://docs.rs/rustls/0.15.2/src/rustls/msgs/enums.rs.html#720
	const SIGSCHEME_ECDSA_NISTP256_SHA256: u16 = 0x0403;
	const SIGSCHEME_RSA_PKCS1_SHA256: u16 = 0x0401;
	match sig_type {
		SIGSCHEME_ECDSA_NISTP256_SHA256 => {
			if pub_key.id() != openssl::pkey::Id::EC {
				return Err(format!("Signature is EC, but key is {:?}", pub_key.id()));
			}
		}
		SIGSCHEME_RSA_PKCS1_SHA256 => {
			if pub_key.id() != openssl::pkey::Id::RSA {
				return Err(format!("Signature is RSA, but key is {:?}", pub_key.id()));
			}
		}
		_ => {
			return Err(format!("Unknow signature scheme {:2x}", sig_type));
		}
	}

	let mut verifier = openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), pub_key).map_err(|e| format!("Unable to EVP_DigestVerifyInit: {}", &e))?;
	if sig_type == SIGSCHEME_RSA_PKCS1_SHA256 {
		verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1).map_err(|e| format!("EVP_PKEY_CTX_set_rsa_padding: {}", &e))?;
	}
	verifier.update(data).map_err(|e| format!("Unable to EVP_DigestUpdate: {}", &e))?;
	if !verifier.verify(rest).map_err(|e| format!("Unable to EVP_DigestVerifyFinal: {}", &e))? {
		return Err(format!("Invalid signature."));
	}
	Ok(())
}

#[test]
fn verify_dss_test() {
	let key = PKey::public_key_from_der(&utils::hex_to_u8("3056301006072a8648ce3d020106052b8104000a0342000412c022d1b5cab048f419d46f111743cea4fcd54a05228d14cecd9cc1d120e4cc3e22e8481e5ccc3db16273a8d981ac144306d644a4227468fccd6580563ec8bd")[..]).unwrap();
	verify_dss(&utils::hex_to_u8("040300473045022100ba6da0fb4d4440965dd1d096212da95880320113320ddc5202a0b280ac518349022005bb17637d4ed06facb4af5b4b9b9083210474998ac33809a6e10c9352032055"), &key, b"hello").unwrap();
	verify_dss(&utils::hex_to_u8("0403004830460221009857dc5e2bcc0b67059a5bde9ead6a36614ab315423c0b2e4762ba7aca3f0181022100eab3af33367cb89d556c17c1ce7de1c2b8c2b80d709d0c3cbb45c8acc6809d1d"), &key, b"not hello").unwrap();
	verify_dss(&utils::hex_to_u8("0403004530460221009857dc5e2bcc0b67059a5bde9ead6a36614ab315423c0b2e4762ba7aca3f0181022100eab3af33367cb89d556c17c1ce7de1c2b8c2b80d709d0c3cbb45c8acc6809d1d"), &key, b"hello").expect_err("");

	// Don't panic.
	verify_dss(&utils::hex_to_u8(""), &key, b"hello").expect_err("");
	verify_dss(&utils::hex_to_u8("00"), &key, b"hello").expect_err("");
	verify_dss(&utils::hex_to_u8("0001"), &key, b"hello").expect_err("");
	verify_dss(&utils::hex_to_u8("000102"), &key, b"hello").expect_err("");
	verify_dss(&utils::hex_to_u8("00010203"), &key, b"hello").expect_err("");
	verify_dss(&utils::hex_to_u8("0001020304"), &key, b"hello").expect_err("");
	verify_dss(&utils::hex_to_u8("000102030405"), &key, b"hello").expect_err("");
}

/// Check and verify signed tree head
fn check_tree_head(client: &reqwest::Client, base_url: &reqwest::Url, pub_key: &PKey<openssl::pkey::Public>) -> Result<(u64, [u8; 32]), String> {
	let mut response = client.get(base_url.join("ct/v1/get-sth").map_err(|e| format!("Url failure"))?).send().map_err(|e| format!("Error getting ct/v1/get-sth: {}", &e))?;
	if response.status().as_u16() != 200 {
		return Err(format!("got status {}", response.status()));
	}
	let response: jsons::STH = response.json().map_err(|e| format!("Unable to parse response JSON: {}", &e))?;
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
	let root_hash = base64::decode(&response.sha256_root_hash).map_err(|e| format!("base64 decode failure on root sha256: {}", &e))?;
	if root_hash.len() != 32 {
		return Err(format!("Invalid server response: sha256_root_hash should have length of 32."));
	}
	verify_body.extend_from_slice(&root_hash[..]);
	let dss = base64::decode(&response.tree_head_signature).map_err(|e| format!("base64 decode failure on signature: {}", &e))?;
	verify_dss(&dss[..], pub_key, &verify_body[..]).map_err(|e| format!("Signature verification failure: {}", &e))?;
	Ok((response.tree_size, unsafe { *(&root_hash[..] as *const [u8] as *const [u8; 32]) }))
}

impl CTClient {
	/// Construct a new `CTClient` instance, and fetch the latest tree root.
	///
	/// Pervious certificates in this log will not be checked. Useful for testing
	/// but could result in missing some important stuff. Not recommended for
	/// production. See `new_from_state_file`.
	///
	/// ## Panics
	///
	/// * If `base_url` does not ends with `/`.
	pub fn new_from_latest_th(base_url: &str, pub_key: &[u8]) -> Result<Self, String> {
		if !base_url.ends_with("/") {
			panic!("baseUrl must end with /");
		}
		let base_url = reqwest::Url::parse(base_url).map_err(|e| format!("Unable to parse url: {}", &e))?;
		let http_client = new_http_client()?;
		let evp_pkey = PKey::public_key_from_der(pub_key).map_err(|e| format!("Error parsing public key: {}", &e))?;
		let (current_size, root_hash) = check_tree_head(&http_client, &base_url, &evp_pkey).map_err(|e| format!("While checking tree root: {}", &e))?;
		Ok(CTClient{
			base_url,
			pub_key: evp_pkey,
			http_client,
			latest_size: current_size,
			latest_tree_hash: root_hash,
		})
	}

	pub fn update(&mut self) -> Result<usize, String> {
		unimplemented!();
	}

	pub fn new_from_state_file<P: AsRef<path::Path>>(file_path: P) -> Result<Self, String> {
		let save_file = fs::OpenOptions::new().create(false).read(true).write(true).open(&file_path)
			.map_err(|e| format!("Unable to open {}: {}", file_path.as_ref().to_str().unwrap_or("???"), &e))?;
		unimplemented!();
	}
}
