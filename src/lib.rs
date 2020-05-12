//! Certificate Transparency Log client for monitoring and gossiping.
//!
//! The source code of this project contains some best-effort explanation
//! comments for others trying to implement such a client to read - as of 2019,
//! the documentation that exists out there are (in my opinion) pretty lacking,
//! and I had some bad time trying to implement this.
//!
//! All `pub_key` are in DER format, which is the format returned (in base64)
//! by google's trusted log list. (No one told me this).
//!
//! This project is not a beginner tutorial on how a CT log works. Read [the
//! RFC](https://tools.ietf.org/html/rfc6962) first.
use std::{path, fmt, io};
use openssl::pkey::PKey;

pub mod utils;
pub mod jsons;
pub mod internal;

use log::{info, warn, trace};

/// Errors that this library could return.
#[derive(Debug)]
pub enum Error {
	/// Some odd stuff happened.
	Unknown(String),

	/// You provided something bad.
	InvalidArgument(String),

	/// File IO error
	FileIO(path::PathBuf, io::Error),

	/// Network IO error
	NetIO(reqwest::Error),

	/// The CT server provided us with invalid signature.
	InvalidSignature(String),

	/// The CT server responded with something other than 200.
	InvalidResponseStatus(reqwest::StatusCode),

	/// Server responded with something bad (e.g. malformed JSON)
	MalformedResponseBody(String),

	/// Server returned an invalid consistency proof. (prev_size, new_size, desc)
	InvalidConsistencyProof(u64, u64, String),

	/// ConsistencyProofPart::verify failed
	CannotVerifyTreeData(String),

	// Something's wrong with the certificate.
	BadCertificate(String),
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Error::Unknown(desc) => write!(f, "{}", desc),
			Error::InvalidArgument(desc) => write!(f, "Invalid argument: {}", desc),
			Error::FileIO(path, e) => write!(f, "{}: {}", path.to_string_lossy(), &e),
			Error::NetIO(e) => write!(f, "Network IO error: {}", &e),
			Error::InvalidSignature(desc) => write!(f, "Invalid signature received: {}", &desc),
			Error::InvalidResponseStatus(response_code) => write!(f, "Server responded with {} {}", response_code.as_u16(), response_code.as_str()),
			Error::MalformedResponseBody(desc) => write!(f, "Unable to parse server response: {}", &desc),
			Error::InvalidConsistencyProof(prev_size, new_size, desc) => write!(f, "Server provided an invalid consistency proof from {} to {}: {}", prev_size, new_size, &desc),
			Error::CannotVerifyTreeData(desc) => write!(f, "The certificates returned by the server is inconsistent with the previously provided consistency proof: {}", &desc),
			Error::BadCertificate(desc) => write!(f, "The certificate returned by the server has a problem: {}", &desc),
		}
	}
}

/// A stateful CT monitor.
///
/// It remembers a last checked tree root, so that it only checks the newly added
/// certificates. It's state can be load from / stored as a `[u8]`, which you can
/// then e.g. store in a file / database.
pub struct CTClient {
	base_url: reqwest::Url,
	pub_key: PKey<openssl::pkey::Public>,
	http_client: reqwest::Client,
	latest_size: u64,
	latest_tree_hash: [u8; 32],
}

impl fmt::Debug for CTClient {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "CT log {}: current root = {}, size = {}", self.base_url, utils::u8_to_hex(&self.latest_tree_hash[..]), self.latest_size)
	}
}

use internal::new_http_client;

impl CTClient {
	/// Construct a new `CTClient` instance, and fetch the latest tree root.
	///
	/// Previous certificates in this log will not be checked. Useful for testing
	/// but could result in missing some important stuff. Not recommended for
	/// production. Use `from_bytes` and `as_bytes` to store state instead.
	///
	/// ## Errors
	///
	/// * If `base_url` does not ends with `/`.
	///
	/// ## Example
	///
	/// ```
	/// use ctclient::CTClient;
	/// use base64::decode;
	/// // URL and public key copy-pasted from https://www.gstatic.com/ct/log_list/v2/all_logs_list.json .
	/// let public_key = decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE01EAhx4o0zPQrXTcYjgCt4MVFsT0Pwjzb1RwrM0lhWDlxAYPP6/gyMCXNkOn/7KFsjL7rwk78tHMpY8rXn8AYg==").unwrap();
	/// let client = CTClient::new_from_latest_th("https://ct.cloudflare.com/logs/nimbus2020/", &public_key).unwrap();
	/// ```
	pub fn new_from_latest_th(base_url: &str, pub_key: &[u8]) -> Result<Self, Error> {
		if !base_url.ends_with('/') {
			return Err(Error::InvalidArgument("baseUrl must end with /".to_owned()));
		}
		let base_url = reqwest::Url::parse(base_url).map_err(|e| Error::InvalidArgument(format!("Unable to parse url: {}", &e)))?;
		let http_client = new_http_client()?;
		let evp_pkey = PKey::public_key_from_der(pub_key).map_err(|e| Error::InvalidArgument(format!("Error parsing public key: {}", &e)))?;
		let (current_size, root_hash) = internal::check_tree_head(&http_client, &base_url, &evp_pkey)?;
		Ok(CTClient{
			base_url,
			pub_key: evp_pkey,
			http_client,
			latest_size: current_size,
			latest_tree_hash: root_hash,
		})
	}

	/// Construct a new `CTClient` that will check all certificates included after
	/// the given tree state.
	///
	/// Previous certificates in this log before the provided tree hash will not be checked, so make sure to check
	/// them manually (i.e. with crt.sh). For production,
	/// `from_bytes` and `as_bytes` is recommended
	/// to avoid duplicate work (e.g. checking those which has already been checked in
	/// previous run).
	///
	/// ## Example
	///
	/// ```
	/// use ctclient::{CTClient, utils};
	/// use base64::decode;
	/// // URL and public key copy-pasted from https://www.gstatic.com/ct/log_list/v2/all_logs_list.json .
	/// let public_key = decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE01EAhx4o0zPQrXTcYjgCt4MVFsT0Pwjzb1RwrM0lhWDlxAYPP6/gyMCXNkOn/7KFsjL7rwk78tHMpY8rXn8AYg==").unwrap();
	/// use std::convert::TryInto;
	/// // Tree captured on 2020-05-12 15:34:11 UTC
	/// let th: [u8; 32] = (&utils::hex_to_u8("63875e88a3e37dc5b6cdbe213fe1df490d40193e4777f79467958ee157de70d6")[..]).try_into().unwrap();
	/// let client = CTClient::new_from_perv_tree_hash("https://ct.cloudflare.com/logs/nimbus2020/", &public_key, th, 299304276).unwrap();
	/// ```
	pub fn new_from_perv_tree_hash(base_url: &str, pub_key: &[u8], tree_hash: [u8; 32], tree_size: u64) -> Result<Self, Error> {
		if !base_url.ends_with('/') {
			return Err(Error::InvalidArgument("baseUrl must end with /".to_owned()));
		}
		let base_url = reqwest::Url::parse(base_url).map_err(|e| Error::InvalidArgument(format!("Unable to parse url: {}", &e)))?;
		let http_client = new_http_client()?;
		let evp_pkey = PKey::public_key_from_der(pub_key).map_err(|e| Error::InvalidArgument(format!("Error parsing public key: {}", &e)))?;
		Ok(CTClient{
			base_url,
			pub_key: evp_pkey,
			http_client,
			latest_size: tree_size,
			latest_tree_hash: tree_hash,
		})
	}

	/// Get the last checked tree head. Returns `(tree_size, root_hash)`.
	pub fn get_checked_tree_head(&self) -> (u64, [u8; 32]) {
		(self.latest_size, self.latest_tree_hash)
	}

	/// Get the underlying http client used to call CT APIs.
	pub fn get_reqwest_client(&self) -> &reqwest::Client {
		&self.http_client
	}

 /// Fetch the latest tree root, check all the new certificates, and update our
 /// internal "last checked tree root".
 ///
 /// This function should never panic, no matter what the server does to us.
 ///
 /// Returns the new tree size.
	pub fn update(&mut self) -> Result<u64, Error> {
		let mut delaycheck = std::time::Instant::now();
		let (new_tree_size, new_tree_root) = internal::check_tree_head(&self.http_client, &self.base_url, &self.pub_key)?;
   	use std::cmp::Ordering;
		match new_tree_size.cmp(&self.latest_size) {
			Ordering::Equal => {
				if new_tree_root == self.latest_tree_hash {
					info!("CTClient: {} remained the same.", self.base_url.as_str());
					Ok(new_tree_size)
				} else {
					Err(Error::InvalidConsistencyProof(self.latest_size, new_tree_size, format!("Server forked! {} and {} both corrospond to tree_size {}", &utils::u8_to_hex(&self.latest_tree_hash), &utils::u8_to_hex(&new_tree_root), new_tree_size)))
				}
			},
			Ordering::Less => {
				// Make sure server isn't doing trick with us.
				internal::check_consistency_proof(&self.http_client, &self.base_url, new_tree_size, self.latest_size, &new_tree_root, &self.latest_tree_hash)?;
				warn!("{} rolled back? {} -> {}", self.base_url.as_str(), self.latest_size, new_tree_size);
				Ok(self.latest_size)
			},
			Ordering::Greater => {
				let consistency_proof_parts = internal::check_consistency_proof(&self.http_client, &self.base_url, self.latest_size, new_tree_size, &self.latest_tree_hash, &new_tree_root)?;

				let i_start = self.latest_size;
				let mut leafs = internal::get_entries(&self.http_client, &self.base_url, i_start..new_tree_size);
				let mut leaf_hashes: Vec<[u8; 32]> = Vec::new();
				leaf_hashes.reserve((new_tree_size - i_start) as usize);
				for i in i_start..new_tree_size {
					match leafs.next().unwrap() {
						Ok(leaf) => {
							leaf_hashes.push(leaf.hash);
							self.check_leaf(&leaf)?;
						},
						Err(e) => {
							if let Error::MalformedResponseBody(inner_e) = e {
								return Err(Error::MalformedResponseBody(format!("While parsing leaf #{}: {}", i, &inner_e)));
							} else {
								return Err(e);
							}
						}
					}
					if delaycheck.elapsed() > std::time::Duration::from_secs(1) {
						info!("Catching up: {} / {}", i, new_tree_size);
						delaycheck = std::time::Instant::now();
					}
				}
				assert_eq!(leaf_hashes.len(), (new_tree_size - i_start) as usize);
				for proof_part in consistency_proof_parts.into_iter() {
					assert!(proof_part.subtree.0 >= i_start);
					assert!(proof_part.subtree.1 <= new_tree_size);
					proof_part.verify(&leaf_hashes[(proof_part.subtree.0 - i_start) as usize..(proof_part.subtree.1 - i_start) as usize]).map_err(Error::CannotVerifyTreeData)?;
				}

				self.latest_size = new_tree_size;
				self.latest_tree_hash = new_tree_root;
				info!("CTClient: {} updated to {} {} (read {} leaves)", self.base_url.as_str(), new_tree_size, &utils::u8_to_hex(&new_tree_root), new_tree_size - i_start);
				Ok(new_tree_size)
			}
		}
	}

 /// Called by [`Self::update`](crate::CTClient::update) for each leaf received
 /// to check the certificates. Usually no need to call yourself.
	pub fn check_leaf(&self, leaf: &internal::Leaf) -> Result<(), Error> {
		let chain: Vec<_> = leaf.x509_chain.iter().map(|der| {
			openssl::x509::X509::from_der(&der[..])
		}).collect();
		for rs in chain.iter() {
			if let Err(e) = rs {
				return Err(Error::BadCertificate(format!("While decoding certificate: {}", e)));
			}
		}
		let chain: Vec<_> = chain.into_iter().map(|x| x.unwrap()).collect();
		if chain.len() <= 1 {
			return Err(Error::BadCertificate("Empty certificate chain?".to_owned()));
		}
		let mut is_first = true;
		for cert in chain {
			// I tried to use openssl to verify the certificate chain here, but the CT
			// Precertificate Poison prevents it from working. (unhandled critical
			// extension)
			let try_common_names: Vec<_> = cert.subject_name().entries_by_nid(openssl::nid::Nid::COMMONNAME).map(|x| x.data().as_utf8()).collect();
			let mut common_names: Vec<String> = Vec::new();
			for cn in try_common_names {
				if let Err(e) = cn {
					return Err(Error::BadCertificate(format!("While parsing common name: {}", &e)));
				}
				common_names.push(String::from(AsRef::<str>::as_ref(&cn.unwrap())));
			}
			if is_first {
				let mut dns_names: Vec<String> = Vec::new();
				if let Some(san) = cert.subject_alt_names() {
					for name in san.iter() {
						if let Some(name) = name.dnsname() {
							dns_names.push(String::from(name));
						} else if let Some(uri) = name.uri() {
							let url_parsed = reqwest::Url::parse(uri).map_err(|_| Error::BadCertificate("This certificate has a URI SNI, but the URI is not parsable.".to_owned()))?;
							if let Some(host) = url_parsed.domain() {
								dns_names.push(String::from(host));
							}
						}
					}
				}
        for cn in common_names.iter() {
					// TODO: determine if cn is a domain name
					dns_names.push(cn.clone());
				}
				trace!("Check leaf: {:?} ({}, etc...)", &leaf, common_names.get(0).unwrap_or(&String::from("(no common name)")));
			}
			is_first = false;
		}
		Ok(())
	}

	/// Serialize the state of this client into bytes
	pub fn as_bytes(&self) -> Result<Vec<u8>, Error> {
		// Scheme: (All integers are in big-endian, fixed array don't specify length)
		// [Version: u8] [base_url in UTF-8] 0x00 [tree_size: u64] [tree_hash: [u8; 32]] [len of pub_key: u32] [pub_key: [u8]: DER public key for this log] [sha256 of everything seen before: [u8; 32]]
		let mut v = Vec::new();
		v.push(0u8); // Version = development
		let url_bytes = self.base_url.as_str().as_bytes();
		assert!(!url_bytes.contains(&0u8));
		v.extend_from_slice(url_bytes);
		v.push(0u8);
		v.extend_from_slice(&u64::to_be_bytes(self.latest_size));
		assert_eq!(self.latest_tree_hash.len(), 32);
		v.extend_from_slice(&self.latest_tree_hash);
		let pub_key = self.pub_key.public_key_to_der().map_err(|e| Error::Unknown(format!("While encoding public key: {}", &e)))?;
		assert!(pub_key.len() < std::u32::MAX as usize);
		v.extend_from_slice(&u32::to_be_bytes(pub_key.len() as u32));
		v.extend_from_slice(&pub_key);
		v.extend_from_slice(&utils::sha256(&v));
		Ok(v)
	}

  /// Parse a byte string returned by [`Self::as_bytes`].
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
		use std::convert::TryInto;
		fn e_inval() -> Result<CTClient, Error> {
			Err(Error::InvalidArgument("The bytes are invalid.".to_owned()))
		}
		let mut input = bytes;
		if input.is_empty() {
			return e_inval();
		}
		let version = input[0];
		input = &input[1..];
		if version != 0 {
			return Err(Error::InvalidArgument("The bytes are encoded by a ctclient of higher version.".to_owned()));
		}
		let base_url_len = match input.iter().position(|x| *x == 0) {
			Some(k) => k,
			None => return e_inval()
		};
		let base_url = std::str::from_utf8(&input[..base_url_len]).map_err(|e| Error::InvalidArgument(format!("Invalid UTF-8 in base_url: {}", &e)))?;
		input = &input[base_url_len + 1..];
		if input.len() < 8 {
			return e_inval();
		}
		let tree_size = u64::from_be_bytes(input[..8].try_into().unwrap());
		input = &input[8..];
		if input.len() < 32 {
			return e_inval();
		}
		let tree_hash: [u8; 32] = input[..32].try_into().unwrap();
		input = &input[32..];
		if input.len() < 4 {
			return e_inval();
		}
		let len_pub_key = u32::from_be_bytes(input[..4].try_into().unwrap());
		input = &input[4..];
		if input.len() < len_pub_key as usize {
			return e_inval();
		}
		let pub_key = &input[..len_pub_key as usize];
		input = &input[len_pub_key as usize..];
		if input.len() < 32 {
			return e_inval();
		}
		let checksum: [u8; 32] = input[..32].try_into().unwrap();
		input = &input[32..];
		if !input.is_empty() {
			return e_inval();
		}
		let expect_checksum = utils::sha256(&bytes[..bytes.len() - 32]);
		#[cfg(not(fuzzing))] {
			if checksum != expect_checksum {
				return e_inval();
			}
		}
		let pub_key = openssl::pkey::PKey::<openssl::pkey::Public>::public_key_from_der(pub_key).map_err(|e| Error::InvalidArgument(format!("Can't parse public key: {}", &e)))?;
		Ok(CTClient{
			base_url: reqwest::Url::parse(base_url).map_err(|e| Error::InvalidArgument(format!("Unable to parse base_url: {}", &e)))?,
			pub_key,
			http_client: new_http_client()?,
			latest_size: tree_size,
			latest_tree_hash: tree_hash,
		})
	}
}

#[test]
fn as_bytes_test() {
	let c = CTClient::new_from_latest_th("https://ct.googleapis.com/logs/argon2019/", &utils::hex_to_u8("3059301306072a8648ce3d020106082a8648ce3d030107034200042373109be1f35ef6986b6995961078ce49dbb404fc712c5a92606825c04a1aa1b0612d1b8714a9baf00133591d0530e94215e755d72af8b4a2ba45c946918756")).unwrap();
	let mut bytes = c.as_bytes().unwrap();
	println!("bytes: {}", &base64::encode(&bytes));
	let mut c_clone = CTClient::from_bytes(&bytes).unwrap();
	assert_eq!(c.latest_size, c_clone.latest_size);
	assert_eq!(c.latest_tree_hash, c_clone.latest_tree_hash);
	assert_eq!(c.base_url, c_clone.base_url);
	c_clone.update().unwrap(); // test public key
	let len = bytes.len();
	bytes[len - 1] ^= 1;
	CTClient::from_bytes(&bytes).expect_err("");
}
