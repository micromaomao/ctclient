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
//! This project is not a beginner tutorial on how a CT log work. Read [the
//! RFC](https://tools.ietf.org/html/rfc6962) first.
use reqwest;
use std::{fs, path, fmt, io};
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

	/// The CT server responsed with something other than 200.
	InvalidResponseStatus(reqwest::StatusCode),

	/// Server responsed with something bad (e.g. malformed JSON)
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
			Error::InvalidResponseStatus(response_code) => write!(f, "Server responsed with {} {}", response_code.as_u16(), response_code.as_str()),
			Error::MalformedResponseBody(desc) => write!(f, "Unable to parse server response: {}", &desc),
			Error::InvalidConsistencyProof(prev_size, new_size, desc) => write!(f, "Server provided an invalid consistency proof from {} to {}: {}", prev_size, new_size, &desc),
			Error::CannotVerifyTreeData(desc) => write!(f, "The certificates returned by the server is inconsistent with the perviously provided consistency proof: {}", &desc),
			Error::BadCertificate(desc) => write!(f, "The certificate returned by the server has a problem: {}", &desc),
		}
	}
}

/// A stateful CT monitor.
///
/// It remembers a last checked tree root, so that it only checks the newly added
/// certificates. It's state can be load from / stored to a file (see
/// [`new_from_state_file`](crate::CTClient::new_from_state_file)).
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

fn new_http_client() -> Result<reqwest::Client, Error> {
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

impl CTClient {
	/// Construct a new `CTClient` instance, and fetch the latest tree root.
	///
	/// Pervious certificates in this log will not be checked. Useful for testing
	/// but could result in missing some important stuff. Not recommended for
	/// production. See [`new_from_state_file`](crate::CTClient::new_from_state_file).
	///
	/// ## Errors
	///
	/// * If `base_url` does not ends with `/`.
	pub fn new_from_latest_th(base_url: &str, pub_key: &[u8]) -> Result<Self, Error> {
		if !base_url.ends_with("/") {
			return Err(Error::InvalidArgument(format!("baseUrl must end with /")));
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
	/// Pervious certificates in this log will not be checked, so make sure to check
	/// them manually (i.e. with crt.sh). For production,
	/// [`new_from_state_file`](crate::CTClient::new_from_state_file) is recommended
	/// to avoid duplicate work (checking those which has already been checked in
	/// pervious run).
	pub fn new_from_perv_tree_hash(base_url: &str, pub_key: &[u8], tree_hash: [u8; 32], tree_size: u64) -> Result<Self, Error> {
		if !base_url.ends_with("/") {
			return Err(Error::InvalidArgument(format!("baseUrl must end with /")));
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

	pub fn update(&mut self) -> Result<u64, Error> {
		let (new_tree_size, new_tree_root) = internal::check_tree_head(&self.http_client, &self.base_url, &self.pub_key)?;
		if new_tree_size == self.latest_size {
			if new_tree_root == self.latest_tree_hash {
				info!("CTClient: {} remained the same.", self.base_url.as_str());
				return Ok(new_tree_size);
			} else {
				return Err(Error::InvalidConsistencyProof(self.latest_size, new_tree_size, format!("Server forked! {} and {} both corrospond to tree_size {}", &utils::u8_to_hex(&self.latest_tree_hash), &utils::u8_to_hex(&new_tree_root), new_tree_size)));
			}
		} else if new_tree_size < self.latest_size {
			// Make sure server isn't doing trick with us.
			internal::check_consistency_proof(&self.http_client, &self.base_url, new_tree_size, self.latest_size, &new_tree_root, &self.latest_tree_hash)?;
			warn!("{} rolled back? {} -> {}", self.base_url.as_str(), self.latest_size, new_tree_size);
			return Ok(self.latest_size)
		}
		let consistency_proof_parts = internal::check_consistency_proof(&self.http_client, &self.base_url, self.latest_size, new_tree_size, &self.latest_tree_hash, &new_tree_root)?;

		let i_start = self.latest_size;
		let mut leafs = internal::get_entries(&self.http_client, &self.base_url, i_start..new_tree_size);
		let mut leaf_hashes: Vec<[u8; 32]> = Vec::new();
		leaf_hashes.reserve((new_tree_size - i_start) as usize);
		for i in i_start..new_tree_size {
			match leafs.next().unwrap() {
				Ok(leaf) => {
					leaf_hashes.push(leaf.leaf_hash());
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
		}
		assert_eq!(leaf_hashes.len(), (new_tree_size - i_start) as usize);
		for proof_part in consistency_proof_parts.into_iter() {
			assert!(proof_part.subtree.0 >= i_start);
			assert!(proof_part.subtree.1 <= new_tree_size);
			proof_part.verify(&leaf_hashes[(proof_part.subtree.0 - i_start) as usize..(proof_part.subtree.1 - i_start) as usize]).map_err(|e| Error::CannotVerifyTreeData(e))?;
		}

		self.latest_size = new_tree_size;
		self.latest_tree_hash = new_tree_root;
		info!("CTClient: {} updated to {} {} (read {} leaves)", self.base_url.as_str(), new_tree_size, &utils::u8_to_hex(&new_tree_root), new_tree_size - i_start);
		Ok(new_tree_size)
	}

	fn check_leaf(&self, leaf: &internal::Leaf) -> Result<(), Error> {
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
			return Err(Error::BadCertificate(format!("Empty certificate chain?")));
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
			let mut dns_names: Vec<String> = Vec::new();
			if let Some(san) = cert.subject_alt_names() {
				for name in san.iter() {
					if let Some(name) = name.dnsname() {
						dns_names.push(String::from(name));
					} else if let Some(uri) = name.uri() {
						let url_parsed = reqwest::Url::parse(uri).map_err(|_| Error::BadCertificate(format!("This certificate has a URI SNI, but the URI is not parsable.")))?;
						if let Some(host) = url_parsed.domain() {
							dns_names.push(String::from(host));
						}
					}
				}
			}
			if is_first {
				trace!("Check leaf: {:?} ({}, etc...)", &leaf, common_names.get(0).unwrap_or(&String::from("(no common name)")));
			}
			is_first = false;
		}
		Ok(())
	}

	pub fn new_from_state_file<P: AsRef<path::Path>>(file_path: P) -> Result<Self, Error> {
		let save_file = fs::OpenOptions::new().create(false).read(true).write(true).open(&file_path)
			.map_err(|e| Error::FileIO(file_path.as_ref().to_path_buf(), e))?;
		unimplemented!();
	}
}
