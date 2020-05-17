//! Things that are only useful if you are doing your own API calling.

use std::convert::TryInto;

use log::trace;
use openssl::pkey::PKey;

use crate::{Error, jsons, SignedTreeHead, utils};

mod consistency;
mod get_entries;
mod leaf;
mod digitally_signed_struct;
pub use consistency::*;
pub use digitally_signed_struct::*;
pub use get_entries::*;
pub use leaf::*;

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

/// Check, verify and return the latest tree head from the CT log at
/// `base_url`.
///
/// This function is only useful to those who want to do some custom CT API
/// calling. [`CTClient`](crate::CTClient) will automatically update its cache of
/// tree root. If you use `CTClient`, call
/// [`CTClient::get_checked_tree_head`](crate::CTClient::get_checked_tree_head)
/// instead.
///
/// # Params
///
/// * `client`: A [`reqwest::Client`](reqwest::Client) instance. See
/// [`CTClient::get_reqwest_client`](crate::CTClient::get_reqwest_client)
pub fn check_tree_head(client: &reqwest::blocking::Client, base_url: &reqwest::Url, pub_key: &PKey<openssl::pkey::Public>) -> Result<SignedTreeHead, Error> {
  let response: jsons::STH = get_json(client, base_url, "ct/v1/get-sth")?;
  let root_hash = base64::decode(&response.sha256_root_hash).map_err(|e| Error::MalformedResponseBody(format!("base64 decode failure on root sha256: {} (trying to decode {:?})", &e, &response.sha256_root_hash)))?;
  if root_hash.len() != 32 {
    return Err(Error::MalformedResponseBody(format!("Invalid server response: sha256_root_hash should have length of 32. Server response is {:?}", &response)));
  }
  let dss = base64::decode(&response.tree_head_signature).map_err(|e| Error::MalformedResponseBody(format!("base64 decode failure on signature: {} (trying to decode {:?})", &e, &response.tree_head_signature)))?;
  let sth = SignedTreeHead {
    tree_size: response.tree_size,
    timestamp: response.timestamp,
    root_hash: root_hash[..].try_into().unwrap(),
    signature: dss
  };
  sth.verify(pub_key)?;
  trace!("{} tree head now on {} {}", base_url.as_str(), sth.tree_size, &utils::u8_to_hex(&sth.root_hash));
  Ok(sth)
}

