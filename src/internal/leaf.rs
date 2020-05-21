use std::convert::{TryFrom, TryInto};
use std::fmt;

use crate::Error;
use crate::jsons;
use crate::utils;

/// A parsed leaf.
///
/// Parse a JSON get-entries response to this with
/// `TryFrom<&jsons::LeafEntry>::try_from`.
pub struct Leaf {
  /// What they call "leaf hash".
  pub hash: [u8; 32],
  /// The leaf timestamp provided by the log.
  pub timestamp: u64,
  pub is_pre_cert: bool,
  /// The first cert is the end entity cert (or pre cert, if `is_pre_cert` is
  /// true), and the last is the root CA.
  pub x509_chain: Vec<Vec<u8>>,
  /// When is_pre_cert is true, this contains the tbs certificate found at the leaf input data.
  /// You should verify that this is the same certificate as x509_chain\[0], except not signed.
  pub tbs_cert: Option<Vec<u8>>,
  pub issuer_key_hash: Option<Vec<u8>>,
  /// Raw extensions data. Ignored. Length not included.
  pub extensions: Vec<u8>,
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
    let mut tbs = None;
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
    let timestamp = u64::from_be_bytes(leaf_slice[0..8].try_into().unwrap());
    leaf_slice = &leaf_slice[8..];
    let entry_type = u16::from_be_bytes([leaf_slice[0], leaf_slice[1]]);
    leaf_slice = &leaf_slice[2..];
    let issuer_key_hash;
    match entry_type {
      0 => { // x509_entry
        is_pre_cert = false;
        issuer_key_hash = None;
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
        // rest of leaf_slice parsed below this match statement.

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
        issuer_key_hash = Some(leaf_slice[0..32].to_owned());
        leaf_slice = &leaf_slice[32..];
        if leaf_slice.len() < 3 {
          return err_invalid();
        }
        let len = u32::from_be_bytes([0, leaf_slice[0], leaf_slice[1], leaf_slice[2]]);
        leaf_slice = &leaf_slice[3..];
        if leaf_slice.len() < len as usize {
          return err_invalid();
        }
        let tbs_data = &leaf_slice[..len as usize];
        leaf_slice = &leaf_slice[len as usize..];
        // rest of leaf_slice parsed below this match statement.

        tbs = Some(tbs_data.to_vec());

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
    Ok(Leaf{hash, is_pre_cert, x509_chain, tbs_cert: tbs, timestamp, extensions: leaf_slice.to_owned(), issuer_key_hash})
  }
}

pub fn construct_x509_leaf_hash(x509_endcert: &[u8], timestamp: u64, extensions_data: &[u8]) -> [u8; 32] {
  let mut hash_data: Vec<u8> = Vec::new();
  hash_data.push(0); // hash type = leaf data
  // Merkle tree leaf_input:
  hash_data.push(0); // version = 0
  hash_data.push(0); // leaf type = 0
  hash_data.extend_from_slice(&timestamp.to_be_bytes()); // timestamp
  hash_data.extend_from_slice(&0u16.to_be_bytes()); // entry type = x509_entry
  // all there is left is just chain[0].
  assert!(x509_endcert.len() < 1<<24);
  hash_data.extend_from_slice(&(x509_endcert.len() as u32).to_be_bytes()[1..4]); // len of x509
  hash_data.extend_from_slice(&x509_endcert); // x509 data
  assert!(extensions_data.len() < 1<<16);
  hash_data.extend_from_slice(&(extensions_data.len() as u16).to_be_bytes()); // len of extensions
  hash_data.extend_from_slice(&extensions_data); // extensions
  utils::sha256(&hash_data)
}

pub fn construct_precert_leaf_hash(tbs: &[u8], issuer_key_hash: &[u8], timestamp: u64, extensions_data: &[u8]) -> [u8; 32] {
  assert_eq!(issuer_key_hash.len(), 32);
  let mut hash_data: Vec<u8> = Vec::new();
  hash_data.push(0); // hash type = leaf data
  // Merkle tree leaf_input:
  hash_data.push(0); // version = 0
  hash_data.push(0); // leaf type = 0
  hash_data.extend_from_slice(&timestamp.to_be_bytes()); // timestamp
  hash_data.extend_from_slice(&1u16.to_be_bytes()); // entry type = precert_entry
  hash_data.extend_from_slice(issuer_key_hash); // issuer_key_hash
  assert!(tbs.len() < 1<<24);
  hash_data.extend_from_slice(&(tbs.len() as u32).to_be_bytes()[1..4]); // len of tbs
  hash_data.extend_from_slice(tbs); // tbs
  assert!(extensions_data.len() < 1<<16);
  hash_data.extend_from_slice(&(extensions_data.len() as u16).to_be_bytes()); // len of extensions
  hash_data.extend_from_slice(&extensions_data); // extensions
  utils::sha256(&hash_data)
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
