use openssl::pkey::PKey;

use crate::{Error, internal};

/// A *signed tree head* (STH), as returned from the server. This encapsulate the state of the tree at
/// some point in time.
///
/// This struct stores the signature but does not store the public key or log id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTreeHead {
  pub tree_size: u64,
  pub timestamp: u64,
  pub root_hash: [u8; 32],
  /// Digitally signed struct
  pub signature: Vec<u8>
}

impl SignedTreeHead {
  /// Verify the contained signature against the log's public key.
  pub fn verify(&self, pub_key: &PKey<openssl::pkey::Public>) -> Result<(), Error> {
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
    verify_body.extend_from_slice(&self.timestamp.to_be_bytes()); // Timestamp
    verify_body.extend_from_slice(&self.tree_size.to_be_bytes()); // TreeSize
    verify_body.extend_from_slice(&self.root_hash);
    internal::verify_dss(&self.signature, pub_key, &verify_body).map_err(|e| {
      match e {
        Error::InvalidSignature(desc) => Error::InvalidSignature(format!("When checking STH signature: {}", &desc)),
        other => other
      }
    })
  }
}
