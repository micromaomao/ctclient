use std::convert::TryInto;

use openssl::pkey::PKey;
use openssl::sha::sha256;
use openssl::x509::X509Ref;

use crate::Error;
use crate::internal::leaf_hash_constructors;
use crate::internal::openssl_ffi::{sct_list_from_x509, SCTVersion, SignatureAlgorithm, x509_clone, x509_remove_sct_list, x509_to_tbs};
use crate::internal::verify_dss_raw;

fn to_unknown_err(openssl_err: openssl::error::ErrorStack) -> Error {
  Error::Unknown(format!("{}", openssl_err))
}

/// An unverified *Signed Certificate Timestamp* (SCT).
#[derive(Debug, Clone)]
pub struct SignedCertificateTimestamp {
  pub log_id: [u8; 32],
  pub timestamp: u64,
  pub extensions_data: Vec<u8>,
  pub entry: SctEntry,
  pub signature_algorithm: SignatureAlgorithm,
  /// Raw signature encoded in ASN.1
  pub raw_signature: Vec<u8>
}

/// Either a X509 der, or (in case of pre-cert) tbs and issuer key hash.
///
/// Used within [`SignedCertificateTimestamp`]
#[derive(Debug, Clone)]
pub enum SctEntry {
  X509(Vec<u8>),
  PreCert { tbs: Vec<u8>, issuer_key_hash: [u8; 32] }
}

impl SignedCertificateTimestamp {
  /// Extract a list of SCTs from the SCT List extension of the given openssl-parsed certificate,
  /// if the extension is there.
  ///
  /// If the certificate does not contain the extension, `Ok(vec![])` is returned.
  ///
  /// Will not verify the signature. Call [`self.verify`](Self::verify) with the log's public key to verify.
  pub fn from_cert_sct_extension(cert: &X509Ref, issuer: &X509Ref) -> Result<Vec<SignedCertificateTimestamp>, Error> {
    let sctlist = sct_list_from_x509(cert)?;
    if sctlist.is_none() {
      return Ok(Vec::new());
    }
    let sctlist = sctlist.unwrap();
    let tbs = {
      let mut cert_clone = x509_clone(cert).map_err(to_unknown_err)?;
      x509_remove_sct_list(&mut cert_clone).map_err(to_unknown_err)?;
      x509_to_tbs(&cert_clone).map_err(to_unknown_err)?
    };
    let issuer_key_hash = {
      let k = issuer.public_key()
          .map_err(|e| Error::BadCertificate(format!("Can't parse public key from issuer: {}", e)))?
          .public_key_to_der().map_err(to_unknown_err)?;
      sha256(&k)
    };
    let mut scts = Vec::with_capacity(sctlist.len());
    for raw_sct in sctlist.into_iter() {
      if raw_sct.version() != Some(SCTVersion::V1) {
        return Err(Error::BadCertificate("Invalid SCT version.".to_owned()));
      }
      scts.push(SignedCertificateTimestamp {
        log_id: raw_sct.log_id().try_into().map_err(|_| Error::BadCertificate("Expected log_id to have len 32".to_owned()))?,
        timestamp: raw_sct.timestamp(),
        extensions_data: raw_sct.extensions().to_vec(),
        entry: SctEntry::PreCert { tbs: tbs.clone(), issuer_key_hash: issuer_key_hash.clone() },
        signature_algorithm: raw_sct.signature_algorithm().ok_or_else(|| Error::BadSct("Unknown signature algorithm.".to_owned()))?,
        raw_signature: raw_sct.raw_signature().to_vec()
      });
    }
    Ok(scts)
  }

  /// Derive the corresponding Merkle leaf hash from this SCTs.
  ///
  /// Can be used to check inclusion, for example.
  pub fn derive_leaf_hash(&self) -> [u8; 32] {
    match &self.entry {
      SctEntry::PreCert { tbs, issuer_key_hash } => {
        leaf_hash_constructors::with_precert(&tbs[..], &issuer_key_hash[..], self.timestamp, &self.extensions_data)
      }
      SctEntry::X509(x509) => {
        leaf_hash_constructors::with_x509(&x509, self.timestamp, &self.extensions_data)
      }
    }
  }

  /// Check the signature in this SCT.
  ///
  /// To get the log public key, lookup the log with `self.log_id` by e.g. using [`crate::google_log_list::LogList::find_by_id`].
  pub fn verify(&self, log_public_key: &PKey<openssl::pkey::Public>) -> Result<(), Error> {
    // type CertificateTimestamp struct {
    let mut signed_data: Vec<u8> = Vec::new();
    // 	SCTVersion    Version       `tls:"maxval:255"`
    signed_data.push(0u8);
    // 	SignatureType SignatureType `tls:"maxval:255"`
    signed_data.push(0u8);
    // 	Timestamp     uint64
    signed_data.extend_from_slice(&self.timestamp.to_be_bytes());
    // 	EntryType     LogEntryType   `tls:"maxval:65535"`
    signed_data.extend_from_slice(&match &self.entry {
      SctEntry::X509(_) => 0u16,
      SctEntry::PreCert { tbs: _, issuer_key_hash: _ } => 1u16
    }.to_be_bytes());
    match &self.entry {
      // 	X509Entry     *ASN1Cert      `tls:"selector:EntryType,val:0"`
      SctEntry::X509(cert) => {
        let len = cert.len();
        if len > 1<<24 {
          return Err(Error::BadSct("Certificate too long.".to_owned()));
        }
        signed_data.extend_from_slice(&u32::to_be_bytes(len as u32)[1..4]);
        signed_data.extend_from_slice(cert);
      },
      // 	PrecertEntry  *PreCert       `tls:"selector:EntryType,val:1"`
      SctEntry::PreCert { tbs, issuer_key_hash } => {
        signed_data.extend_from_slice(issuer_key_hash);
        let len = tbs.len();
        if len > 1<<24 {
          return Err(Error::BadSct("TBS certificate too long.".to_owned()));
        }
        signed_data.extend_from_slice(&u32::to_be_bytes(len as u32)[1..4]);
        signed_data.extend_from_slice(tbs);
      }
    }
    // 	Extensions    CTExtensions   `tls:"minlen:0,maxlen:65535"`
    let ext_len = self.extensions_data.len();
    if ext_len > 1<<16 {
      return Err(Error::BadSct("extension data too long.".to_owned()));
    }
    signed_data.extend_from_slice(&u16::to_be_bytes(ext_len as u16));
    signed_data.extend_from_slice(&self.extensions_data);
    // }
    verify_dss_raw(self.signature_algorithm, log_public_key, &self.raw_signature, &signed_data)
  }
}

