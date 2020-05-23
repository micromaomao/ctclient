use openssl::pkey::PKey;
use crate::Error;
use openssl::x509::X509Ref;
use crate::internal::openssl_ffi::{sct_list_from_x509, x509_clone, x509_remove_sct_list, x509_to_tbs};
use std::convert::TryInto;
use openssl::sha::sha256;

#[derive(Debug, Clone)]
pub struct SignedCertificateTimestamp {
  pub log_id: [u8; 32],
  pub timestamp: u64,
  pub extensions_data: Vec<u8>,
  pub entry: SCTInner,
  pub signature: Vec<u8>
}

#[derive(Debug, Clone)]
pub enum SCTInner {
  X509(Vec<u8>),
  PreCert { tbs: Vec<u8>, issuer_key_hash: [u8; 32] }
}

impl SignedCertificateTimestamp {
  pub fn verify(&self, log_public_key: PKey<openssl::pkey::Public>) -> Result<(), Error> {
    unimplemented!()
  }
}

fn to_unknown_err(openssl_err: openssl::error::ErrorStack) -> Error {
  Error::Unknown(format!("{}", openssl_err))
}

pub fn parse_certificate_sct_list(cert: &X509Ref, issuer: &X509Ref) -> Result<Vec<SignedCertificateTimestamp>, Error> {
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
    scts.push(SignedCertificateTimestamp {
      log_id: raw_sct.log_id().try_into().map_err(|_| Error::BadCertificate("Expected log_id to have len 32".to_owned()))?,
      timestamp: raw_sct.timestamp(),
      extensions_data: raw_sct.extensions().to_vec(),
      entry: SCTInner::PreCert { tbs: tbs.clone(), issuer_key_hash: issuer_key_hash.clone() },
      signature: raw_sct.signature().to_vec()
    });
  }
  Ok(scts)
}
