use log::trace;
use openssl::pkey::PKey;

use crate::Error;
use crate::utils;

// https://docs.rs/rustls/0.15.2/src/rustls/msgs/enums.rs.html#720
// We only need to handle these two cases because RFC says so.
pub(crate) const SIGSCHEME_ECDSA_NISTP256_SHA256: u16 = 0x0403;
pub(crate) const SIGSCHEME_RSA_PKCS1_SHA256: u16 = 0x0401;

/// Verifies a TLS digitally-signed struct (see [the TLS
/// RFC](https://tools.ietf.org/html/rfc5246#section-4.7) for more info.)
///
/// This function is only useful to those who want to do some custom CT API
/// calling. [`CTClient`](crate::CTClient) will automatically verify all
/// signature.
///
/// # Params
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

  let signature_algorithm = match sig_type {
    SIGSCHEME_ECDSA_NISTP256_SHA256 => SignatureAlgorithm::Sha256Ecdsa,
    SIGSCHEME_RSA_PKCS1_SHA256 => SignatureAlgorithm::Sha256Rsa,
    _ => {
      return Err(Error::InvalidSignature(format!("Unknow signature scheme {:2x}", sig_type)));
    }
  };

  verify_dss_raw(signature_algorithm, pub_key, rest, data)
}

use crate::internal::openssl_ffi::SignatureAlgorithm;

/// Verifies a raw, ASN.1 encoded signature.
pub fn verify_dss_raw(signature_algorithm: SignatureAlgorithm, pub_key: &PKey<openssl::pkey::Public>, raw_signature: &[u8], data: &[u8]) -> Result<(), Error> {
  use SignatureAlgorithm::*;
  match signature_algorithm {
    Sha256Ecdsa => {
      if pub_key.id() != openssl::pkey::Id::EC {
        return Err(Error::InvalidSignature(format!("dss says signature is EC, but key is {:?}", pub_key.id())));
      }
    }
    Sha256Rsa => {
      if pub_key.id() != openssl::pkey::Id::RSA {
        return Err(Error::InvalidSignature(format!("dss says signature is RSA, but key is {:?}", pub_key.id())));
      }
    }
  }

  let mut verifier = openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), pub_key).map_err(|e| Error::Unknown(format!("EVP_DigestVerifyInit: {}", &e)))?;
  if signature_algorithm == Sha256Rsa {
    verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1).map_err(|e| Error::Unknown(format!("EVP_PKEY_CTX_set_rsa_padding: {}", &e)))?;
  }
  verifier.update(data).map_err(|e| Error::Unknown(format!("EVP_DigestUpdate: {}", &e)))?;
  if !verifier.verify(raw_signature).map_err(|e| Error::InvalidSignature(format!("EVP_DigestVerifyFinal: {}", &e)))? {
    return Err(Error::InvalidSignature(format!("Signature is invalid: signature = {}, data = {}.", &utils::u8_to_hex(raw_signature), &utils::u8_to_hex(data))));
  }

  debug_assert!({
    trace!("Signature checked for data {}", &utils::u8_to_hex(data));
    true
  });

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
