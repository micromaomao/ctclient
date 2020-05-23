//! Because `openssl` crate is incomplete.

use std::convert::TryFrom;
use std::ptr::null_mut;

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::error::ErrorStack;
use openssl::stack::{Stack, Stackable};
use openssl::x509::X509Ref;
use openssl_sys::ASN1_OBJECT;

use foreign::*;

/// Because `openssl_sys` crate is incomplete.
#[allow(non_camel_case_types)]
pub mod foreign {
  pub enum SCT_LIST {}
  pub enum SCT {}

  pub type sct_version_t = i32;
  pub const SCT_VERSION_NOT_SET: sct_version_t = -1;
  pub const SCT_VERSION_V1: sct_version_t = 0;

  extern "C" {
    pub fn i2d_re_X509_tbs(
      x: *mut openssl_sys::X509,
      pp: *mut *mut std::os::raw::c_uchar,
    ) -> std::os::raw::c_int;

    pub fn X509_get_ext_by_OBJ(
      x: *const openssl_sys::X509,
      obj: *const openssl_sys::ASN1_OBJECT,
      lastpos: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;

    pub fn X509_get_ext(x: *const openssl_sys::X509, loc: ::std::os::raw::c_int) -> *mut openssl_sys::X509_EXTENSION;
    pub fn X509_delete_ext(x: *mut openssl_sys::X509, loc: ::std::os::raw::c_int) -> *mut openssl_sys::X509_EXTENSION;

    pub fn OBJ_txt2obj(
      s: *const ::std::os::raw::c_char,
      no_name: ::std::os::raw::c_int,
    ) -> *mut openssl_sys::ASN1_OBJECT;

    pub fn ASN1_OBJECT_free(a: *mut openssl_sys::ASN1_OBJECT);

    pub fn X509_EXTENSION_free(a: *mut openssl_sys::X509_EXTENSION);

    pub fn X509_dup(x509: *mut openssl_sys::X509) -> *mut openssl_sys::X509;

    pub fn X509_EXTENSION_get_data(ne: *mut openssl_sys::X509_EXTENSION) -> *mut openssl_sys::ASN1_OCTET_STRING;
    pub fn X509_EXTENSION_set_data(
      ex: *mut openssl_sys::X509_EXTENSION,
      data: *mut openssl_sys::ASN1_OCTET_STRING,
    ) -> ::std::os::raw::c_int;


    pub fn d2i_SCT_LIST(
      a: *mut *mut SCT_LIST,
      pp: *mut *const ::std::os::raw::c_uchar,
      len: ::std::os::raw::c_long,
    ) -> *mut SCT_LIST;

    pub fn SCT_LIST_free(a: *mut SCT_LIST);

    pub fn SCT_get_version(sct: *const SCT) -> sct_version_t;
    pub fn SCT_get0_log_id(sct: *const SCT, log_id: *mut *mut ::std::os::raw::c_uchar) -> ::std::os::raw::c_ulong;
    pub fn SCT_get_timestamp(sct: *const SCT) -> u64;
    pub fn SCT_get0_extensions(sct: *const SCT, ext: *mut *mut ::std::os::raw::c_uchar) -> ::std::os::raw::c_ulong;
    pub fn SCT_get_signature_nid(sct: *const SCT) -> ::std::os::raw::c_int;
    pub fn SCT_get0_signature(sct: *const SCT, sig: *mut *mut ::std::os::raw::c_uchar) -> ::std::os::raw::c_ulong;
    pub fn SCT_free(sct: *mut SCT);

    pub fn X509_set_issuer_name(x: *mut openssl_sys::X509, name: *mut openssl_sys::X509_NAME) -> ::std::os::raw::c_int;
    pub fn X509_get_subject_name(a: *const openssl_sys::X509) -> *mut openssl_sys::X509_NAME;

    pub fn ASN1_STRING_new() -> *mut openssl_sys::ASN1_STRING;
    pub fn ASN1_STRING_set(
      str: *mut openssl_sys::ASN1_STRING,
      data: *const ::std::os::raw::c_void,
      len: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
  }
}

foreign_types::foreign_type! {
  type CType = foreign::SCT;
  fn drop = foreign::SCT_free;
  /// An owned reference to a openssl `SCT` struct.
  pub struct Sct;
  /// A reference to a openssl `SCT` struct.
  pub struct SctRef;
}

impl Stackable for Sct {
  type StackType = foreign::SCT_LIST;
}

/// An owned `STACK_OF(SCT)`.
pub type SctList = Stack<Sct>;

pub fn x509_clone<R: AsRef<X509Ref>>(src: &R) -> Result<openssl::x509::X509, ErrorStack> {
  unsafe {
    let cloned_ptr = X509_dup(src.as_ref().as_ptr());
    if cloned_ptr.is_null() {
      return Err(ErrorStack::get());
    }
    Ok(openssl::x509::X509::from_ptr(cloned_ptr))
  }
}

struct WrappedObjPointer(*mut ASN1_OBJECT);

unsafe impl Sync for WrappedObjPointer {}

impl Drop for WrappedObjPointer {
  fn drop(&mut self) {
    let ptr = self.0;
    unsafe {
      ASN1_OBJECT_free(ptr);
    }
  }
}

unsafe fn oid_to_obj(zero_terminated_oid: &'static str) -> WrappedObjPointer {
  let ptr = OBJ_txt2obj(zero_terminated_oid.as_ptr() as *const _, 1);
  if ptr.is_null() {
    panic!("OBJ_txt2obj failed.");
  }
  WrappedObjPointer(ptr)
}

lazy_static! {
  static ref POISON_ASN1_OBJECT: WrappedObjPointer = unsafe { oid_to_obj("1.3.6.1.4.1.11129.2.4.3\0") };
  static ref SCT_LIST_ASN1_OBJECT: WrappedObjPointer = unsafe { oid_to_obj("1.3.6.1.4.1.11129.2.4.2\0") };
  static ref AUTHORITY_KEY_IDENTIFIER: WrappedObjPointer = unsafe { oid_to_obj("2.5.29.35\0") };
  static ref SUBJECT_KEY_IDENTIFIER: WrappedObjPointer = unsafe { oid_to_obj("2.5.29.14\0") };
}

unsafe fn x509_remove_extension_by_obj(cert: &mut openssl::x509::X509, obj: *const ASN1_OBJECT) -> Result<(), ErrorStack> {
  let extpos = X509_get_ext_by_OBJ(cert.as_ptr(), obj, -1);
  if extpos == -1 {
    return Ok(());
  }
  let ext = X509_delete_ext(cert.as_ptr(), extpos);
  if ext.is_null() {
    Err(ErrorStack::get())
  } else {
    X509_EXTENSION_free(ext);
    Ok(())
  }
}

pub fn x509_remove_poison(cert: &mut openssl::x509::X509) -> Result<(), ErrorStack> {
  unsafe {
    x509_remove_extension_by_obj(cert, POISON_ASN1_OBJECT.0)
  }
}

pub fn x509_remove_sct_list(cert: &mut openssl::x509::X509) -> Result<(), openssl::error::ErrorStack> {
  unsafe {
    x509_remove_extension_by_obj(cert, SCT_LIST_ASN1_OBJECT.0)
  }
}

unsafe fn asn1_string_to_bytes<'a>(asn1_str: *mut openssl_sys::ASN1_STRING) -> &'a [u8] {
  let data_len = usize::try_from(openssl_sys::ASN1_STRING_length(asn1_str)).unwrap();
  let data_ptr = openssl_sys::ASN1_STRING_get0_data(asn1_str);
  assert!(!data_ptr.is_null());
  &*std::ptr::slice_from_raw_parts(data_ptr, data_len)
}

fn bytes_to_asn1_string(bytes: &[u8]) -> openssl::asn1::Asn1String {
  unsafe {
    let asn1 = openssl::asn1::Asn1String::from_ptr(ASN1_STRING_new());
    ASN1_STRING_set(asn1.as_ptr(), bytes.as_ptr() as *const _, bytes.len() as _);
    asn1
  }
}

fn x509_get_ext_data<'a>(cert: &'a X509Ref, ext: &WrappedObjPointer) -> Result<Option<&'a [u8]>, ErrorStack> {
  unsafe {
    let extpos = X509_get_ext_by_OBJ(cert.as_ptr(), ext.0, -1);
    if extpos == -1 {
      return Ok(None);
    }
    let ext = X509_get_ext(cert.as_ptr(), extpos);
    if ext.is_null() {
      return Err(ErrorStack::get());
    }
    // ASN1_OCTET_STRING is the same as ASN1_STRING: https://www.openssl.org/docs/man1.1.1/man3/ASN1_STRING_get0_data.html#NOTES
    Ok(Some(asn1_string_to_bytes(
      X509_EXTENSION_get_data(ext) as *mut _
    )))
  }
}

fn x509_set_ext_data(cert: &mut openssl::x509::X509, ext: &WrappedObjPointer, data: &[u8]) -> Result<(), crate::Error> {
  unsafe {
    use crate::Error;
    let extpos = X509_get_ext_by_OBJ(cert.as_ptr(), ext.0, -1);
    if extpos == -1 {
      return Err(Error::Unknown("x509_set_ext_data: no such extension".to_owned()));
    }
    let ext = X509_get_ext(cert.as_ptr(), extpos);
    if ext.is_null() {
      return Err(Error::Unknown(ErrorStack::get().to_string()));
    }
    X509_EXTENSION_set_data(ext, bytes_to_asn1_string(data).as_ptr() as *mut _);
    Ok(())
  }
}

pub fn x509_to_tbs<R: AsRef<X509Ref>>(cert: &R) -> Result<Vec<u8>, ErrorStack> {
  unsafe {
    let mut buf: *mut u8 = null_mut();
    let ret = i2d_re_X509_tbs(cert.as_ref().as_ptr(), &mut buf as *mut _);
    if ret < 0 {
      return Err(ErrorStack::get());
    }
    if buf.is_null() {
      return Ok(Vec::new());
    }
    let size = usize::try_from(ret).unwrap();
    let mut owned_buf = Vec::with_capacity(size);
    std::ptr::copy_nonoverlapping(buf, owned_buf.as_mut_ptr(), size);
    owned_buf.set_len(size);
    openssl_sys::CRYPTO_free(buf as *mut _, "openssl_ffi.rs\0".as_ptr() as *const _, line!() as i32);
    Ok(owned_buf)
  }
}

pub fn sct_list_from_x509<R: AsRef<X509Ref>>(cert: &R) -> Result<Option<SctList>, crate::Error> {
  let data = x509_get_ext_data(cert.as_ref(), &SCT_LIST_ASN1_OBJECT).map_err(|e| crate::Error::BadCertificate(format!("{}", e)))?;
  if data.is_none() {
    return Ok(None);
  }
  let data = data.unwrap();
  if data.is_empty() {
    return Ok(None);
  }
  let mut pp = data.as_ptr();
  unsafe {
    let res = d2i_SCT_LIST(std::ptr::null_mut(), &mut pp as *mut _, i64::try_from(data.len()).unwrap());
    if res.is_null() {
      return Err(crate::Error::BadSct(format!("{}", ErrorStack::get())));
    }
    if pp != data.as_ptr().add(data.len()) {
      return Err(crate::Error::BadSct("SCT extension data not fully consumed.".to_owned()));
    }
    Ok(Some(SctList::from_ptr(res)))
  }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum SCTVersion {
  V1
}
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
pub enum SignatureAlgorithm {
  Sha256Rsa,
  Sha256Ecdsa
}

macro_rules! impl_get_data_fn {
  ($fnname:ident, $fn:expr) => {
    pub fn $fnname<'a>(&'a self) -> &'a [u8] {
      unsafe {
        let mut ptr: *mut u8 = std::ptr::null_mut();
        let size = $fn(self.as_ptr(), &mut ptr as *mut _);
        &*std::ptr::slice_from_raw_parts(ptr, size as usize)
      }
    }
  };
}

impl SctRef {
  pub fn version(&self) -> Option<SCTVersion> {
    let raw_version = unsafe {SCT_get_version(self.as_ptr())};
    match raw_version {
      SCT_VERSION_V1 => Some(SCTVersion::V1),
      _ => None
    }
  }

  impl_get_data_fn!(log_id, SCT_get0_log_id);

  pub fn timestamp(&self) -> u64 {
    unsafe {
      SCT_get_timestamp(self.as_ptr())
    }
  }

  impl_get_data_fn!(extensions, SCT_get0_extensions);

  pub fn signature_algorithm(&self) -> Option<SignatureAlgorithm> {
    let nid = unsafe { SCT_get_signature_nid(self.as_ptr()) };
    match nid {
      668 => Some(SignatureAlgorithm::Sha256Rsa),
      794 => Some(SignatureAlgorithm::Sha256Ecdsa),
      _ => None
    }
  }

  impl_get_data_fn!(raw_signature, SCT_get0_signature);
}

/// Set the issuer name of `dst` to be the subject name of `src`, and also set the authorityKeyIdentifier of a to the
/// subjectKeyIdentifier of b.
pub fn x509_make_a_looks_like_issued_by_b(a: &mut openssl::x509::X509, b: &openssl::x509::X509Ref) -> Result<(), crate::Error> {
  use crate::Error;
  let subj_name = unsafe { X509_get_subject_name(b.as_ptr()) };
  // subj_name is an internal pointer to data in src.
  let ret = unsafe { X509_set_issuer_name(a.as_ptr(), subj_name) };
  // X509_set_issuer_name copies the data pointed to by subj_name.
  if ret != 1 {
    Err(Error::Unknown(ErrorStack::get().to_string()))
  } else {
    let subj_auth_keyid = x509_get_ext_data(b, &SUBJECT_KEY_IDENTIFIER)
        .map_err(|e| Error::Unknown(e.to_string()))?
        .ok_or_else(|| Error::Unknown("x509_get_ext_data returned None".to_owned()))?;
    if subj_auth_keyid.len() < 2 || subj_auth_keyid.len() > (1<<8) - 1 {
      return Err(Error::BadCertificate("Bad subjectKeyIdentifier".to_owned()));
    }
    let key = &subj_auth_keyid[2..];
    if &subj_auth_keyid[0..2] != &[0x04, key.len() as u8] {
      return Err(Error::BadCertificate("Bad subjectKeyIdentifier".to_owned()));
    }
    let mut auth_data = vec![0x30, (key.len() + 2) as u8, 0x80, key.len() as u8];
    auth_data.extend_from_slice(&key);
    x509_set_ext_data(a, &AUTHORITY_KEY_IDENTIFIER, &auth_data)?;
    Ok(())
  }
}
