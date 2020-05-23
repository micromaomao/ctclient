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

fn x509_get_sct_data<'a>(cert: &'a X509Ref) -> Result<Option<&'a [u8]>, ErrorStack> {
  unsafe {
    let extpos = X509_get_ext_by_OBJ(cert.as_ptr(), SCT_LIST_ASN1_OBJECT.0, -1);
    if extpos == -1 {
      return Ok(None);
    }
    let ext = X509_get_ext(cert.as_ptr(), extpos);
    if ext.is_null() {
      return Err(ErrorStack::get());
    }
    // ASN1_OCTET_STRING is the same as ASN1_STRING: https://www.openssl.org/docs/man1.1.1/man3/ASN1_STRING_get0_data.html#NOTES
    let extdata: *mut openssl_sys::ASN1_STRING = X509_EXTENSION_get_data(ext) as *mut _;
    let data_len = usize::try_from(openssl_sys::ASN1_STRING_length(extdata)).unwrap();
    let data_ptr = openssl_sys::ASN1_STRING_get0_data(extdata);
    assert!(!data_ptr.is_null());
    let data: &'a [u8] = &*std::ptr::slice_from_raw_parts(data_ptr, data_len);
    Ok(Some(data))
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
  let data = x509_get_sct_data(cert.as_ref()).map_err(|e| crate::Error::BadCertificate(format!("{}", e)))?;
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

