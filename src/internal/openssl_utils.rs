use std::convert::TryFrom;
use std::ptr::null_mut;

use foreign_types_shared::ForeignTypeRef;
use openssl::x509::X509Ref;
use openssl_sys::ASN1_OBJECT;

extern "C" {
  fn i2d_re_X509_tbs(
    x: *mut openssl_sys::X509,
    pp: *mut *mut std::os::raw::c_uchar,
  ) -> std::os::raw::c_int;

  fn X509_get_ext_by_OBJ(
    x: *const openssl_sys::X509,
    obj: *const openssl_sys::ASN1_OBJECT,
    lastpos: ::std::os::raw::c_int,
  ) -> ::std::os::raw::c_int;

  pub fn X509_delete_ext(x: *mut openssl_sys::X509, loc: ::std::os::raw::c_int) -> *mut openssl_sys::X509_EXTENSION;

  fn OBJ_txt2obj(
    s: *const ::std::os::raw::c_char,
    no_name: ::std::os::raw::c_int,
  ) -> *mut openssl_sys::ASN1_OBJECT;

  fn ASN1_OBJECT_free(a: *mut openssl_sys::ASN1_OBJECT);

  fn X509_EXTENSION_free(a: *mut openssl_sys::X509_EXTENSION);
}

struct WrappedObjPointer (*mut ASN1_OBJECT);
unsafe impl Sync for WrappedObjPointer {}
impl Drop for WrappedObjPointer {
  fn drop(&mut self) {
    let ptr = self.0;
    unsafe {
      ASN1_OBJECT_free(ptr);
    }
  }
}

lazy_static! {
  static ref POISON_ASN1_OBJECT: WrappedObjPointer = unsafe {
    let ptr = OBJ_txt2obj("1.3.6.1.4.1.11129.2.4.3\0".as_ptr() as *const _, 1);
    if ptr.is_null() {
      panic!("OBJ_txt2obj failed.");
    }
    WrappedObjPointer(ptr)
  };
}

pub fn x509_remove_poison(cert: &mut openssl::x509::X509) -> Result<(), openssl::error::ErrorStack> {
  let poison_obj: *const ASN1_OBJECT = (*POISON_ASN1_OBJECT).0;
  unsafe {
    let extpos = X509_get_ext_by_OBJ(cert.as_ptr(), poison_obj, -1);
    if extpos == -1 {
      return Ok(());
    }
    let ext = X509_delete_ext(cert.as_ptr(), extpos);
    if ext.is_null() {
      Err(openssl::error::ErrorStack::get())
    } else {
      X509_EXTENSION_free(ext);
      Ok(())
    }
  }
}

pub fn x509_to_tbs<R: AsRef<X509Ref>>(cert: &R) -> Result<Vec<u8>, openssl::error::ErrorStack> {
  unsafe {
    let mut buf: *mut u8 = null_mut();
    let ret = i2d_re_X509_tbs(cert.as_ref().as_ptr(), &mut buf as *mut _);
    if ret < 0 {
      return Err(openssl::error::ErrorStack::get());
    }
    if buf.is_null() {
      return Ok(Vec::new());
    }
    let size = usize::try_from(ret).unwrap();
    let mut owned_buf = Vec::with_capacity(size);
    std::ptr::copy_nonoverlapping(buf, owned_buf.as_mut_ptr(), size);
    owned_buf.set_len(size);
    openssl_sys::CRYPTO_free(buf as *mut _, "openssl_utils.rs\0".as_ptr() as *const _, line!() as i32);
    Ok(owned_buf)
  }
}
