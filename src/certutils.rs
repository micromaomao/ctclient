//! Verious utilities for checking the content of a certificate.

use openssl::x509::X509Ref;
use crate::Error;

/// Return the common name of the certificate. Usually will only contains one. May be empty.
pub fn get_common_names<R: AsRef<X509Ref>>(cert: &R) -> Result<Vec<String>, Error> {
  let cert = cert.as_ref();
  let try_common_names: Vec<_> = cert.subject_name().entries_by_nid(openssl::nid::Nid::COMMONNAME)
      .map(|x| x.data().as_utf8()).collect();
  let mut common_names: Vec<String> = Vec::with_capacity(try_common_names.len());
  for cn in try_common_names {
    if let Err(e) = cn {
      return Err(Error::BadCertificate(format!("While parsing common name: {}", &e)));
    }
    common_names.push(String::from(AsRef::<str>::as_ref(&cn.unwrap())));
  }
  Ok(common_names)
}

/// Return the DNS names in the subjectAlternativeNames of the certificate as well as its common name.
///
/// Result may contain duplicate items.
pub fn get_dns_names<R: AsRef<X509Ref>>(cert: &R) -> Result<Vec<String>, Error> {
  let cert = cert.as_ref();
  let mut names = get_common_names(cert)?;
  // fixme: common names may not be host names.
  if let Some(san) = cert.subject_alt_names() {
    for name in san.iter() {
      if let Some(name) = name.dnsname() {
        names.push(String::from(name));
      } else if let Some(uri) = name.uri() {
        let url_parsed = reqwest::Url::parse(uri).map_err(|_| Error::BadCertificate("This certificate has a URI SNI, but the URI is not parsable.".to_owned()))?;
        if let Some(host) = url_parsed.domain() {
          names.push(String::from(host));
        }
      }
    }
  }
  Ok(names)
}
