//! Human-readable and JSON formatting of certificate information.

use crate::fields::CertificateInfo;
use crate::XcertError;

/// Format certificate information as human-readable text.
///
/// If `show_all` is true, includes signature bytes and full public key details.
pub fn display_text(cert: &CertificateInfo, show_all: bool) -> String {
    let _ = (cert, show_all);
    String::new() // stub
}

/// Serialize certificate information to a JSON string.
pub fn to_json(cert: &CertificateInfo) -> Result<String, XcertError> {
    let _ = cert;
    Err(XcertError::Unsupported("not yet implemented".into()))
}
