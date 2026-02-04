//! PEM <-> DER format conversion.

use crate::XcertError;

/// Convert DER-encoded certificate bytes to a PEM string.
pub fn der_to_pem(der: &[u8]) -> String {
    let _ = der;
    String::new() // stub
}

/// Convert a PEM-encoded certificate to DER bytes.
pub fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>, XcertError> {
    let _ = pem;
    Err(XcertError::PemError("not yet implemented".into()))
}
