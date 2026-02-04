//! PEM <-> DER format conversion.

use crate::util;
use crate::XcertError;

/// Convert DER-encoded certificate bytes to a PEM string.
pub fn der_to_pem(der: &[u8]) -> String {
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        util::base64_wrap(der)
    )
}

/// Convert a PEM-encoded certificate to DER bytes.
pub fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>, XcertError> {
    let (_, parsed) = x509_parser::pem::parse_x509_pem(pem)
        .map_err(|e| XcertError::PemError(format!("{}", e)))?;
    Ok(parsed.contents)
}
