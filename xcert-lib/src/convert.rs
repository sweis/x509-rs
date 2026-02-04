//! PEM <-> DER format conversion.

use crate::XcertError;
use base64::Engine;

/// Convert DER-encoded certificate bytes to a PEM string.
pub fn der_to_pem(der: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let wrapped = encoded
        .as_bytes()
        .chunks(64)
        .filter_map(|c| std::str::from_utf8(c).ok())
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        wrapped
    )
}

/// Convert a PEM-encoded certificate to DER bytes.
pub fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>, XcertError> {
    let (_, parsed) = x509_parser::pem::parse_x509_pem(pem)
        .map_err(|e| XcertError::PemError(format!("{}", e)))?;
    Ok(parsed.contents)
}
