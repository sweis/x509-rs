//! Certificate parsing from PEM and DER formats.

use crate::fields::CertificateInfo;
use crate::XcertError;

/// Parse a certificate from PEM or DER (auto-detected).
///
/// If the input begins with `-----BEGIN` (after stripping whitespace), it is
/// treated as PEM. Otherwise it is treated as DER.
pub fn parse_cert(input: &[u8]) -> Result<CertificateInfo, XcertError> {
    let trimmed = input
        .iter()
        .skip_while(|b| b.is_ascii_whitespace())
        .take(11)
        .copied()
        .collect::<Vec<_>>();

    if trimmed.starts_with(b"-----BEGIN") {
        parse_pem(input)
    } else {
        parse_der(input)
    }
}

/// Parse a certificate from PEM format.
pub fn parse_pem(input: &[u8]) -> Result<CertificateInfo, XcertError> {
    let _ = input;
    Err(XcertError::ParseError("not yet implemented".into()))
}

/// Parse a certificate from DER format.
pub fn parse_der(input: &[u8]) -> Result<CertificateInfo, XcertError> {
    let _ = input;
    Err(XcertError::ParseError("not yet implemented".into()))
}
