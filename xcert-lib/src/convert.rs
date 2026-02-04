//! PEM <-> DER format conversion.

use crate::XcertError;

/// Convert DER-encoded certificate bytes to a PEM string.
pub fn der_to_pem(der: &[u8]) -> String {
    let encoded = base64_encode_wrapped(der);
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        encoded
    )
}

/// Convert a PEM-encoded certificate to DER bytes.
pub fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>, XcertError> {
    let (_, parsed) = x509_parser::pem::parse_x509_pem(pem)
        .map_err(|e| XcertError::PemError(format!("{}", e)))?;
    Ok(parsed.contents)
}

fn base64_encode_wrapped(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let mut line_len = 0;
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        line_len += 4;
        if line_len >= 64 {
            result.push('\n');
            line_len = 0;
        }
    }
    result
}
