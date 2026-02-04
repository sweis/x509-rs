//! Certificate fingerprint (digest) computation.

use crate::fields::DigestAlgorithm;

/// Compute the fingerprint of DER-encoded certificate bytes.
///
/// Returns a colon-separated hex string (e.g., "AB:CD:EF:...").
pub fn compute_fingerprint(der_bytes: &[u8], algorithm: DigestAlgorithm) -> String {
    let _ = (der_bytes, algorithm);
    String::new() // stub
}
