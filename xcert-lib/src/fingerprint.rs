//! Certificate fingerprint (digest) computation.

use crate::fields::DigestAlgorithm;
use digest::Digest;

/// Compute the fingerprint of DER-encoded certificate bytes.
///
/// Returns a colon-separated uppercase hex string (e.g., "AB:CD:EF:...").
pub fn compute_fingerprint(der_bytes: &[u8], algorithm: DigestAlgorithm) -> String {
    let hash_bytes: Vec<u8> = match algorithm {
        DigestAlgorithm::Sha256 => sha2::Sha256::digest(der_bytes).to_vec(),
        DigestAlgorithm::Sha384 => sha2::Sha384::digest(der_bytes).to_vec(),
        DigestAlgorithm::Sha512 => sha2::Sha512::digest(der_bytes).to_vec(),
        DigestAlgorithm::Sha1 => sha1::Sha1::digest(der_bytes).to_vec(),
    };

    hash_bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}
