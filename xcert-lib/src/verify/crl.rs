//! CRL-based certificate revocation checking.
//!
//! Provides functionality for parsing Certificate Revocation Lists (CRLs)
//! and checking whether certificates have been revoked.

use crate::XcertError;
use x509_parser::prelude::*;

/// Parse a PEM-encoded CRL file into DER-encoded CRL data.
pub fn parse_pem_crl(input: &[u8]) -> Result<Vec<Vec<u8>>, XcertError> {
    let mut crls = Vec::new();
    for pem_result in Pem::iter_from_buffer(input) {
        match pem_result {
            Ok(pem) => {
                if pem.label == "X509 CRL" {
                    crls.push(pem.contents);
                }
            }
            Err(e) => {
                if !crls.is_empty() {
                    break;
                }
                return Err(XcertError::PemError(format!(
                    "failed to parse CRL PEM: {}",
                    e
                )));
            }
        }
    }
    if crls.is_empty() {
        return Err(XcertError::PemError("no CRLs found in PEM input".into()));
    }
    Ok(crls)
}

/// Format a CRL revocation reason code as an RFC 5280-style string.
///
/// Matches on the underlying numeric value of the `ReasonCode` newtype
/// (which wraps a `u8`), per RFC 5280 Section 5.3.1.
pub(crate) fn format_crl_reason(rc: &x509_parser::x509::ReasonCode) -> &'static str {
    match rc.0 {
        0 => "unspecified",
        1 => "keyCompromise",
        2 => "cACompromise",
        3 => "affiliationChanged",
        4 => "superseded",
        5 => "cessationOfOperation",
        6 => "certificateHold",
        // 7 is unused per RFC 5280
        8 => "removeFromCRL",
        9 => "privilegeWithdrawn",
        10 => "aACompromise",
        _ => "unspecified",
    }
}

/// Check whether a certificate has been revoked according to the given CRLs.
///
/// `cert` is the parsed certificate to check.
/// `crl_ders` is a slice of DER-encoded CRL data.
/// `issuer_cert` is the issuer's certificate (used to verify the CRL signature).
/// `now_ts` is the current Unix timestamp for CRL validity checking.
///
/// Returns `Some(reason)` if revoked, `None` if not revoked.
pub fn check_crl_revocation(
    cert: &X509Certificate,
    crl_ders: &[Vec<u8>],
    issuer_cert: Option<&X509Certificate>,
    now_ts: i64,
) -> Option<String> {
    let serial = cert.raw_serial();

    for crl_der in crl_ders {
        let parsed = x509_parser::revocation_list::CertificateRevocationList::from_der(crl_der);
        let (_, crl) = match parsed {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Verify CRL is from the right issuer
        if crl.issuer() != cert.issuer() {
            continue;
        }

        // RFC 5280 Section 6.3.3: Check CRL validity dates
        let this_update = crl.last_update().timestamp();
        if now_ts < this_update {
            continue; // CRL is not yet valid
        }
        if let Some(next_update) = crl.next_update() {
            if now_ts > next_update.timestamp() {
                continue; // CRL has expired
            }
        }

        // Verify CRL signature against the issuer's public key
        if let Some(issuer) = issuer_cert {
            if crl.verify_signature(issuer.public_key()).is_err() {
                continue;
            }
        }

        // Check if the certificate's serial number is in the revoked list
        for revoked in crl.iter_revoked_certificates() {
            if revoked.raw_serial() == serial {
                let reason = revoked
                    .reason_code()
                    .map(|rc| format_crl_reason(&rc.1))
                    .unwrap_or("unspecified");
                return Some(reason.to_string());
            }
        }
    }

    None
}
