//! Certificate chain verification against a trust store.
//!
//! Provides functionality to verify X.509 certificate chains by checking
//! signatures, validity dates, basic constraints, and trust anchoring
//! against the system's trusted CA certificates (the same store used by OpenSSL).
//!
//! The system trust store location is discovered via `openssl-probe` and
//! environment variables, matching OpenSSL's lookup behavior.

mod chain;
mod checks;
mod constraints;
pub mod crl;
mod helpers;
mod trust_store;
mod webpki;

use crate::oid;
use crate::XcertError;
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_parser::prelude::*;

// Re-export chain building constants
use chain::build_chain_dfs;
pub(crate) use chain::MAX_CHAIN_DEPTH;

// Re-export check functions
use checks::{
    check_chain_basic_constraints, check_chain_critical_extensions,
    check_chain_duplicate_extensions, check_chain_key_cert_sign,
    check_chain_name_constraint_placement, check_chain_name_constraints,
    check_chain_rfc5280_strict, check_chain_signatures, check_chain_time_validity, check_crl_chain,
    check_crl_strict, check_leaf_email, check_leaf_hostname, check_leaf_ip, check_leaf_purpose,
    check_trusted_root, verify_trust_anchoring,
};

// Re-export CRL functions
pub use crl::check_crl_revocation;
pub use crl::parse_pem_crl;

// Re-export trust store
pub use trust_store::{find_system_ca_bundle, TrustStore};

// Re-export helpers that need to be used by is_self_issued check
use helpers::is_self_issued;

// Re-export webpki check
use webpki::check_webpki_policy;

/// Result of certificate chain verification.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationResult {
    /// Whether the entire chain verified successfully.
    pub is_valid: bool,
    /// Information about each certificate in the verified chain (leaf to root).
    pub chain: Vec<ChainCertInfo>,
    /// List of verification errors encountered (empty if `is_valid` is true).
    pub errors: Vec<String>,
}

impl std::fmt::Display for VerificationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_valid {
            write!(f, "OK")?;
            if !self.chain.is_empty() {
                write!(f, " (chain: ")?;
                for (i, info) in self.chain.iter().enumerate() {
                    if i > 0 {
                        write!(f, " -> ")?;
                    }
                    write!(f, "{}", info.subject)?;
                }
                write!(f, ")")?;
            }
        } else {
            write!(f, "FAIL")?;
            for err in &self.errors {
                write!(f, ": {}", err)?;
            }
        }
        Ok(())
    }
}

/// Information about a certificate in the verified chain.
#[derive(Debug, Clone, Serialize)]
pub struct ChainCertInfo {
    /// Position in chain (0 = leaf).
    pub depth: usize,
    /// Subject distinguished name.
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
}

/// Verification policy that controls which validation rules are applied.
///
/// RFC 5280 mode enforces base X.509 rules. WebPKI mode additionally checks
/// CABF Baseline Requirements for TLS server certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VerifyPolicy {
    /// Standard RFC 5280 certificate path validation.
    #[default]
    Rfc5280,
    /// WebPKI / CABF Baseline Requirements mode (stricter).
    WebPki,
}

/// Options controlling verification behavior.
pub struct VerifyOptions {
    /// Whether to check certificate validity dates.
    /// Set to `false` to skip time checks (useful for testing expired certs).
    pub check_time: bool,
    /// Allow verification to succeed if any certificate in the chain (not just
    /// the root) is in the trust store. Matches OpenSSL's `-partial_chain` flag.
    pub partial_chain: bool,
    /// Required Extended Key Usage OID for the leaf certificate (e.g.,
    /// "1.3.6.1.5.5.7.3.1" for serverAuth). If set, verification fails when
    /// the leaf's EKU extension is present but does not include this OID.
    pub purpose: Option<String>,
    /// Verify at a specific Unix timestamp instead of the current time.
    /// Matches OpenSSL's `-attime` flag.
    pub at_time: Option<i64>,
    /// Maximum chain depth. Defaults to 32.
    pub verify_depth: Option<usize>,
    /// Email to verify against the leaf certificate's SAN/subject.
    pub verify_email: Option<String>,
    /// IP address to verify against the leaf certificate's SAN.
    pub verify_ip: Option<String>,
    /// DER-encoded CRLs to check for revocation.
    pub crl_ders: Vec<Vec<u8>>,
    /// Check CRL for the leaf certificate only (`crl_check`).
    pub crl_check_leaf: bool,
    /// Check CRL for all certificates in the chain (`crl_check_all`).
    pub crl_check_all: bool,
    /// Verification policy (RFC 5280 or WebPKI). Default: RFC 5280.
    pub policy: VerifyPolicy,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            check_time: true,
            partial_chain: false,
            purpose: None,
            at_time: None,
            verify_depth: None,
            verify_email: None,
            verify_ip: None,
            crl_ders: Vec::new(),
            crl_check_leaf: false,
            crl_check_all: false,
            policy: VerifyPolicy::default(),
        }
    }
}

/// Resolve a named purpose string to its EKU OID.
///
/// Matches OpenSSL's `-purpose` named values.
pub fn resolve_purpose(name: &str) -> Option<&'static str> {
    match name {
        "sslserver" => Some(oid::EKU_SERVER_AUTH),
        "sslclient" => Some(oid::EKU_CLIENT_AUTH),
        "smimesign" | "smimeencrypt" => Some(oid::EKU_EMAIL_PROTECTION),
        "codesign" => Some(oid::EKU_CODE_SIGNING),
        "timestampsign" => Some(oid::EKU_TIME_STAMPING),
        "ocsphelper" => Some(oid::EKU_OCSP_SIGNING),
        "any" => Some(oid::EKU_ANY),
        _ => None,
    }
}

/// Parse a PEM-encoded file containing one or more certificates into
/// individual DER-encoded certificates.
pub fn parse_pem_chain(input: &[u8]) -> Result<Vec<Vec<u8>>, XcertError> {
    let mut certs = Vec::new();

    // Use x509-parser's PEM iterator for robust multi-cert parsing
    for pem_result in Pem::iter_from_buffer(input) {
        match pem_result {
            Ok(pem) => {
                if pem.label == "CERTIFICATE" || pem.label == "TRUSTED CERTIFICATE" {
                    certs.push(pem.contents);
                }
            }
            Err(e) => {
                // If we already have some certs, stop at first error (trailing garbage)
                if !certs.is_empty() {
                    break;
                }
                return Err(XcertError::PemError(format!("failed to parse PEM: {}", e)));
            }
        }
    }

    if certs.is_empty() {
        return Err(XcertError::PemError(
            "no certificates found in PEM input".into(),
        ));
    }

    Ok(certs)
}

/// Check whether a list of DER-encoded certificates appears to form a chain
/// (each cert's issuer matches the next cert's subject) rather than an
/// unrelated bundle of independent certificates (e.g. a CA bundle).
///
/// Returns `true` if the certificates form a chain (or there's 0-1 certs).
/// Returns `false` if consecutive certificates lack issuer-subject linkage.
pub fn is_certificate_chain(certs_der: &[Vec<u8>]) -> bool {
    if certs_der.len() <= 1 {
        return true;
    }

    // Check if cert[0]'s issuer matches cert[1]'s subject
    let cert0 = match certs_der
        .first()
        .and_then(|der| X509Certificate::from_der(der).ok())
    {
        Some((_, cert)) => cert,
        None => return true, // can't parse; assume chain and let verification handle errors
    };
    let cert1 = match certs_der
        .get(1)
        .and_then(|der| X509Certificate::from_der(der).ok())
    {
        Some((_, cert)) => cert,
        None => return true,
    };

    cert0.issuer().as_raw() == cert1.subject().as_raw()
}

/// Verify a certificate chain provided as a list of DER-encoded certificates.
///
/// The chain should be ordered leaf-first: `[leaf, intermediate..., (optional root)]`.
/// The trust store provides the root CA certificates used to anchor the chain.
///
/// Checks performed:
/// 1. Chain depth limit (max 32 certificates)
/// 2. Signature verification at each link in the chain
/// 3. Validity dates (not expired, not yet valid) for all certificates, unless
///    disabled via `options.check_time`
/// 4. Basic constraints (intermediate CAs must have `CA:TRUE` and satisfy
///    `pathLenConstraint`)
/// 5. Trust anchoring (the chain must terminate at a trusted root)
/// 6. Hostname matching against the leaf certificate (if `hostname` is provided)
pub fn verify_chain(
    chain_der: &[Vec<u8>],
    trust_store: &TrustStore,
    hostname: Option<&str>,
) -> Result<VerificationResult, XcertError> {
    verify_chain_with_options(chain_der, trust_store, hostname, &VerifyOptions::default())
}

/// Verify a certificate chain with configurable options.
///
/// Like [`verify_chain`], but accepts [`VerifyOptions`] to control behavior
/// such as skipping validity date checks.
#[allow(clippy::indexing_slicing)]
pub fn verify_chain_with_options(
    chain_der: &[Vec<u8>],
    trust_store: &TrustStore,
    hostname: Option<&str>,
    options: &VerifyOptions,
) -> Result<VerificationResult, XcertError> {
    if chain_der.is_empty() {
        return Err(XcertError::VerifyError("empty certificate chain".into()));
    }

    let max_depth = options.verify_depth.unwrap_or(MAX_CHAIN_DEPTH);

    let now_ts = options.at_time.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    });

    // Parse all certificates in the chain
    let parsed: Vec<(&[u8], X509Certificate)> = chain_der
        .iter()
        .enumerate()
        .map(|(i, der)| {
            X509Certificate::from_der(der)
                .map(|(_, x509)| (der.as_slice(), x509))
                .map_err(|e| {
                    XcertError::VerifyError(format!(
                        "failed to parse certificate at depth {}: {}",
                        i, e
                    ))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // RFC 5280 Section 6.1: max_chain_depth counts non-self-issued
    // intermediates. Self-issued certificates (subject == issuer) do not
    // count toward the depth limit.
    let num_intermediates = parsed
        .iter()
        .enumerate()
        .skip(1) // skip leaf
        .filter(|(_, (_, cert))| !is_self_issued(cert))
        .count();
    if num_intermediates > max_depth {
        return Err(XcertError::VerifyError(format!(
            "certificate chain exceeds maximum depth of {} (has {} non-self-issued intermediates)",
            max_depth, num_intermediates
        )));
    }

    // Pre-compute subject and issuer strings for all certificates (#29).
    let subjects: Vec<String> = parsed
        .iter()
        .map(|(_, x509)| crate::parser::build_dn(x509.subject()).to_oneline())
        .collect();
    let issuers: Vec<String> = parsed
        .iter()
        .map(|(_, x509)| crate::parser::build_dn(x509.issuer()).to_oneline())
        .collect();

    let mut chain_info: Vec<ChainCertInfo> = subjects
        .iter()
        .zip(issuers.iter())
        .enumerate()
        .map(|(i, (subject, issuer))| ChainCertInfo {
            depth: i,
            subject: subject.clone(),
            issuer: issuer.clone(),
        })
        .collect();

    let mut errors = Vec::new();

    // Individual verification steps, each in its own helper function.
    if options.check_time {
        check_chain_time_validity(&parsed, &subjects, now_ts, &mut errors);
    }
    check_chain_basic_constraints(&parsed, &subjects, &mut errors);
    check_chain_critical_extensions(&parsed, &subjects, &mut errors);
    check_chain_duplicate_extensions(&parsed, &subjects, &mut errors);
    check_chain_name_constraint_placement(&parsed, &subjects, &mut errors);
    check_chain_name_constraints(&parsed, &subjects, &mut errors);
    check_chain_key_cert_sign(&parsed, &subjects, &mut errors);
    check_chain_rfc5280_strict(&parsed, &subjects, &mut errors);
    check_chain_signatures(&parsed, &subjects, &mut errors);

    // Trust anchoring
    let trusted_root_der = verify_trust_anchoring(
        &parsed,
        &subjects,
        &issuers,
        trust_store,
        options,
        &mut chain_info,
        &mut errors,
    )?;

    // Trusted root validation
    if let Some(ref root_der) = trusted_root_der {
        check_trusted_root(root_der, &parsed, &subjects, options, now_ts, &mut errors);
    }

    // Leaf certificate checks
    check_leaf_purpose(&parsed, &subjects, options, &mut errors);
    check_leaf_hostname(&parsed, hostname, options, &mut errors);
    check_leaf_email(&parsed, options, &mut errors);
    check_leaf_ip(&parsed, options, &mut errors);

    // CRL strict validation + revocation checking
    check_crl_strict(options, &mut errors);
    check_crl_chain(
        &parsed,
        &subjects,
        options,
        &trusted_root_der,
        now_ts,
        &mut errors,
    );

    // WebPKI-specific validation (CABF Baseline Requirements)
    if options.policy == VerifyPolicy::WebPki {
        check_webpki_policy(&parsed, &subjects, &trusted_root_der, &mut errors);
    }

    Ok(VerificationResult {
        is_valid: errors.is_empty(),
        chain: chain_info,
        errors,
    })
}

/// Convenience function: parse a PEM chain and verify it against a trust store.
pub fn verify_pem_chain(
    pem_data: &[u8],
    trust_store: &TrustStore,
    hostname: Option<&str>,
) -> Result<VerificationResult, XcertError> {
    let chain_der = parse_pem_chain(pem_data)?;
    verify_chain(&chain_der, trust_store, hostname)
}

/// Parse a PEM bundle, build the optimal chain via path building, and verify.
///
/// The first certificate in the PEM is the leaf. Remaining certificates form
/// the untrusted intermediate pool. A DFS path builder finds the shortest
/// chain from the leaf to a trust anchor.
#[allow(clippy::indexing_slicing)] // all_ders[0] and [1..] guarded by is_empty() check above
pub fn verify_pem_chain_with_options(
    pem_data: &[u8],
    trust_store: &TrustStore,
    hostname: Option<&str>,
    options: &VerifyOptions,
) -> Result<VerificationResult, XcertError> {
    let all_ders = parse_pem_chain(pem_data)?;
    if all_ders.is_empty() {
        return Err(XcertError::VerifyError("empty certificate chain".into()));
    }

    // Path building: first cert is leaf, rest form the intermediate pool.
    let leaf_der = &all_ders[0];
    let intermediates: Vec<(Vec<u8>, X509Certificate)> = all_ders[1..]
        .iter()
        .filter_map(|der| {
            X509Certificate::from_der(der)
                .ok()
                .map(|(_, cert)| (der.clone(), cert))
        })
        .collect();

    let chain = build_chain_dfs(leaf_der, &intermediates, trust_store);
    verify_chain_with_options(&chain, trust_store, hostname, options)
}

/// Build a complete chain by combining a leaf certificate with untrusted
/// intermediate certificates and verify it.
///
/// This mirrors `openssl verify -untrusted intermediates.pem cert.pem`:
/// the leaf cert is provided separately, and intermediates are loaded from
/// a PEM file. Uses DFS path building to find the optimal chain.
#[allow(clippy::indexing_slicing)]
pub fn verify_with_untrusted(
    leaf_der: &[u8],
    untrusted_pem: &[u8],
    trust_store: &TrustStore,
    hostname: Option<&str>,
    options: &VerifyOptions,
) -> Result<VerificationResult, XcertError> {
    let intermediate_der = parse_pem_chain(untrusted_pem)?;
    let intermediates: Vec<(Vec<u8>, X509Certificate)> = intermediate_der
        .iter()
        .filter_map(|der| {
            X509Certificate::from_der(der)
                .ok()
                .map(|(_, cert)| (der.clone(), cert))
        })
        .collect();

    let chain = build_chain_dfs(leaf_der, &intermediates, trust_store);
    verify_chain_with_options(&chain, trust_store, hostname, options)
}
