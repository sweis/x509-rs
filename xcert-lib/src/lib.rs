//! xcert-lib: Library for parsing and inspecting X.509 certificates.
//!
//! Provides a high-level API for extracting information from X.509 certificates
//! in PEM or DER format, computing fingerprints, checking validity, and
//! converting between formats.

mod check;
mod convert;
mod display;
mod fields;
mod fingerprint;
mod parser;
mod util;
pub mod verify;

pub use check::{check_email, check_expiry, check_host, check_ip};
pub use convert::{der_to_pem, pem_to_der};
pub use display::{display_text, to_json};
pub use fields::{
    AiaEntry, CertificateInfo, DateTime, DigestAlgorithm, DistinguishedName, Extension,
    ExtensionValue, PublicKeyInfo, SanEntry,
};
pub use fingerprint::compute_fingerprint;
pub use parser::{parse_cert, parse_der, parse_pem};
pub use verify::{
    find_system_ca_bundle, parse_pem_chain, verify_chain, verify_chain_with_options,
    verify_pem_chain, verify_pem_chain_with_options, verify_with_untrusted, ChainCertInfo,
    TrustStore, VerificationResult, VerifyOptions,
};

/// Errors returned by xcert-lib.
#[derive(Debug, thiserror::Error)]
pub enum XcertError {
    #[error("Failed to parse certificate: {0}")]
    ParseError(String),

    #[error("Invalid PEM format: {0}")]
    PemError(String),

    #[error("Invalid DER format: {0}")]
    DerError(String),

    #[error("Unsupported feature: {0}")]
    Unsupported(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Verification error: {0}")]
    VerifyError(String),
}
