#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Tests using the zlint testdata repository (git submodule).
//!
//! Test certificates from <https://github.com/zmap/zlint> (Apache 2.0 license).
//! These tests verify that our parser handles a wide variety of real-world
//! and edge-case certificate structures without panicking.
//!
//! To initialize the test data:
//! ```sh
//! git submodule update --init
//! ```
//!
//! Tests skip gracefully when the submodule is not initialized.

use std::path::{Path, PathBuf};
use xcert_lib::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Path to the zlint testdata directory.
fn zlint_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // up from xcert-lib to workspace root
    p.push("testdata");
    p.push("zlint");
    p.push("v3");
    p.push("testdata");
    p
}

/// Extract the PEM block from a zlint test file.
///
/// zlint PEM files typically contain the `openssl x509 -text` dump
/// followed by the actual PEM block. This finds `-----BEGIN` and
/// returns everything from that point onward.
fn extract_pem(data: &[u8]) -> Option<&[u8]> {
    data.windows(11)
        .position(|w| w == b"-----BEGIN ")
        .map(|pos| &data[pos..])
}

/// Recursively collect all `.pem` files under a directory.
fn collect_pem_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                files.extend(collect_pem_files(&path));
            } else if path.extension().is_some_and(|e| e == "pem") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

/// Parse a zlint PEM file, returning the CertificateInfo on success.
fn parse_zlint_cert(path: &Path) -> Result<CertificateInfo, String> {
    let data = std::fs::read(path).map_err(|e| format!("read error: {}", e))?;
    let pem_data = extract_pem(&data).ok_or_else(|| "no PEM block found".to_string())?;
    parse_pem(pem_data).map_err(|e| format!("{}", e))
}

/// Skip macro: return early if the zlint submodule is not present.
macro_rules! require_zlint {
    ($dir:expr) => {
        if !$dir.exists() {
            eprintln!(
                "Skipping zlint tests: submodule not initialized. \
                 Run `git submodule update --init` to enable."
            );
            return;
        }
    };
}

// =========================================================================
// Core: parse every cert without panicking
// =========================================================================

#[test]
fn parse_all_zlint_certs_no_panic() {
    let dir = zlint_dir();
    require_zlint!(dir);

    let files = collect_pem_files(&dir);
    assert!(!files.is_empty(), "No PEM files found in zlint testdata");

    let mut parsed = 0;
    let mut errors = 0;
    let mut no_pem = 0;

    for path in &files {
        let data = std::fs::read(path).unwrap();

        let pem_data = match extract_pem(&data) {
            Some(pem) => pem,
            None => {
                no_pem += 1;
                continue;
            }
        };

        match parse_pem(pem_data) {
            Ok(_) => parsed += 1,
            Err(_) => errors += 1,
        }
    }

    eprintln!(
        "zlint testdata: {} files, {} parsed OK, {} parse errors, {} no PEM data",
        files.len(),
        parsed,
        errors,
        no_pem
    );

    // At least 90% should parse successfully
    let parseable = files.len() - no_pem;
    assert!(
        parsed > parseable * 9 / 10,
        "Too many parse failures: {errors} out of {parseable} parseable files \
         (expected >90% success rate)"
    );
}

// =========================================================================
// Display/JSON: no panics on any parsed cert
// =========================================================================

#[test]
fn display_and_json_all_zlint_certs_no_panic() {
    let dir = zlint_dir();
    require_zlint!(dir);

    let files = collect_pem_files(&dir);
    let mut tested = 0;

    for path in &files {
        if let Ok(cert) = parse_zlint_cert(path) {
            // display_text must not panic
            let _text = display_text(&cert, true);
            // to_json must not panic
            let _json = to_json(&cert);
            tested += 1;
        }
    }

    eprintln!("zlint display/json: tested {} certs", tested);
    assert!(tested > 0, "No certs were testable for display/json");
}

// =========================================================================
// Property tests: verify cert properties match filename conventions
// =========================================================================

#[test]
fn wildcard_san_certs_have_wildcard_entries() {
    let dir = zlint_dir();
    require_zlint!(dir);

    let files = collect_pem_files(&dir);
    let mut checked = 0;

    for path in &files {
        let name = path.file_stem().unwrap().to_string_lossy();
        // Only check files whose name explicitly indicates a wildcard SAN
        if !name.contains("SANDNSWildcard") && !name.contains("WildcardSAN") {
            continue;
        }

        if let Ok(cert) = parse_zlint_cert(path) {
            let sans = cert.san_entries();
            let has_wildcard = sans.iter().any(|e| match e {
                SanEntry::Dns(d) => d.starts_with("*."),
                _ => false,
            });
            assert!(
                has_wildcard,
                "{}: expected wildcard SAN entry but found none in {:?}",
                name, sans
            );
            checked += 1;
        }
    }

    eprintln!("zlint wildcard SAN: checked {} certs", checked);
    assert!(checked > 0, "No wildcard SAN certs found to check");
}

#[test]
fn ip_san_certs_have_ip_entries() {
    let dir = zlint_dir();
    require_zlint!(dir);

    let files = collect_pem_files(&dir);
    let mut checked = 0;

    for path in &files {
        let name = path.file_stem().unwrap().to_string_lossy();
        if !name.contains("SANIPv4") && !name.contains("SANIPv6") {
            continue;
        }

        if let Ok(cert) = parse_zlint_cert(path) {
            let sans = cert.san_entries();
            let has_ip = sans.iter().any(|e| matches!(e, SanEntry::Ip(_)));
            assert!(
                has_ip,
                "{}: expected IP SAN entry but found none in {:?}",
                name, sans
            );
            checked += 1;
        }
    }

    eprintln!("zlint IP SAN: checked {} certs", checked);
    assert!(checked > 0, "No IP SAN certs found to check");
}

#[test]
fn ecc_certs_have_ec_key_type() {
    let dir = zlint_dir();
    require_zlint!(dir);

    let files = collect_pem_files(&dir);
    let mut checked = 0;

    for path in &files {
        let name = path.file_stem().unwrap().to_string_lossy();
        if !name.starts_with("ecc") && !name.contains("ECDSA") {
            continue;
        }

        if let Ok(cert) = parse_zlint_cert(path) {
            assert!(
                cert.public_key.algorithm.contains("EC")
                    || cert.public_key.algorithm.contains("ec"),
                "{}: expected EC key type but got '{}'",
                name,
                cert.public_key.algorithm
            );
            checked += 1;
        }
    }

    eprintln!("zlint EC certs: checked {} certs", checked);
    assert!(checked > 0, "No ECC certs found to check");
}

#[test]
fn rsa_certs_have_rsa_key_type() {
    let dir = zlint_dir();
    require_zlint!(dir);

    let files = collect_pem_files(&dir);
    let mut checked = 0;

    for path in &files {
        let name = path.file_stem().unwrap().to_string_lossy();
        // Match files that clearly indicate RSA keys
        if !name.starts_with("rsa") && !name.starts_with("RSA") {
            continue;
        }

        if let Ok(cert) = parse_zlint_cert(path) {
            let algo = &cert.public_key.algorithm;
            // Accept "RSA", "rsa", or known RSA-family OIDs (e.g. RSASSA-PSS 1.2.840.113549.1.1.10)
            let is_rsa = algo.contains("RSA")
                || algo.contains("rsa")
                || algo.contains("1.2.840.113549.1.1.");
            assert!(is_rsa, "{}: expected RSA key type but got '{}'", name, algo);
            checked += 1;
        }
    }

    eprintln!("zlint RSA certs: checked {} certs", checked);
    assert!(checked > 0, "No RSA certs found to check");
}

#[test]
fn ca_certs_have_ca_flag() {
    let dir = zlint_dir();
    require_zlint!(dir);

    let files = collect_pem_files(&dir);
    let mut checked = 0;

    for path in &files {
        let name = path.file_stem().unwrap().to_string_lossy();
        // Match filenames like "rootCAValid.pem", "caKeyUsage*.pem"
        if !name.starts_with("rootCA") && !name.starts_with("caKey") {
            continue;
        }

        if let Ok(cert) = parse_zlint_cert(path) {
            let is_ca = cert.extensions.iter().any(|ext| {
                matches!(
                    &ext.value,
                    ExtensionValue::BasicConstraints { ca: true, .. }
                )
            });
            assert!(
                is_ca,
                "{}: expected BasicConstraints ca=true for CA certificate",
                name
            );
            checked += 1;
        }
    }

    eprintln!("zlint CA certs: checked {} certs", checked);
    assert!(checked > 0, "No CA certs found to check");
}

// =========================================================================
// Fingerprint: verify consistency across all parseable certs
// =========================================================================

#[test]
fn fingerprints_are_consistent_across_algorithms() {
    let dir = zlint_dir();
    require_zlint!(dir);

    let files = collect_pem_files(&dir);
    let mut checked = 0;

    for path in &files {
        if let Ok(cert) = parse_zlint_cert(path) {
            let sha256 = cert.fingerprint(DigestAlgorithm::Sha256);
            let sha384 = cert.fingerprint(DigestAlgorithm::Sha384);
            let sha512 = cert.fingerprint(DigestAlgorithm::Sha512);

            // SHA-256 = 64 hex chars + 31 colons = 95
            assert_eq!(sha256.len(), 95, "{}: bad SHA-256 length", path.display());
            // SHA-384 = 96 hex chars + 47 colons = 143
            assert_eq!(sha384.len(), 143, "{}: bad SHA-384 length", path.display());
            // SHA-512 = 128 hex chars + 63 colons = 191
            assert_eq!(sha512.len(), 191, "{}: bad SHA-512 length", path.display());

            // Same cert should always produce the same fingerprint
            assert_eq!(sha256, cert.fingerprint(DigestAlgorithm::Sha256));

            checked += 1;
        }
    }

    eprintln!("zlint fingerprints: checked {} certs", checked);
    assert!(checked > 0);
}
