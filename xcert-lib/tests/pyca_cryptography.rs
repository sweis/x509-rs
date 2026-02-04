#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Tests using the pyca/cryptography test vectors (git submodule).
//!
//! Test certificates from <https://github.com/pyca/cryptography>
//! (Apache 2.0 / BSD dual license).
//!
//! These vectors cover real-world certs, edge cases (bad ASN.1 times,
//! SCT extensions, VisibleString encoding), algorithm diversity (Ed25519,
//! Ed448, RSA-PSS, ECDSA), and the NIST PKITS certificate path validation
//! test suite (405 DER-encoded certificates).
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

/// Root of the pyca/cryptography x509 test vectors.
fn pyca_x509_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // up from xcert-lib to workspace root
    p.push("testdata");
    p.push("pyca-cryptography");
    p.push("vectors");
    p.push("cryptography_vectors");
    p.push("x509");
    p
}

/// Skip macro: return early if the pyca submodule is not present.
macro_rules! require_pyca {
    ($dir:expr) => {
        if !$dir.exists() {
            eprintln!(
                "Skipping pyca tests: submodule not initialized. \
                 Run `git submodule update --init` to enable."
            );
            return;
        }
    };
}

/// Recursively collect all certificate files under a directory.
///
/// Collects `.pem`, `.der`, `.crt`, and `.cer` files.
fn collect_cert_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_cert_files_recursive(dir, &mut files);
    files.sort();
    files
}

fn collect_cert_files_recursive(dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_cert_files_recursive(&path, files);
        } else if is_cert_file(&path) {
            files.push(path);
        }
    }
}

fn is_cert_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("pem" | "der" | "crt" | "cer")
    )
}

/// Try to parse a certificate file, handling both PEM and DER formats.
///
/// For PEM files that include an OpenSSL text dump before the PEM block,
/// extracts the PEM portion first.
fn try_parse_cert(path: &Path) -> Result<CertificateInfo, String> {
    let data = std::fs::read(path).map_err(|e| format!("read error: {}", e))?;

    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match ext {
        "pem" => {
            // Some PEM files have text before the PEM block; extract it
            if let Some(pos) = data.windows(11).position(|w| w == b"-----BEGIN ") {
                parse_pem(&data[pos..]).map_err(|e| format!("{}", e))
            } else {
                Err("no PEM block found".to_string())
            }
        }
        "der" | "crt" | "cer" => parse_der(&data).map_err(|e| format!("{}", e)),
        _ => Err(format!("unknown extension: {}", ext)),
    }
}

// =========================================================================
// Core: parse all pyca x509 cert files without panicking
// =========================================================================

#[test]
fn parse_all_pyca_certs_no_panic() {
    let dir = pyca_x509_dir();
    require_pyca!(dir);

    let files = collect_cert_files(&dir);
    assert!(!files.is_empty(), "No cert files found in pyca testdata");

    let mut parsed = 0;
    let mut errors = 0;

    for path in &files {
        match try_parse_cert(path) {
            Ok(_) => parsed += 1,
            Err(_) => errors += 1,
        }
    }

    eprintln!(
        "pyca testdata: {} files, {} parsed OK, {} parse errors",
        files.len(),
        parsed,
        errors
    );

    // At least 80% should parse (PKITS DER certs + edge cases may have
    // intentionally malformed structures, so threshold is slightly lower)
    assert!(
        parsed > files.len() * 8 / 10,
        "Too many parse failures: {errors} out of {} files (expected >80% success rate)",
        files.len()
    );
}

// =========================================================================
// Display/JSON: no panics on any parsed cert
// =========================================================================

#[test]
fn display_and_json_all_pyca_certs_no_panic() {
    let dir = pyca_x509_dir();
    require_pyca!(dir);

    let files = collect_cert_files(&dir);
    let mut tested = 0;

    for path in &files {
        if let Ok(cert) = try_parse_cert(path) {
            let _text = display_text(&cert, true);
            let _json = to_json(&cert);
            tested += 1;
        }
    }

    eprintln!("pyca display/json: tested {} certs", tested);
    assert!(tested > 0, "No certs were testable for display/json");
}

// =========================================================================
// PKITS: NIST certificate path validation test suite (DER certs)
// =========================================================================

#[test]
fn parse_all_pkits_certs_no_panic() {
    let dir = pyca_x509_dir().join("PKITS_data").join("certs");
    require_pyca!(dir);

    let mut parsed = 0;
    let mut errors = 0;
    let mut total = 0;

    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("crt") {
                continue;
            }
            total += 1;
            let data = std::fs::read(&path).unwrap();
            match parse_der(&data) {
                Ok(_) => parsed += 1,
                Err(_) => errors += 1,
            }
        }
    }

    eprintln!(
        "PKITS certs: {} total, {} parsed OK, {} parse errors",
        total, parsed, errors
    );
    assert!(total > 400, "Expected 400+ PKITS certs, found {}", total);
    // PKITS certs are well-formed; we should parse nearly all of them
    assert!(
        parsed > total * 9 / 10,
        "Too many PKITS parse failures: {errors} out of {total}"
    );
}

// =========================================================================
// Algorithm-specific tests
// =========================================================================

#[test]
fn ed25519_certs_parse_correctly() {
    let dir = pyca_x509_dir().join("ed25519");
    require_pyca!(dir);

    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("pem") {
            continue;
        }
        let cert = try_parse_cert(&path).unwrap_or_else(|e| {
            panic!("Failed to parse {}: {}", path.display(), e);
        });

        let algo = &cert.public_key.algorithm;
        // Accept Ed25519 (1.3.101.112) or X25519 (1.3.101.110) since
        // ed25519-rfc8410.pem uses X25519 (RFC 8410 covers both curves)
        assert!(
            algo.contains("Ed25519")
                || algo.contains("1.3.101.112")
                || algo.contains("1.3.101.110"),
            "{}: expected Ed25519/X25519 key, got '{}'",
            path.file_name().unwrap().to_string_lossy(),
            algo
        );
        checked += 1;
    }

    eprintln!("pyca Ed25519: checked {} certs", checked);
    assert!(checked > 0, "No Ed25519 certs found");
}

#[test]
fn ed448_certs_parse_correctly() {
    let dir = pyca_x509_dir().join("ed448");
    require_pyca!(dir);

    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("pem") {
            continue;
        }
        let cert = try_parse_cert(&path).unwrap_or_else(|e| {
            panic!("Failed to parse {}: {}", path.display(), e);
        });

        let algo = &cert.public_key.algorithm;
        assert!(
            algo.contains("Ed448") || algo.contains("1.3.101.113"),
            "{}: expected Ed448 key, got '{}'",
            path.file_name().unwrap().to_string_lossy(),
            algo
        );
        checked += 1;
    }

    eprintln!("pyca Ed448: checked {} certs", checked);
    assert!(checked > 0, "No Ed448 certs found");
}

// =========================================================================
// Specific edge-case certs from pyca
// =========================================================================

#[test]
fn v1_cert_has_version_1() {
    let dir = pyca_x509_dir();
    require_pyca!(dir);

    let cert = try_parse_cert(&dir.join("v1_cert.pem")).unwrap();
    assert_eq!(cert.version, 1, "Expected X.509 v1 certificate");
}

#[test]
fn wildcard_san_cert_has_wildcard() {
    let dir = pyca_x509_dir();
    require_pyca!(dir);

    let cert = try_parse_cert(&dir.join("wildcard_san.pem")).unwrap();
    let has_wildcard = cert.san_entries().iter().any(|e| match e {
        SanEntry::Dns(d) => d.contains('*'),
        _ => false,
    });
    assert!(has_wildcard, "Expected wildcard SAN in wildcard_san.pem");
}

#[test]
fn utf8_dnsname_cert_parses() {
    let dir = pyca_x509_dir();
    require_pyca!(dir);

    let cert = try_parse_cert(&dir.join("utf8-dnsname.pem")).unwrap();
    let sans = cert.san_entries();
    assert!(!sans.is_empty(), "Expected SAN entries in utf8-dnsname.pem");
}

#[test]
fn ecdsa_root_has_ec_key() {
    let dir = pyca_x509_dir();
    require_pyca!(dir);

    let cert = try_parse_cert(&dir.join("ecdsa_root.pem")).unwrap();
    assert!(
        cert.public_key.algorithm.contains("EC"),
        "Expected EC key, got '{}'",
        cert.public_key.algorithm
    );
}

#[test]
fn letsencrypt_x3_parses() {
    let dir = pyca_x509_dir();
    require_pyca!(dir);

    let cert = try_parse_cert(&dir.join("letsencryptx3.pem")).unwrap();
    assert!(
        cert.issuer_string().contains("DST Root CA"),
        "Expected DST Root CA issuer, got '{}'",
        cert.issuer_string()
    );
}

#[test]
fn chain_pem_parses_first_cert() {
    let dir = pyca_x509_dir();
    require_pyca!(dir);

    let cert = try_parse_cert(&dir.join("cryptography.io.pem")).unwrap();
    // The leaf cert should have cryptography.io in the subject or SAN
    let has_cryptography_io = cert.san_entries().iter().any(|e| match e {
        SanEntry::Dns(d) => d.contains("cryptography.io"),
        _ => false,
    });
    assert!(
        has_cryptography_io || cert.subject_string().contains("cryptography.io"),
        "Expected cryptography.io in subject or SAN"
    );
}

// =========================================================================
// Custom directory: edge-case and extension-specific certs
// =========================================================================

#[test]
fn parse_all_custom_certs_no_panic() {
    let dir = pyca_x509_dir().join("custom");
    require_pyca!(dir);

    let files = collect_cert_files(&dir);
    assert!(!files.is_empty(), "No cert files found in custom/");

    let mut parsed = 0;
    let mut errors = 0;

    for path in &files {
        match try_parse_cert(path) {
            Ok(_) => parsed += 1,
            Err(_) => errors += 1,
        }
    }

    eprintln!(
        "pyca custom: {} files, {} parsed OK, {} parse errors",
        files.len(),
        parsed,
        errors
    );

    // Custom dir has intentionally malformed certs, so 70% threshold
    assert!(
        parsed > files.len() * 7 / 10,
        "Too many custom parse failures: {errors} out of {}",
        files.len()
    );
}

#[test]
fn custom_all_key_usages_has_key_usage() {
    let dir = pyca_x509_dir().join("custom");
    require_pyca!(dir);

    let cert = try_parse_cert(&dir.join("all_key_usages.pem")).unwrap();
    let ku = cert.key_usage().expect("Expected Key Usage extension");
    // Should have multiple key usage values
    assert!(
        ku.len() >= 5,
        "Expected many key usages, got {}: {:?}",
        ku.len(),
        ku
    );
}

#[test]
fn custom_bc_path_length_zero() {
    let dir = pyca_x509_dir().join("custom");
    require_pyca!(dir);

    let cert = try_parse_cert(&dir.join("bc_path_length_zero.pem")).unwrap();
    let has_bc = cert.extensions.iter().any(|ext| {
        matches!(
            &ext.value,
            ExtensionValue::BasicConstraints {
                ca: true,
                path_len: Some(0)
            }
        )
    });
    assert!(has_bc, "Expected BasicConstraints CA:TRUE, pathlen:0");
}

// =========================================================================
// Fingerprint consistency across all parseable pyca certs
// =========================================================================

#[test]
fn fingerprints_consistent_across_pyca_certs() {
    let dir = pyca_x509_dir();
    require_pyca!(dir);

    let files = collect_cert_files(&dir);
    let mut checked = 0;

    for path in &files {
        if let Ok(cert) = try_parse_cert(path) {
            let sha256 = cert.fingerprint(DigestAlgorithm::Sha256);
            let sha384 = cert.fingerprint(DigestAlgorithm::Sha384);

            assert_eq!(sha256.len(), 95, "{}: bad SHA-256 length", path.display());
            assert_eq!(sha384.len(), 143, "{}: bad SHA-384 length", path.display());
            // Deterministic
            assert_eq!(sha256, cert.fingerprint(DigestAlgorithm::Sha256));

            checked += 1;
        }
    }

    eprintln!("pyca fingerprints: checked {} certs", checked);
    assert!(checked > 0);
}
