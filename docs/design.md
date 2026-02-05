# Design Document: xcert

## 1. Overview

`xcert` is a Rust command-line tool and library for parsing and displaying X.509
certificates. It is a read-only replacement for the display and inspection
features of `openssl x509`, with a simplified, modern CLI interface.

### Goals
- Parse X.509 certificates from PEM and DER formats
- Display certificate information in human-readable and JSON formats
- Extract individual fields for scripting
- Check certificate validity (expiry, hostname, email, IP)
- Convert between PEM and DER encodings
- Provide a library interface (`xcert-lib`) usable programmatically

### Non-Goals
- Certificate creation, signing, or modification
- Trust store management
- Full chain validation (use `openssl verify` or webpki for that). Note: Chain verification is now implemented via the `verify` subcommand.
- Private key handling

## 2. Architecture

```
┌─────────────────────────────────────────────────┐
│                   xcert (CLI binary)             │
│  ┌───────────┐ ┌────────┐ ┌───────┐ ┌────────┐ │
│  │  show cmd  │ │field   │ │check  │ │convert │ │
│  │            │ │cmd     │ │cmd    │ │cmd     │ │
│  └─────┬─────┘ └───┬────┘ └───┬───┘ └───┬────┘ │
│        └────────────┴──────────┴─────────┘      │
│                      │                           │
│              ┌───────┴────────┐                  │
│              │  xcert-lib     │                  │
│              │  (library)     │                  │
│              └───────┬────────┘                  │
│                      │                           │
│       ┌──────────────┼──────────────┐            │
│       │              │              │            │
│  ┌────┴─────┐  ┌─────┴────┐  ┌─────┴────┐      │
│  │  Parser   │  │ Display  │  │ Check    │      │
│  │  module   │  │ module   │  │ module   │      │
│  └────┬─────┘  └──────────┘  └──────────┘      │
│       │                                          │
└───────┼──────────────────────────────────────────┘
        │
   ┌────┴───────────────┐
   │  x509-parser crate │  (external dependency)
   └────────────────────┘
```

### Crate Structure

The project is organized as a Cargo workspace with two crates:

```
xcert-rs/
├── Cargo.toml              # Workspace root
├── xcert/                   # CLI binary crate
│   ├── Cargo.toml
│   └── src/
│       └── main.rs
└── xcert-lib/               # Library crate
    ├── Cargo.toml
    ├── src/
    │   ├── lib.rs           # Public API
    │   ├── parser.rs        # PEM/DER parsing, format detection
    │   ├── display.rs       # Human-readable formatting
    │   ├── fields.rs        # Individual field extraction
    │   ├── check.rs         # Validity checks (expiry, hostname, IP, email)
    │   ├── convert.rs       # PEM <-> DER conversion
    │   └── fingerprint.rs   # Digest computation
    └── tests/
        └── integration.rs   # Integration tests using test vectors
```

## 3. Dependencies

### xcert-lib

| Crate | Version | Purpose |
|-------|---------|---------|
| `x509-parser` | 0.18 | Core X.509 DER/PEM parsing |
| `sha2` | 0.10 | SHA-256/384/512 fingerprints |
| `sha1` | 0.10 | SHA-1 fingerprints (legacy compat) |
| `serde` | 1 | Serialization (with `derive` feature) |
| `serde_json` | 1 | JSON output |
| `thiserror` | 2 | Error types |
| `hex` | 0.4 | Hex encoding for fingerprints/serial |

### xcert (CLI)

| Crate | Version | Purpose |
|-------|---------|---------|
| `xcert-lib` | path | The library |
| `clap` | 4 | CLI argument parsing (with `derive` feature) |
| `anyhow` | 1 | Error handling in binary |

## 4. Library API Design

### Core Types

```rust
/// A parsed X.509 certificate with extracted fields.
pub struct CertificateInfo {
    pub version: u32,
    pub serial: String,                  // Hex string
    pub signature_algorithm: String,
    pub issuer: DistinguishedName,
    pub subject: DistinguishedName,
    pub not_before: DateTime,
    pub not_after: DateTime,
    pub public_key: PublicKeyInfo,
    pub extensions: Vec<Extension>,
    pub signature: Vec<u8>,

    // Raw DER bytes for fingerprint computation
    raw_der: Vec<u8>,
}

/// Distinguished name with ordered components.
pub struct DistinguishedName {
    pub components: Vec<(String, String)>,  // e.g., [("CN", "example.com"), ("O", "Org")]
}

/// Public key summary.
pub struct PublicKeyInfo {
    pub algorithm: String,      // "RSA", "EC", "Ed25519", etc.
    pub key_size: Option<u32>,  // Bit size (e.g., 2048 for RSA)
    pub curve: Option<String>,  // e.g., "P-256" for EC keys
    pub modulus: Option<String>, // Hex string for RSA
    pub pem: String,            // PEM-encoded SubjectPublicKeyInfo
}

/// A certificate extension.
pub struct Extension {
    pub oid: String,
    pub name: String,       // Human-readable name or OID if unknown
    pub critical: bool,
    pub value: ExtensionValue,
}

/// Strongly-typed extension values.
pub enum ExtensionValue {
    BasicConstraints { ca: bool, path_len: Option<u32> },
    KeyUsage(Vec<String>),
    ExtendedKeyUsage(Vec<String>),
    SubjectAltName(Vec<SanEntry>),
    SubjectKeyIdentifier(String),
    AuthorityKeyIdentifier { key_id: Option<String>, issuer: Option<String> },
    AuthorityInfoAccess(Vec<AiaEntry>),
    CrlDistributionPoints(Vec<String>),
    CertificatePolicies(Vec<String>),
    Raw(String),  // Hex dump for unknown extensions
}

pub enum SanEntry {
    Dns(String),
    Email(String),
    Ip(String),
    Uri(String),
    Other(String),
}

pub struct AiaEntry {
    pub method: String,   // "OCSP" or "CA Issuers"
    pub location: String, // URI
}

pub struct DateTime {
    // Internal representation using the ASN1Time from x509-parser
    // Displays as ISO 8601 by default
}
```

### Public API Functions

```rust
// --- Parsing ---

/// Parse a certificate from PEM or DER (auto-detected).
pub fn parse_cert(input: &[u8]) -> Result<CertificateInfo, XcertError>;

/// Parse a certificate from PEM.
pub fn parse_pem(input: &[u8]) -> Result<CertificateInfo, XcertError>;

/// Parse a certificate from DER.
pub fn parse_der(input: &[u8]) -> Result<CertificateInfo, XcertError>;

// --- Field Extraction ---
// (All available as methods on CertificateInfo)

impl CertificateInfo {
    pub fn subject_string(&self) -> String;
    pub fn issuer_string(&self) -> String;
    pub fn serial_hex(&self) -> &str;
    pub fn not_before_string(&self) -> String;
    pub fn not_after_string(&self) -> String;
    pub fn fingerprint(&self, algorithm: DigestAlgorithm) -> String;
    pub fn public_key_pem(&self) -> &str;
    pub fn modulus_hex(&self) -> Option<&str>;
    pub fn emails(&self) -> Vec<&str>;
    pub fn san_entries(&self) -> Vec<&SanEntry>;
    pub fn ocsp_urls(&self) -> Vec<&str>;
    pub fn key_usage(&self) -> Option<&[String]>;
    pub fn ext_key_usage(&self) -> Option<&[String]>;
}

pub enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    Sha1,
}

// --- Display ---

/// Format certificate as human-readable text (similar to openssl x509 -text).
pub fn display_text(cert: &CertificateInfo, show_all: bool) -> String;

/// Serialize certificate info to JSON.
pub fn to_json(cert: &CertificateInfo) -> Result<String, XcertError>;

// --- Checks ---

/// Check if certificate expires within `seconds` from now.
/// Returns true if the certificate will still be valid.
pub fn check_expiry(cert: &CertificateInfo, seconds: u64) -> bool;

/// Check if certificate matches a hostname (checks CN and SAN DNS entries).
pub fn check_host(cert: &CertificateInfo, hostname: &str) -> bool;

/// Check if certificate matches an email address (checks subject and SAN).
pub fn check_email(cert: &CertificateInfo, email: &str) -> bool;

/// Check if certificate matches an IP address (checks SAN IP entries).
pub fn check_ip(cert: &CertificateInfo, ip: &str) -> bool;

// --- Conversion ---

/// Convert DER bytes to PEM string.
pub fn der_to_pem(der: &[u8]) -> String;

/// Convert PEM string to DER bytes.
pub fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>, XcertError>;
```

### Error Types

```rust
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
}
```

## 5. CLI Design

See [cli-interface.md](cli-interface.md) for the full CLI specification.

The CLI binary is a thin layer over the library. Each subcommand maps directly
to library functions:

| Subcommand | Library functions used |
|---|---|
| `xcert show` | `parse_cert()` + `display_text()` or `to_json()` |
| `xcert field <F>` | `parse_cert()` + corresponding `CertificateInfo` method |
| `xcert check <C>` | `parse_cert()` + `check_*()` |
| `xcert convert` | `pem_to_der()` or `der_to_pem()` |
| `xcert verify` | `verify_chain()` + chain building |

## 6. Input Format Detection

Auto-detection algorithm:

1. If `--pem` or `--der` is specified, use that format.
2. If the input starts with `-----BEGIN` (after stripping leading whitespace),
   treat as PEM.
3. Otherwise, treat as DER.

This handles the common case (PEM files and raw DER blobs) without requiring
the user to specify the format.

## 7. Output Formatting

### Human-readable (default)

The `show` command produces output structured similarly to `openssl x509 -text`
but with cleaner formatting:

```
Certificate:
  Version: 3 (v3)
  Serial: 10:00
  Signature Algorithm: SHA-256 with RSA
  Issuer: CN=Test Intermediate CA, OU=Intermediate Authority, O=Test PKI, ST=California, C=US
  Validity:
    Not Before: 2026-02-03T23:57:06Z
    Not After:  2101-02-03T23:57:06Z
  Subject: CN=www.example.com, O=Example Corp, L=San Francisco, ST=California, C=US
  Public Key:
    Algorithm: RSA (2048 bit)
  Extensions:
    Basic Constraints: CA=false
    Key Usage: [critical] Digital Signature, Key Encipherment
    Extended Key Usage: TLS Web Server Authentication
    Subject Alternative Name:
      DNS: www.example.com
      DNS: example.com
      DNS: *.example.com
      IP: 93.184.216.34
      IP: 2606:2800:220:1:248:1893:25c8:1946
      Email: admin@example.com
    Authority Information Access:
      OCSP: http://ocsp.example.com
      CA Issuers: http://ca.example.com/intermediate.crt
    CRL Distribution Points:
      http://crl.example.com/intermediate.crl
  Fingerprint (SHA-256): ed:d7:70:25:...
```

Key differences from openssl:
- Dates in ISO 8601 format
- No hexdump of signature bytes (unless `--all`)
- No hexdump of public key modulus (unless `--all` or `field modulus`)
- Extensions are formatted more cleanly
- Fingerprint included by default

### JSON

The `--json` flag produces structured JSON output. All fields are present, with
extensions as typed objects. This is designed for programmatic consumption.

## 8. Hostname Matching

The `check host` command implements RFC 6125 hostname matching:

1. Check SAN DNS entries first (if SAN extension exists).
2. Wildcard matching: `*.example.com` matches `foo.example.com` but not
   `foo.bar.example.com` or `example.com`.
3. Only fall back to CN matching if no SAN DNS entries exist.
4. Case-insensitive comparison.

## 9. Implementation Plan

### Phase 1: Core Library
1. Set up Cargo workspace with `xcert-lib` and `xcert` crates
2. Implement `parser.rs` -- PEM/DER parsing and format detection
3. Implement `fields.rs` -- CertificateInfo construction and field extraction
4. Implement `fingerprint.rs` -- digest computation
5. Implement `display.rs` -- human-readable text formatting
6. Implement `check.rs` -- expiry, hostname, email, IP checks
7. Implement `convert.rs` -- PEM/DER conversion

### Phase 2: CLI Binary
8. Set up clap argument parsing with subcommands
9. Wire up `show` command
10. Wire up `field` command
11. Wire up `check` command
12. Wire up `convert` command

### Phase 3: Polish
13. JSON output support
14. Error messages and edge cases
15. Documentation and examples

### Test Strategy

Tests are organized at the library level using the generated test certificates:

- **Unit tests** in each module for internal logic
- **Integration tests** in `xcert-lib/tests/` using the test vectors in
  `testdata/certs/` and comparing against the reference outputs in
  `testdata/certs/reference/`
- **CLI tests** (future) using `assert_cmd` to test the binary end-to-end

Test categories:
1. Parsing tests -- PEM, DER, auto-detect, invalid input, chain bundles
2. Field extraction tests -- each field against reference output
3. Fingerprint tests -- SHA-256, SHA-1 against reference
4. Display tests -- full text output structure
5. Check tests -- expiry, hostname, email, IP (positive and negative)
6. Conversion tests -- PEM->DER->PEM roundtrip
7. Key algorithm tests -- RSA, ECDSA P-256, ECDSA P-384, Ed25519
8. Edge cases -- minimal certs, UTF-8 subjects, many extensions, expired certs
