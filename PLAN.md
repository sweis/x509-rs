# Improvement Plan

Comprehensive plan based on reviewing all code and comparing against x509
libraries in Python (pyca/cryptography), Go (crypto/x509), Java (PKIX +
Bouncy Castle), and the Rust ecosystem (rustls-webpki, x509-cert, x509-parser).

Goal: make xcert-lib the most complete, correct, and useful X.509 certificate
inspection and verification library available in Rust.

## Current State

- 195 integration tests, 11 clippy warnings, 0 compiler errors
- 5 CLI subcommands: show, field, check, convert, verify
- Parses 10 extension types into typed values; 8+ fall through to raw hex
- Chain verification covers: signatures, validity dates, BasicConstraints,
  pathLenConstraint, Key Usage (keyCertSign), EKU, hostname/email/IP, partial
  chain, custom time, max depth
- No revocation checking, no Name Constraints, no policy validation, no CRL/OCSP

## Phase 1: Extension Coverage (Zero New Dependencies)

x509-parser 0.16 already parses these extensions but our code drops them to
`ExtensionValue::Raw` in the `_ =>` catch-all arm. Add match arms and
`ExtensionValue` variants for each.

### 1.1 Name Constraints (2.5.29.30) -- CRITICAL
- Add `ExtensionValue::NameConstraints { permitted: Vec<GeneralSubtree>,
  excluded: Vec<GeneralSubtree> }` variant to `fields.rs`
- Add `ParsedExtension::NameConstraints` arm in `parser.rs:build_extension()`
- Display permitted/excluded subtrees in `display.rs`
- This is prerequisite for Phase 3 enforcement

### 1.2 Policy Constraints (2.5.29.36)
- Add `ExtensionValue::PolicyConstraints { require_explicit_policy: Option<u32>,
  inhibit_policy_mapping: Option<u32> }`
- Wire up in parser.rs and display.rs

### 1.3 Policy Mappings (2.5.29.33)
- Add `ExtensionValue::PolicyMappings(Vec<(String, String)>)` (issuer OID,
  subject OID pairs)
- Wire up in parser.rs and display.rs

### 1.4 Inhibit Any-Policy (2.5.29.54)
- Add `ExtensionValue::InhibitAnyPolicy(u32)` (skip-certs count)
- Wire up in parser.rs and display.rs

### 1.5 Issuer Alternative Name (2.5.29.18)
- Add `ExtensionValue::IssuerAltName(Vec<SanEntry>)` -- reuses existing
  `SanEntry` type
- Wire up in parser.rs and display.rs (same format as SAN display)

### 1.6 Subject Information Access (1.3.6.1.5.5.7.1.11)
- Add `ExtensionValue::SubjectInfoAccess(Vec<AiaEntry>)` -- reuses existing
  `AiaEntry` type
- Wire up in parser.rs and display.rs

### 1.7 Netscape Cert Type (2.16.840.1.113730.1.1)
- x509-parser parses this but we only handle NsCertComment
- Add `ExtensionValue::NsCertType(Vec<String>)` for the bitmask flags
- Wire up in parser.rs and display.rs

### 1.8 Signed Certificate Timestamps (1.3.6.1.4.1.11129.2.4.2)
- x509-parser parses SCT lists from Certificate Transparency
- Add `ExtensionValue::SignedCertificateTimestamps(Vec<SctInfo>)` with
  fields: version, log_id (hex), timestamp, hash_alg, sig_alg
- Wire up in parser.rs and display.rs
- Enables CT auditing which no other Rust library provides for inspection

**Estimated effort:** Low. Each is a new match arm + ExtensionValue variant.
No new dependencies.

---

## Phase 2: CRL Revocation Checking (Zero New Dependencies)

x509-parser 0.16 already includes `x509_parser::revocation_list` with full
CRL parsing. We just need to use it.

### 2.1 CRL Parsing
- Add `crl` module to xcert-lib
- Types: `CrlInfo { issuer, last_update, next_update, entries: Vec<CrlEntry> }`
- `CrlEntry { serial, revocation_date, reason: Option<CrlReason> }`
- Parse from DER or PEM using x509-parser's existing
  `CertificateRevocationList::from_der()`

### 2.2 CRL-Based Revocation Checking in Verify
- Add `VerifyOptions::crl_file: Option<PathBuf>` field
- Add `--crl` flag to CLI verify subcommand
- During chain verification, for each certificate:
  1. Parse the CRL
  2. Verify CRL signature against the issuing CA
  3. Check CRL validity (not expired)
  4. Look up the certificate's serial number in the CRL
  5. If found, add a verification error with the revocation reason
- Also add `VerifyOptions::crl_check_all: bool` to check entire chain vs
  leaf-only (matching OpenSSL's `-crl_check` vs `-crl_check_all`)

### 2.3 CLI `crl` Subcommand
- `xcert crl show <file>` -- display CRL information
- `xcert crl check <serial> <file>` -- check if serial is revoked
- Mirrors `openssl crl -text -noout -in crl.pem`

### 2.4 Tests
- Generate test CRLs using `openssl ca -gencrl`
- Test: valid CRL with no revocations passes
- Test: CRL containing the leaf serial fails verification
- Test: expired CRL fails
- Test: CRL signature verification

**Estimated effort:** Medium. CRL parsing is already available; logic code
needed for revocation checking and CRL display.

---

## Phase 3: Name Constraints Enforcement (Zero New Dependencies)

This is the single most critical RFC 5280 compliance gap. Go's crypto/x509,
Java's PKIX validator, and rustls-webpki all enforce this.

### 3.1 Implement RFC 5280 Section 6.1 Name Constraints Processing
- During `verify_chain_with_options()`, after building the chain, walk from
  root to leaf
- At each CA certificate that has a NameConstraints extension:
  - Extract permitted and excluded subtrees
  - For each subsequent certificate in the chain (toward the leaf):
    - Check that the subject DN and all SAN entries comply with the constraints
    - Specifically: dNSName, rfc822Name, iPAddress, directoryName, URI
  - Track cumulative constraints (child constraints must be within parent)
- Error messages should identify which constraint was violated and by which
  certificate

### 3.2 General Name Matching Functions
- `dns_name_within_subtree(name, constraint)` -- suffix matching
- `email_within_subtree(email, constraint)` -- domain part matching
- `ip_within_subtree(ip, network)` -- CIDR prefix matching
- `directory_name_within_subtree(dn, constraint)` -- DN prefix matching
- Place in `util.rs` or a new `constraints.rs` module

### 3.3 Tests
- Generate CA with Name Constraints limiting to `.example.com`
- Test: leaf cert for `www.example.com` passes
- Test: leaf cert for `www.evil.com` fails
- Test: excluded subtree matching works
- Test: IP range constraints work
- Cross-reference with Go's crypto/x509 test vectors

**Estimated effort:** Medium-high. The algorithm is well-defined (RFC 5280
Section 6.1.4(c)) but has edge cases with each GeneralName type.

---

## Phase 4: Verification Hardening

### 4.1 AKI/SKI Chain Building
- Current `verify_with_untrusted()` matches intermediates by subject name only
  (`verify.rs:671`)
- When multiple intermediates share the same subject (cross-certified CAs),
  this can select the wrong one
- Add AKI keyIdentifier matching: compare the child's AKI.keyIdentifier
  against the candidate parent's SKI
- Also use AKI for trust store lookup alongside subject-name matching

### 4.2 Chain Loop Detection
- rustls-webpki checks for repeated SPKIs to prevent circular chains
- Add SPKI-based loop detection in `verify_chain_with_options()`: track seen
  SPKIs and error if one repeats

### 4.3 Signature Algorithm Whitelisting
- Add `VerifyOptions::allowed_sig_algs: Option<Vec<String>>` to restrict
  acceptable signature algorithms
- Add `--sig-alg` CLI flag
- Default: allow all algorithms that x509-parser supports
- Enables rejecting SHA-1 chains in security-sensitive contexts

### 4.4 Self-Issued Intermediate Handling
- RFC 5280 Section 4.2.1.9: self-issued certificates (subject == issuer but
  not self-signed) are used for key rollover
- These should not count against pathLenConstraint
- Current code may incorrectly count them

### 4.5 Fix Clippy Warnings
- 7 indexing warnings in verify.rs: replace `parsed[i]` with `.get(i)` or
  iterator patterns
- 2 unnecessary `if let` in TrustStore::system(): flatten the
  `Vec<Option<String>>` iteration
- 1 `ref` pattern warning: use `Some(constraints)` instead of
  `Some(ref constraints)`
- 1 collapsible `else { if }` in main.rs

**Estimated effort:** Medium.

---

## Phase 5: Code Simplification with RustCrypto Crates

### 5.1 Replace Manual DER Encoding with `spki` Crate
- `build_spki_pem()` in parser.rs (60 lines) manually constructs DER TLV for
  SubjectPublicKeyInfo
- The `spki` crate (v0.7) provides `SubjectPublicKeyInfoRef::to_der()` and
  PEM encoding
- This eliminates `der_wrap()` entirely
- New dependency: `spki` (pulls in `der`, `const-oid` transitively)

### 5.2 Consider x509-parser Upgrade (0.16 -> 0.18)
- v0.17 added: RSA-PSS signature verification, visitor traits, better error
  types
- v0.18 added: aws-lc-rs backend option for FIPS environments
- Check UPGRADING.md for breaking changes before upgrading
- May require adjusting some API calls but would get free improvements

**Estimated effort:** Low-medium.

---

## Phase 6: OCSP Support

### 6.1 OCSP Response Parsing
- Add `ocsp` module to xcert-lib
- Use `x509-ocsp` crate (RustCrypto) for ASN.1 types: OCSPRequest,
  OCSPResponse, BasicOCSPResponse, CertID
- Parse OCSP responses from DER
- Extract: response status, cert status (good/revoked/unknown), produced_at,
  this_update, next_update, revocation time/reason

### 6.2 OCSP Request Building
- Build OCSP requests from a certificate + issuer pair
- Compute CertID (issuer name hash, issuer key hash, serial number)
- Export as DER for sending to OCSP responders

### 6.3 OCSP CLI
- `xcert ocsp status --issuer issuer.pem cert.pem` -- build request, send
  to OCSP responder (from AIA extension), display response
- Requires HTTP client dependency (ureq for minimal footprint, or make it
  optional behind a feature flag)

### 6.4 OCSP in Verification
- During chain verification, optionally check OCSP for each certificate
- `VerifyOptions::ocsp: bool` flag
- Fetch OCSP responder URL from AIA extension
- Cache responses for performance

**Estimated effort:** High. Requires new dependencies and HTTP networking.
Consider making this an optional feature (`ocsp` feature flag).

---

## Phase 7: Certificate Creation (Optional, Changes Library Scope)

This would expand xcert-lib from read-only to read-write, matching pyca and
Go crypto/x509. Only pursue if the goal is to compete as a general PKI
library rather than a certificate inspection tool.

### 7.1 CSR Parsing
- Parse PKCS#10 Certificate Signing Requests
- Display CSR contents (subject, public key, extensions, signature)
- `xcert csr show request.pem`

### 7.2 Self-Signed Certificate Generation
- `xcert generate --subject "CN=test" --key rsa:2048 --out cert.pem`
- Useful for testing and development
- Would require key generation crate (e.g., `rcgen`)

**Estimated effort:** High. Significant scope change.

---

## Phase 8: Quality and Documentation

### 8.1 Update README
- Fix test count (195, not 155)
- Document new CLI flags (--CApath, --partial-chain, --purpose, --attime,
  --verify-depth, --show-chain, --verify-email, --verify-ip, --ext)
- Add verify examples showing new flags
- Update comparison table with new commands

### 8.2 Update ISSUES.md
- Close issues #2, #3, #5-15 (already fixed in main)
- Add new issues discovered during this review
- Track remaining open items: #1 (CRL/OCSP), #4 (Name Constraints)

### 8.3 Benchmark Updates
- Re-run benchmarks with the latest code
- Add verify benchmarks (chain verification speed vs OpenSSL)

### 8.4 Additional Test Vectors
- Import test certificates from Go's crypto/x509 test suite
- Import test certificates from pyca/cryptography test suite
- Add Name Constraints test certs (when Phase 3 is implemented)
- Add CRL test data (when Phase 2 is implemented)

---

## Priority Order

| Phase | What | Impact | Effort | Dependencies |
|-------|------|--------|--------|--------------|
| **1** | Parse 8 more extensions | High (completeness) | Low | None |
| **4.5** | Fix clippy warnings | Medium (quality) | Low | None |
| **8.1** | Update README | Medium (usability) | Low | None |
| **2** | CRL revocation checking | Critical (security) | Medium | None |
| **3** | Name Constraints enforcement | Critical (compliance) | Medium-high | Phase 1.1 |
| **4.1-4.4** | Verification hardening | High (correctness) | Medium | None |
| **5** | RustCrypto simplification | Medium (maintainability) | Low-medium | spki crate |
| **6** | OCSP support | High (completeness) | High | x509-ocsp, HTTP client |
| **7** | Certificate creation | Medium (scope) | High | rcgen or similar |

Phases 1-3 close the two remaining open issues from ISSUES.md and bring the
library to RFC 5280 compliance parity with Go's crypto/x509 for path
validation. Phase 4 hardens edge cases that production deployments would
encounter. Phases 5-7 are longer-term improvements.
