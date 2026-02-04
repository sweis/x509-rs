# Known Issues

Issues identified during code review. Ordered roughly by severity.

## Security / Correctness

### 1. No certificate revocation checking (CRL/OCSP)

`verify.rs` does not check whether certificates have been revoked. Neither
CRL Distribution Points nor OCSP responder URLs are consulted during chain
verification. A revoked intermediate or leaf certificate will verify
successfully.

**Impact:** A revoked certificate chain will pass verification.

**Files:** `xcert-lib/src/verify.rs`

---

### ~~2. Key Usage not checked during chain verification~~ FIXED

RFC 5280 Section 4.2.1.3 requires that CA certificates used to sign other
certificates have the `keyCertSign` bit set in the Key Usage extension.

**Fix:** Added keyCertSign check for CA certificates when Key Usage extension
is present. Verification now fails if a CA certificate has Key Usage but lacks
the keyCertSign bit.

---

### ~~3. `check_expiry` does not validate `notBefore`~~ FIXED

**Fix:** `check_expiry()` now checks that `not_before` is in the past before
considering the certificate valid. Not-yet-valid certificates return `false`.

---

### 4. No Name Constraints checking

The verification module does not enforce the Name Constraints extension
(RFC 5280 Section 4.2.1.10). A CA certificate with Name Constraints limiting
its scope to a specific domain could be used to sign certificates for
arbitrary domains without triggering a verification error.

**Files:** `xcert-lib/src/verify.rs`

---

## Code Quality

### ~~5. Duplicate hostname matching logic~~ FIXED

**Fix:** Shared `hostname_matches()` extracted to `util.rs`. Both `check.rs`
and `verify.rs` now call `util::hostname_matches()`.

---

### ~~6. Duplicate OID-to-short-name mappings~~ FIXED

**Fix:** Consolidated into `util::oid_short_name()`. Both `parser.rs` and
`verify.rs` now use the shared function.

---

### ~~7. `TrustStore::add_pem_bundle` return value is misleading~~ FIXED

**Fix:** `add_pem_bundle()` now counts only certificates that were successfully
added via `add_der()`, rather than counting all PEM entries found.

---

### ~~8. Unused `load_reference` function in tests~~ FIXED

**Fix:** The unused function was removed. A new `load_reference()` helper and
`reference_path()` function were added to support the reference vector tests.

---

### ~~9. 116 reference test vectors are unused~~ FIXED

**Fix:** Added a `reference_vectors` test module with 9 tests that compare
library output against OpenSSL reference files: serial numbers, SHA-256 and
SHA-1 fingerprints, subject and issuer DN components, RSA modulus, email
addresses, and OCSP URIs.

---

## Missing Features

### ~~10. No `--partial-chain` option~~ FIXED

**Fix:** Added `partial_chain` field to `VerifyOptions` and `--partial-chain`
CLI flag. When enabled, verification succeeds if any certificate in the chain
is directly in the trust store.

---

### ~~11. No Extended Key Usage checking during verification~~ FIXED

**Fix:** Added `purpose` field to `VerifyOptions` and `--purpose` CLI flag.
When specified, the leaf certificate's EKU extension is checked for the
required OID (e.g., `1.3.6.1.5.5.7.3.1` for serverAuth).

---

### ~~12. No LICENSE file~~ FIXED

**Fix:** Added MIT LICENSE file and updated README reference.

---

## Minor

### ~~13. `docs/cli-interface.md` does not document `verify` subcommand~~ FIXED

**Fix:** Added full `xcert verify` documentation to `cli-interface.md`
including all options, examples, and comparison table entries.

---

### ~~14. Version display is redundant~~ FIXED

**Fix:** Changed `Version: 3 (v3)` to `Version: 3 (0x2)` matching OpenSSL's
format of showing the human-readable version and the ASN.1 encoded value.

---

### ~~15. No CI configuration~~ FIXED

**Fix:** Added `.github/workflows/ci.yml` with test, clippy, and fmt jobs
running on push/PR to main.
