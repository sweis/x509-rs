# Known Issues

Issues identified during code review. Ordered roughly by severity.

## Security / Correctness

### ~~1. CRL validity dates are not checked~~ FIXED

**Fix:** `check_crl_revocation()` now takes a `now_ts` parameter and validates
the CRL's `thisUpdate` / `nextUpdate` fields per RFC 5280 Section 6.3.3.
CRLs that are not yet valid or have expired are skipped.

---

### ~~2. CRL signature is not verified for root certificates~~ FIXED

**Fix:** The CRL check loop now pre-parses the trusted root certificate when
available and uses it (or the cert itself for self-signed roots) as the issuer
for CRL signature verification. The issuer is never `None` for CRL checks.

---

### ~~3. `--crl-check` without `--CRLfile` silently does nothing~~ FIXED

**Fix:** `xcert verify` now validates that `--CRLfile` is provided when
`--crl-check` or `--crl-check-all` is used, and exits with an error if not.

---

### ~~4. `der_wrap()` panics on untrusted input~~ FIXED

**Fix:** `der_wrap()` now returns `Result<Vec<u8>, XcertError>` instead of
using `assert!()`. Errors are propagated through `build_spki_pem()` which
also returns `Result`. No more panics on malformed input.

---

### ~~5. RSA parameter extraction silently returns incorrect values on failure~~ FIXED

**Fix:** `extract_rsa_params()` now returns `Option<(String, u32, u64)>`.
On parse failure, the caller sets modulus, key_size, and exponent to `None`
rather than reporting incorrect fallback values.

---

## Code Quality

### ~~6. O(n^2) email deduplication in `CertificateInfo::emails()`~~ FIXED

**Fix:** Replaced `Vec::contains()` deduplication with a `HashSet` for O(1)
lookup per insertion.

---

### ~~7. Duplicate GeneralName formatting logic~~ FIXED

**Fix:** `format_general_name()` now calls `general_name_to_san_entry()` and
extracts the inner string, eliminating the duplicate match arms.

---

### ~~8. Unnecessary Vec allocation for PEM detection~~ FIXED

**Fix:** Both `parse_cert()` in `parser.rs` and the convert command in
`main.rs` now use iterator-based comparison (`iter().take(10).eq(...)`)
instead of collecting into a `Vec<u8>`.

---

### ~~9. `base64_wrap()` uses unnecessary intermediate allocations~~ FIXED

**Fix:** Replaced byte-chunking with `from_utf8` and `Vec<&str>::join()` with
direct string slicing into a pre-allocated `String`. No intermediate Vec or
UTF-8 validation needed since base64 is ASCII.

---

### ~~10. Duplicate extension search methods in `fields.rs`~~ FIXED

**Fix:** Replaced manual `for/if let/return` loops in `san_entries()`,
`ocsp_urls()`, `key_usage()`, and `ext_key_usage()` with idiomatic
`find_map()` calls.

---

## Minor

### ~~11. CRL reason code uses Debug formatting~~ FIXED

**Fix:** Added `format_crl_reason()` function that maps `ReasonCode` debug
representations to RFC 5280-style camelCase strings (e.g., `keyCompromise`,
`cACompromise`, `cessationOfOperation`).

---

### ~~12. No X.509 version validation~~ FIXED

**Fix:** `build_certificate_info()` now validates that the X.509 version
field is 0, 1, or 2 (v1, v2, v3) and returns `XcertError::ParseError` for
unsupported version values.
