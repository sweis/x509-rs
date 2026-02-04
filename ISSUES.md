# Known Issues

## Code Coverage (as of 2026-02-04)

| File | Line Coverage | Notes |
|------|-------------|-------|
| check.rs | 96.88% | |
| convert.rs | 100.00% | |
| display.rs | 93.85% | |
| fields.rs | 91.73% | |
| fingerprint.rs | 100.00% | |
| parser.rs | 86.12% | Error paths, Ed448, unknown OIDs |
| util.rs | 98.53% | |
| verify.rs | 82.18% | Partial chain, CRL edge cases |
| main.rs | 25.62% | CLI binary; integration tests run externally |
| **TOTAL** | **69.55%** | Library avg ~91%; main.rs drags total down |

Issues identified during code review. All 39 issues have been fixed.

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

### ~~11. `dns_name_matches_constraint` allocates on every call~~ FIXED

**Fix:** Replaced `name.ends_with(&format!(".{}", constraint))` with a
non-allocating length + suffix + byte check.

---

### ~~12. `ip_matches_constraint` has duplicate IPv4/IPv6 masking loops~~ FIXED

**Fix:** Consolidated into a single generic implementation using
`split_at(addr_len)` and `Iterator::zip().all()`.

---

### ~~13. `check_host` collects SAN DNS entries into unnecessary Vec~~ FIXED

**Fix:** Replaced `Vec<&str>` collect + `is_empty()` check + iterate with a
single-pass loop that tracks `has_san_dns` and matches in one iteration.

---

### ~~14. `to_oneline` uses intermediate Vec and `replace()` chain~~ FIXED

**Fix:** Replaced `collect::<Vec<_>>().join(", ")` with direct `String`
building, and replaced the three `.replace()` calls with a single char-by-char
escape loop.

---

## Minor

### ~~15. CRL reason code uses Debug formatting~~ FIXED

**Fix:** Added `format_crl_reason()` function that maps `ReasonCode` debug
representations to RFC 5280-style camelCase strings (e.g., `keyCompromise`,
`cACompromise`, `cessationOfOperation`).

---

### ~~16. No X.509 version validation~~ FIXED

**Fix:** `build_certificate_info()` now validates that the X.509 version
field is 0, 1, or 2 (v1, v2, v3) and returns `XcertError::ParseError` for
unsupported version values.

---

### ~~17. `check_email` and `check_ip` use verbose loops~~ FIXED

**Fix:** Simplified both functions to use iterator `.any()` and `matches!()`
instead of explicit `for` loops with early return.

---

### ~~18. RSA exponent silently defaults to 65537 on parse failure~~ FIXED

**Fix:** `extract_rsa_params()` now returns `None` (via `?`) when the exponent
cannot be parsed from the DER sequence, instead of silently substituting 65537.

---

### ~~19. DER encoding errors silently swallowed in SPKI PEM generation~~ FIXED

**Fix:** `build_spki_pem()` now propagates DER encoding errors from
`to_der_vec()` via `map_err` + `?` instead of using `unwrap_or_default()`
and NULL-byte fallbacks.

---

### ~~20. `check_expiry` skips notBefore validation for non-positive timestamps~~ FIXED

**Fix:** Replaced mixed signed/unsigned comparison with consistent signed
arithmetic (`not_before > (now as i64)`), correctly handling pre-epoch
timestamps without skipping validation.

---

### ~~21. Hardcoded DER length limit magic number~~ FIXED

**Fix:** Extracted `MAX_DER_CONTENT_LEN` named constant (0xFF_FFFF / 16 MiB)
with documentation explaining the 3-byte DER length field limit.

---

### ~~22. Inconsistent IPv6 hex formatting between parser and check modules~~ FIXED

**Fix:** `normalize_ip()` in `check.rs` now uses uppercase hex (`{:X}`)
matching `format_ip_bytes()` in `parser.rs` for consistent OpenSSL-compatible
IPv6 formatting.

---

### ~~23. Duplicate PEM detection logic in parser.rs and main.rs~~ FIXED

**Fix:** Extracted `util::is_pem()` shared utility function, exposed as
`xcert_lib::is_pem()`. Both `parse_cert()` and the CLI convert command
now call the shared function.

---

### ~~24. OID comparisons use `format!()` instead of `to_id_string()`~~ FIXED

**Fix:** Replaced `format!("{}", oid)` and `format!("{}", attr.attr_type())`
with `oid.to_id_string()` / `attr.attr_type().to_id_string()` in `verify.rs`
(EKU check, extract_cn, verify_email, check_name_constraints) and `parser.rs`
(build_dn). More idiomatic and avoids format machinery overhead.

---

### ~~25. Redundant bounds checks on `used` vector in `verify_with_untrusted`~~ FIXED

**Fix:** Replaced `used.get(idx).copied().unwrap_or(true)` and
`used.get_mut(idx)` with direct indexing (`used[idx]`), since the vector
is guaranteed to have the same length as the `intermediates` iterator.

---

## Round 3: Post-merge comprehensive review

Issues identified after merging significant new features (directory/batch mode,
chain detection, Name Constraints, keyCertSign, trusted root validation,
`find_system_ca_bundle()`).

### ~~26. Duplicate hostname/email/IP matching logic in `check.rs` and `verify.rs`~~ FIXED

**Fix:** Extracted shared matching functions `verify_hostname_match()`,
`verify_email_match()`, and `verify_ip_match()` into `util.rs`. Both
`check.rs` (operating on `CertificateInfo`) and `verify.rs` (operating on
`X509Certificate`) now extract their data and delegate to the shared functions.

---

### ~~27. `find_system_ca_bundle()` duplicates path discovery from `TrustStore::system()`~~ FIXED

**Fix:** Extracted `KNOWN_CA_BUNDLE_PATHS` and `KNOWN_CA_DIR_PATHS` constants.
`TrustStore::system()` now calls `find_system_ca_bundle()` for file discovery
and `add_pem_directory()` for directory loading. Both functions also check
`SSL_CERT_FILE` / `SSL_CERT_DIR` environment variables.

---

### ~~28. `serial_compact()` is unused dead code~~ FIXED

**Fix:** Removed the unused `serial_compact()` method from `fields.rs`.

---

### ~~29. Repeated `build_dn(x509.subject()).to_oneline()` pattern in `verify.rs`~~ FIXED

**Fix:** Pre-computed `subjects` and `issuers` vectors once after parsing
the chain. All helper functions receive the pre-computed strings, eliminating
repeated DN traversal and allocation.

---

### ~~30. `format_crl_reason()` relies on fragile Debug string matching~~ FIXED

**Fix:** Replaced `Debug` string matching with direct numeric matching on
`rc.0` (the underlying `u8` value). Matches RFC 5280 reason code values
0–10 directly, immune to upstream `Debug` formatting changes.

---

### ~~31. No file size limit for disk file reads~~ FIXED

**Fix:** Added `MAX_INPUT_BYTES` constant (10 MiB) and a `std::fs::metadata()`
size check before `std::fs::read()`. Files exceeding the limit produce a
clear error message. Both stdin and disk file paths now share the same limit.

---

### ~~32. IPv6 formatting duplicated between `parser.rs` and `check.rs`~~ FIXED

**Fix:** Extracted `format_ipv6_expanded()` into `util.rs`. Both `parser.rs`
and `check.rs` (via `normalize_ip()`) now call the shared function.

---

### ~~33. `TrustStore::add_pem_directory()` uses overly broad filename matching~~ FIXED

**Fix:** Extracted `is_pem_cert_file()` function that checks for `.pem`,
`.crt`, `.cer` extensions (case-insensitive) or single-digit extensions
(OpenSSL hash-linked files). Validates the extension is exactly one digit
character, not just any filename ending in a digit.

---

### ~~34. Inconsistent cert file extension filtering across trust store methods~~ FIXED

**Fix:** Both `TrustStore::system()` and `add_pem_directory()` now use the
shared `is_pem_cert_file()` function, ensuring consistent extension filtering
(`.pem`, `.crt`, `.cer`, and OpenSSL hash-linked single-digit extensions).

---

### ~~35. `verify_chain_with_options()` is ~460 lines and could be decomposed~~ FIXED

**Fix:** Decomposed into 14 focused helper functions: `check_chain_time_validity()`,
`check_chain_basic_constraints()`, `check_chain_critical_extensions()`,
`check_chain_duplicate_extensions()`, `check_chain_name_constraint_placement()`,
`check_chain_name_constraints()`, `check_chain_key_cert_sign()`,
`check_chain_signatures()`, `verify_trust_anchoring()`, `check_trusted_root()`,
`check_leaf_purpose()`, `check_leaf_hostname()`, `check_leaf_email()`,
`check_leaf_ip()`, and `check_crl_chain()`. Main function reduced from ~460
lines to ~110 lines.

---

## Round 4: CLI deduplication

### ~~36. main.rs: Duplicate batch result construction~~ FIXED

**Fix:** Added `verify_to_batch()` helper that converts a
`Result<VerificationResult, E>` into a `BatchResult`, replacing 4
duplicate match arms in the batch verify closure.

---

### ~~37. main.rs: Duplicate verification result printing~~ FIXED

**Fix:** Added `print_verify_result()` helper that handles JSON output,
valid/invalid printing, and `--show-chain` display. Replaces 3 duplicate
print blocks in the single-file verify handler.
