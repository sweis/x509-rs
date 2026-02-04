# Known Issues

Issues identified during code review. All issues below have been fixed.

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
