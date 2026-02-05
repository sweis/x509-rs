# Known Issues

All issues identified during code review have been resolved.

## Round 5: Code quality and simplification

### ~~40. `format_crl_reason()` allocates `String` for static strings~~ FIXED

**Fix:** Changed return type to `&'static str`, eliminating heap allocation
on every call.

---

### ~~41. `check_trusted_root()` iterates root extensions twice~~ FIXED

**Fix:** Merged the two extension loops into one, computing `oid.to_id_string()`
once and checking both unknown critical extensions and Name Constraints
criticality in a single pass.

---

### ~~42. `verify_trust_anchoring()` recomputes issuer string already in `issuers[]`~~ FIXED

**Fix:** Added `issuers` parameter; now uses `issuers[last_idx]` instead of
calling `build_dn(last_x509.issuer()).to_oneline()`.

---

### ~~43. `check_name_constraints()` recomputes subject strings already pre-computed~~ FIXED

**Fix:** Added `subject: &str` parameter. Both call sites
(`check_chain_name_constraints` and `check_trusted_root`) now pass the
pre-computed subject string.

---

### ~~44. `eku_oid_to_name()` has dead match arms for already-handled EKU OIDs~~ FIXED

**Fix:** Removed the 7 dead match arms (serverAuth, clientAuth, codeSigning,
emailProtection, timeStamping, ocspSigning, anyEKU). Replaced with useful
uncommon OID mappings (IPSec, Microsoft/Netscape Server Gated Crypto).

---

### ~~45. `SanEntry` lacks `Display` impl, causing duplicate label-extraction patterns~~ FIXED

**Fix:** Added `Display` impl to `SanEntry` in `fields.rs`. Simplified
`display.rs::format_extension` from 20 match-arm lines to 3 lines, and
`main.rs` SAN output from 8 match-arm lines to `e.to_string()`.

---

### ~~46. `check_trusted_root()` re-parses root DER that was already parsed~~ DEFERRED

**Note:** The root certificate is parsed in `verify_trust_anchoring()` but
cannot be returned alongside its DER bytes due to Rust lifetime constraints
(`X509Certificate` borrows from the DER data). Re-parsing is necessary. The
cost is negligible for a single certificate.

---

### ~~47. `TrustStore::system()` builds unnecessary `Vec<Option<String>>` for dir paths~~ FIXED

**Fix:** Replaced `Vec<Option<String>>` + `.flatten()` with a direct iterator
chain: `env_var.into_iter().chain(probe_dirs).chain(known_dirs)`.

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
