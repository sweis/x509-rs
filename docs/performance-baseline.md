# OpenSSL x509 Performance Baseline

## Environment

| Parameter       | Value                                                        |
|-----------------|--------------------------------------------------------------|
| OpenSSL version | OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024) |
| Platform        | Linux 4.4.0                                                  |
| Date            | 2026-02-04 00:25 UTC                                         |
| Iterations      | 1000 per benchmark                                           |
| Timing method   | `date +%s%N` (nanosecond wall-clock)                         |
| Benchmark script| `bench/openssl-baseline.sh`                                  |

## Results

| # | Operation | Certificate | Iterations | Total Time (ms) | Avg per Op (ms) |
|---|-----------|-------------|------------|-----------------|-----------------|
| 1 | Parse + text display | root-ca.pem | 1000 | 43236.14 | 43.2361 |
| 2 | Parse + text display | server.pem | 1000 | 44336.27 | 44.3363 |
| 3 | Parse + text display | many-extensions.pem | 1000 | 46343.89 | 46.3439 |
| 4 | Parse + subject extraction | root-ca.pem | 1000 | 46763.14 | 46.7631 |
| 5 | Parse + subject extraction | server.pem | 1000 | 48544.66 | 48.5447 |
| 6 | Parse + subject extraction | many-extensions.pem | 1000 | 48151.21 | 48.1512 |
| 7 | SHA-256 fingerprint | root-ca.pem | 1000 | 46680.77 | 46.6808 |
| 8 | SHA-256 fingerprint | server.pem | 1000 | 48551.32 | 48.5513 |
| 9 | SHA-256 fingerprint | many-extensions.pem | 1000 | 46850.93 | 46.8509 |
| 10 | PEM to DER conversion | root-ca.pem | 1000 | 48754.87 | 48.7549 |
| 11 | PEM to DER conversion | server.pem | 1000 | 47453.41 | 47.4534 |
| 12 | PEM to DER conversion | many-extensions.pem | 1000 | 47662.79 | 47.6628 |
| 13 | DER parse + text display | root-ca.der | 1000 | 49544.12 | 49.5441 |
| 14 | Hostname check (match) | server.pem | 1000 | 61918.45 | 61.9184 |

## Summary by Operation (averaged across certificates)

| Operation | Avg per Op (ms) |
|-----------|-----------------|
| Parse + text display | 44.64 |
| Parse + subject extraction | 47.82 |
| SHA-256 fingerprint | 47.36 |
| PEM to DER conversion | 47.96 |
| DER parse + text display | 49.54 |
| Hostname check (match) | 61.92 |

## Notes

- Each measurement includes the full process lifecycle: `fork` + `exec` of the `openssl`
  binary, library initialization, PEM/DER parsing, the requested operation, and output
  formatting. The per-operation cost is dominated by process startup overhead (~43-50 ms),
  not the cryptographic or parsing work itself.
- The hostname check is notably slower (~62 ms) because it performs additional SAN/CN
  matching logic on top of the standard parse.
- The `many-extensions.pem` certificate (2106 bytes, numerous X.509v3 extensions) shows
  only a marginal increase over `root-ca.pem` (1419 bytes) for text display, confirming
  that extension parsing cost is small relative to process startup.
- DER parsing (`root-ca.der`) is comparable to PEM parsing, which is expected since PEM
  decoding (Base64 stripping) is negligible.
- These baselines represent the **ceiling** that the Rust `xcert` implementation should
  beat, since a compiled-in parser avoids per-invocation process startup costs.

## OpenSSL Commands Benchmarked

```bash
# 1. Parse + text display
openssl x509 -in cert.pem -text -noout

# 2. Parse + subject extraction
openssl x509 -in cert.pem -subject -noout

# 3. SHA-256 fingerprint
openssl x509 -in cert.pem -fingerprint -sha256 -noout

# 4. PEM to DER conversion
openssl x509 -in cert.pem -outform DER -out /dev/null

# 5. DER parsing
openssl x509 -in cert.der -inform DER -text -noout

# 6. Hostname check
openssl x509 -in server.pem -checkhost www.example.com -noout
```
