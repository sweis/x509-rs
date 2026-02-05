# Performance Benchmarks

All benchmarks run 1000 iterations measuring wall-clock time (including process
startup). Environment: Linux 4.4.0, OpenSSL 3.0.13.

## Results: xcert vs OpenSSL

| Operation | OpenSSL avg (ms) | xcert avg (ms) | Speedup |
|---|--:|--:|--:|
| Parse + text display (root-ca.pem) | 43.27 | 10.29 | 4.2x |
| Parse + text display (server.pem) | 43.83 | 10.23 | 4.3x |
| Parse + text display (many-extensions.pem) | 43.90 | 10.41 | 4.2x |
| Subject extraction (root-ca.pem) | 44.09 | 10.72 | 4.1x |
| Subject extraction (server.pem) | 44.33 | 10.21 | 4.3x |
| Subject extraction (many-extensions.pem) | 44.78 | 10.55 | 4.2x |
| SHA-256 fingerprint (root-ca.pem) | 42.50 | 10.51 | 4.0x |
| SHA-256 fingerprint (server.pem) | 42.27 | 10.61 | 4.0x |
| SHA-256 fingerprint (many-extensions.pem) | 43.32 | 11.69 | 3.7x |
| PEM to DER (root-ca.pem) | 43.07 | 10.78 | 4.0x |
| PEM to DER (server.pem) | 43.70 | 10.07 | 4.3x |
| PEM to DER (many-extensions.pem) | 43.65 | 9.86 | 4.4x |
| DER parse + text display (root-ca.der) | 43.30 | 9.59 | 4.5x |
| Hostname check (server.pem) | 43.14 | 9.86 | 4.4x |

**Summary:** xcert is **3.7x -- 4.5x faster** than `openssl x509` across all
operations. Both tools are dominated by process startup overhead, but the xcert
binary is significantly lighter (~4 MB static vs OpenSSL's dynamic linking and
larger initialization path).

## Running benchmarks

**OpenSSL baseline:**

```bash
bash bench/openssl-baseline.sh
```

**xcert benchmarks:**

```bash
cargo build --release

time target/release/xcert show testdata/certs/server.pem > /dev/null
time target/release/xcert field fingerprint testdata/certs/server.pem > /dev/null
time target/release/xcert check host www.example.com testdata/certs/server.pem
```

Detailed OpenSSL baseline data is in [`docs/performance-baseline.md`](docs/performance-baseline.md).
