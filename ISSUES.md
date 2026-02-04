# Known Issues

All issues identified during code review have been resolved.

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
