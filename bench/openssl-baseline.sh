#!/usr/bin/env bash
#
# OpenSSL x509 performance baseline benchmark
# Measures wall-clock time for common x509 operations over 1000 iterations.
# Uses date +%s%N for nanosecond-precision timing.
#

set -euo pipefail

ITERATIONS=1000
CERT_DIR="/home/user/xcert-rs/tests/certs"
OPENSSL_VERSION="$(openssl version)"

# CSV-style accumulator: "description|cert|iterations|total_ns"
declare -a RESULTS=()

# bench <description> <command...>
#   Runs <command> $ITERATIONS times, records total elapsed nanoseconds.
bench() {
    local desc="$1"; shift
    local cert_label="$1"; shift

    # Warm-up: run once to populate filesystem cache
    "$@" >/dev/null 2>&1 || true

    local start end elapsed
    start=$(date +%s%N)
    for (( i=0; i<ITERATIONS; i++ )); do
        "$@" >/dev/null 2>&1
    done
    end=$(date +%s%N)
    elapsed=$(( end - start ))

    RESULTS+=("${desc}|${cert_label}|${ITERATIONS}|${elapsed}")

    local avg_ms
    avg_ms=$(awk "BEGIN {printf \"%.4f\", ${elapsed} / ${ITERATIONS} / 1000000}")
    local total_ms
    total_ms=$(awk "BEGIN {printf \"%.2f\", ${elapsed} / 1000000}")
    printf "  %-45s %-22s %s iterations  total %8s ms  avg %s ms/op\n" \
        "$desc" "$cert_label" "$ITERATIONS" "$total_ms" "$avg_ms"
}

echo "============================================================"
echo "  OpenSSL x509 Performance Baseline"
echo "  ${OPENSSL_VERSION}"
echo "  Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "  Iterations per benchmark: ${ITERATIONS}"
echo "============================================================"
echo ""

# ── 1. Parse + text display ──────────────────────────────────────
echo "[1/6] Parse + text display (x509 -text -noout)"
bench "Parse + text display" "root-ca.pem" \
    openssl x509 -in "${CERT_DIR}/root-ca.pem" -text -noout

bench "Parse + text display" "server.pem" \
    openssl x509 -in "${CERT_DIR}/server.pem" -text -noout

bench "Parse + text display" "many-extensions.pem" \
    openssl x509 -in "${CERT_DIR}/many-extensions.pem" -text -noout
echo ""

# ── 2. Parse + subject extraction ────────────────────────────────
echo "[2/6] Parse + subject extraction (x509 -subject -noout)"
bench "Parse + subject extraction" "root-ca.pem" \
    openssl x509 -in "${CERT_DIR}/root-ca.pem" -subject -noout

bench "Parse + subject extraction" "server.pem" \
    openssl x509 -in "${CERT_DIR}/server.pem" -subject -noout

bench "Parse + subject extraction" "many-extensions.pem" \
    openssl x509 -in "${CERT_DIR}/many-extensions.pem" -subject -noout
echo ""

# ── 3. Parse + SHA-256 fingerprint ───────────────────────────────
echo "[3/6] Parse + SHA-256 fingerprint (x509 -fingerprint -sha256 -noout)"
bench "SHA-256 fingerprint" "root-ca.pem" \
    openssl x509 -in "${CERT_DIR}/root-ca.pem" -fingerprint -sha256 -noout

bench "SHA-256 fingerprint" "server.pem" \
    openssl x509 -in "${CERT_DIR}/server.pem" -fingerprint -sha256 -noout

bench "SHA-256 fingerprint" "many-extensions.pem" \
    openssl x509 -in "${CERT_DIR}/many-extensions.pem" -fingerprint -sha256 -noout
echo ""

# ── 4. PEM to DER conversion ─────────────────────────────────────
echo "[4/6] PEM to DER conversion (x509 -outform DER -out /dev/null)"
bench "PEM to DER conversion" "root-ca.pem" \
    openssl x509 -in "${CERT_DIR}/root-ca.pem" -outform DER -out /dev/null

bench "PEM to DER conversion" "server.pem" \
    openssl x509 -in "${CERT_DIR}/server.pem" -outform DER -out /dev/null

bench "PEM to DER conversion" "many-extensions.pem" \
    openssl x509 -in "${CERT_DIR}/many-extensions.pem" -outform DER -out /dev/null
echo ""

# ── 5. DER parsing ───────────────────────────────────────────────
echo "[5/6] DER parsing (x509 -inform DER -text -noout)"
bench "DER parse + text display" "root-ca.der" \
    openssl x509 -in "${CERT_DIR}/root-ca.der" -inform DER -text -noout
echo ""

# ── 6. Parse + hostname check ────────────────────────────────────
echo "[6/6] Parse + hostname check (x509 -checkhost)"
bench "Hostname check (match)" "server.pem" \
    openssl x509 -in "${CERT_DIR}/server.pem" -checkhost www.example.com -noout
echo ""

echo "============================================================"
echo "  All benchmarks complete."
echo "============================================================"

# ── Emit machine-readable CSV for post-processing ────────────────
CSV_FILE="/tmp/openssl-bench-results.csv"
{
    echo "description,certificate,iterations,total_ns"
    for r in "${RESULTS[@]}"; do
        IFS='|' read -r desc cert iters total_ns <<< "$r"
        echo "${desc},${cert},${iters},${total_ns}"
    done
} > "${CSV_FILE}"
echo ""
echo "Raw CSV written to ${CSV_FILE}"
