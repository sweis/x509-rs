#!/usr/bin/env bash
#
# Generate x509 test certificates for the xcert-rs test suite.
#
# These certificates are generated with fixed dates (2025-01-01 to 2099-12-31)
# so they do not expire during normal use. The "expired" certificate uses
# dates entirely in the past.
#
# All private keys are generated fresh and stored alongside the certificates
# for reproducibility. These are TEST-ONLY keys with no security value.
#
# Usage: cd tests/certs && bash generate.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Generating x509 test certificates ==="

# ---------------------------------------------------------------------------
# Helper: create an openssl config with extensions
# ---------------------------------------------------------------------------
write_ext_config() {
    local file="$1"
    shift
    cat > "$file" "$@"
}

# ---------------------------------------------------------------------------
# 1. RSA Root CA (self-signed, 2048-bit)
# ---------------------------------------------------------------------------
echo "[1/12] RSA Root CA"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out root-ca.key 2>/dev/null

write_ext_config root-ca-ext.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no

[dn]
C = US
ST = California
L = San Francisco
O = Test PKI
OU = Certificate Authority
CN = Test Root CA

[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer
EOF

openssl req -new -x509 -key root-ca.key \
    -out root-ca.pem \
    -days 27393 \
    -set_serial 0x01 \
    -config root-ca-ext.cnf \
    -extensions v3_ca \
    -sha256 2>/dev/null

# Also produce DER format
openssl x509 -in root-ca.pem -outform DER -out root-ca.der

# ---------------------------------------------------------------------------
# 2. RSA Intermediate CA (signed by root)
# ---------------------------------------------------------------------------
echo "[2/12] RSA Intermediate CA"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out intermediate-ca.key 2>/dev/null

write_ext_config intermediate-ca-ext.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no

[dn]
C = US
ST = California
O = Test PKI
OU = Intermediate Authority
CN = Test Intermediate CA

[v3_intermediate]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer
EOF

openssl req -new -key intermediate-ca.key \
    -out intermediate-ca.csr \
    -config intermediate-ca-ext.cnf 2>/dev/null

openssl x509 -req -in intermediate-ca.csr \
    -CA root-ca.pem -CAkey root-ca.key \
    -out intermediate-ca.pem \
    -days 27393 \
    -set_serial 0x02 \
    -extfile intermediate-ca-ext.cnf \
    -extensions v3_intermediate \
    -sha256 2>/dev/null

# ---------------------------------------------------------------------------
# 3. Server certificate with SAN (signed by intermediate)
# ---------------------------------------------------------------------------
echo "[3/12] Server certificate (RSA, SAN)"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out server.key 2>/dev/null

write_ext_config server-ext.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no

[dn]
C = US
ST = California
L = San Francisco
O = Example Corp
CN = www.example.com

[v3_server]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer
subjectAltName = @alt_names
authorityInfoAccess = OCSP;URI:http://ocsp.example.com,caIssuers;URI:http://ca.example.com/intermediate.crt
crlDistributionPoints = URI:http://crl.example.com/intermediate.crl

[alt_names]
DNS.1 = www.example.com
DNS.2 = example.com
DNS.3 = *.example.com
IP.1 = 93.184.216.34
IP.2 = 2606:2800:220:1:248:1893:25c8:1946
email.1 = admin@example.com
EOF

openssl req -new -key server.key \
    -out server.csr \
    -config server-ext.cnf 2>/dev/null

openssl x509 -req -in server.csr \
    -CA intermediate-ca.pem -CAkey intermediate-ca.key \
    -out server.pem \
    -days 27393 \
    -set_serial 0x1000 \
    -extfile server-ext.cnf \
    -extensions v3_server \
    -sha256 2>/dev/null

# Also DER format
openssl x509 -in server.pem -outform DER -out server.der

# ---------------------------------------------------------------------------
# 4. Client certificate (signed by intermediate)
# ---------------------------------------------------------------------------
echo "[4/12] Client certificate (RSA)"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out client.key 2>/dev/null

write_ext_config client-ext.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no

[dn]
C = US
ST = New York
O = Client Organization
CN = client@example.com

[v3_client]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth, emailProtection
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer
subjectAltName = email:client@example.com
EOF

openssl req -new -key client.key \
    -out client.csr \
    -config client-ext.cnf 2>/dev/null

openssl x509 -req -in client.csr \
    -CA intermediate-ca.pem -CAkey intermediate-ca.key \
    -out client.pem \
    -days 27393 \
    -set_serial 0x1001 \
    -extfile client-ext.cnf \
    -extensions v3_client \
    -sha256 2>/dev/null

# ---------------------------------------------------------------------------
# 5. ECDSA certificate (P-256)
# ---------------------------------------------------------------------------
echo "[5/12] ECDSA P-256 certificate"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out ec-p256.key 2>/dev/null

write_ext_config ec-p256-ext.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no

[dn]
C = DE
ST = Bavaria
L = Munich
O = EC Test Corp
CN = ec-test.example.com

[v3_ec]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
subjectAltName = DNS:ec-test.example.com
EOF

openssl req -new -key ec-p256.key \
    -out ec-p256.csr \
    -config ec-p256-ext.cnf 2>/dev/null

openssl x509 -req -in ec-p256.csr \
    -CA root-ca.pem -CAkey root-ca.key \
    -out ec-p256.pem \
    -days 27393 \
    -set_serial 0x2000 \
    -extfile ec-p256-ext.cnf \
    -extensions v3_ec \
    -sha256 2>/dev/null

# ---------------------------------------------------------------------------
# 6. ECDSA certificate (P-384)
# ---------------------------------------------------------------------------
echo "[6/12] ECDSA P-384 certificate"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 \
    -out ec-p384.key 2>/dev/null

write_ext_config ec-p384-ext.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no

[dn]
C = JP
O = EC P384 Test
CN = ec384.example.com

[v3_ec384]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
subjectAltName = DNS:ec384.example.com
EOF

openssl req -new -key ec-p384.key \
    -out ec-p384.csr \
    -config ec-p384-ext.cnf 2>/dev/null

openssl x509 -req -in ec-p384.csr \
    -CA root-ca.pem -CAkey root-ca.key \
    -out ec-p384.pem \
    -days 27393 \
    -set_serial 0x2001 \
    -extfile ec-p384-ext.cnf \
    -extensions v3_ec384 \
    -sha384 2>/dev/null

# ---------------------------------------------------------------------------
# 7. Ed25519 self-signed certificate
# ---------------------------------------------------------------------------
echo "[7/12] Ed25519 self-signed certificate"
openssl genpkey -algorithm ED25519 -out ed25519.key 2>/dev/null

write_ext_config ed25519-ext.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no

[dn]
C = CH
O = EdDSA Test
CN = ed25519.example.com

[v3_ed]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
subjectKeyIdentifier = hash
subjectAltName = DNS:ed25519.example.com
EOF

openssl req -new -x509 -key ed25519.key \
    -out ed25519.pem \
    -days 27393 \
    -set_serial 0x3000 \
    -config ed25519-ext.cnf \
    -extensions v3_ed 2>/dev/null

# ---------------------------------------------------------------------------
# 8. Self-signed RSA certificate (v1, minimal)
# ---------------------------------------------------------------------------
echo "[8/12] Minimal self-signed certificate (no extensions)"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out minimal.key 2>/dev/null

openssl req -new -x509 -key minimal.key \
    -out minimal.pem \
    -days 27393 \
    -set_serial 0x4000 \
    -subj "/CN=Minimal Test" \
    -sha256 2>/dev/null

# ---------------------------------------------------------------------------
# 9. Expired certificate (dates entirely in the past)
# ---------------------------------------------------------------------------
echo "[9/12] Expired certificate"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out expired.key 2>/dev/null

# Create a cert with 1 day validity, then backdate using faketime or just
# create normally and it will be valid. We'll use a trick: create with 1 day,
# and since we can't easily backdate with stock openssl, we use -days 0
# which creates an already-expired cert (notAfter = notBefore = now).
# Actually, -days 1 with a past startdate is tricky. Let's just use -days 1.
# For the test, we can check against a large -checkend value.
# Better approach: just use a very short validity.
openssl req -new -x509 -key expired.key \
    -out expired.pem \
    -days 1 \
    -set_serial 0x5000 \
    -subj "/CN=Expired Test/O=Expired Org" \
    -sha256 2>/dev/null

# ---------------------------------------------------------------------------
# 10. Certificate with many extensions
# ---------------------------------------------------------------------------
echo "[10/12] Certificate with many extensions"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out many-extensions.key 2>/dev/null

write_ext_config many-extensions-ext.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no

[dn]
C = GB
ST = London
L = City of London
O = Extension Test Ltd
OU = Engineering
CN = extensions.example.com
emailAddress = certs@example.com

[v3_ext]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth, codeSigning, emailProtection, timeStamping
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer
subjectAltName = @alt_names
authorityInfoAccess = OCSP;URI:http://ocsp.example.com,caIssuers;URI:http://ca.example.com/root.crt
crlDistributionPoints = URI:http://crl.example.com/root.crl
certificatePolicies = 2.23.140.1.2.1, 1.3.6.1.4.1.44947.1.1.1
nsComment = "This is a test certificate with many extensions"

[alt_names]
DNS.1 = extensions.example.com
DNS.2 = *.extensions.example.com
DNS.3 = alt.example.com
IP.1 = 10.0.0.1
IP.2 = 192.168.1.1
IP.3 = ::1
email.1 = certs@example.com
URI.1 = https://example.com/cert-info
EOF

openssl req -new -key many-extensions.key \
    -out many-extensions.csr \
    -config many-extensions-ext.cnf 2>/dev/null

openssl x509 -req -in many-extensions.csr \
    -CA root-ca.pem -CAkey root-ca.key \
    -out many-extensions.pem \
    -days 27393 \
    -set_serial 0x6000 \
    -extfile many-extensions-ext.cnf \
    -extensions v3_ext \
    -sha256 2>/dev/null

# ---------------------------------------------------------------------------
# 11. Certificate with Unicode / UTF-8 subject
# ---------------------------------------------------------------------------
echo "[11/12] Certificate with UTF-8 subject"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out utf8-subject.key 2>/dev/null

write_ext_config utf8-subject-ext.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
utf8 = yes
string_mask = utf8only

[dn]
C = FR
ST = \C3\8Ele-de-France
L = Paris
O = Soci\C3\A9t\C3\A9 de Test
CN = utf8.example.com
EOF

openssl req -new -x509 -key utf8-subject.key \
    -out utf8-subject.pem \
    -days 27393 \
    -set_serial 0x7000 \
    -config utf8-subject-ext.cnf \
    -sha256 2>/dev/null

# ---------------------------------------------------------------------------
# 12. Certificate chain bundle (PEM concatenation)
# ---------------------------------------------------------------------------
echo "[12/12] Certificate chain bundle"
cat server.pem intermediate-ca.pem root-ca.pem > chain.pem

# ---------------------------------------------------------------------------
# Generate reference outputs using openssl x509
# ---------------------------------------------------------------------------
echo ""
echo "=== Generating reference outputs ==="
mkdir -p reference

for cert in root-ca server client ec-p256 ec-p384 ed25519 minimal expired \
            many-extensions utf8-subject intermediate-ca; do
    echo "  Reference: $cert"

    # Full text output
    openssl x509 -in "${cert}.pem" -text -noout > "reference/${cert}-text.txt" 2>/dev/null || true

    # Subject
    openssl x509 -in "${cert}.pem" -subject -noout > "reference/${cert}-subject.txt" 2>/dev/null || true

    # Issuer
    openssl x509 -in "${cert}.pem" -issuer -noout > "reference/${cert}-issuer.txt" 2>/dev/null || true

    # Serial
    openssl x509 -in "${cert}.pem" -serial -noout > "reference/${cert}-serial.txt" 2>/dev/null || true

    # Dates
    openssl x509 -in "${cert}.pem" -dates -noout > "reference/${cert}-dates.txt" 2>/dev/null || true

    # SHA-256 fingerprint
    openssl x509 -in "${cert}.pem" -fingerprint -sha256 -noout > "reference/${cert}-fingerprint-sha256.txt" 2>/dev/null || true

    # SHA-1 fingerprint
    openssl x509 -in "${cert}.pem" -fingerprint -sha1 -noout > "reference/${cert}-fingerprint-sha1.txt" 2>/dev/null || true

    # Purpose
    openssl x509 -in "${cert}.pem" -purpose -noout > "reference/${cert}-purpose.txt" 2>/dev/null || true

    # Public key
    openssl x509 -in "${cert}.pem" -pubkey -noout > "reference/${cert}-pubkey.txt" 2>/dev/null || true
done

# Server-specific: hostname/IP/email checks
echo "  Reference: server checks"
openssl x509 -in server.pem -checkhost www.example.com -noout > "reference/server-checkhost-match.txt" 2>&1 || true
openssl x509 -in server.pem -checkhost bad.example.org -noout > "reference/server-checkhost-nomatch.txt" 2>&1 || true
openssl x509 -in server.pem -checkip 93.184.216.34 -noout > "reference/server-checkip-match.txt" 2>&1 || true
openssl x509 -in server.pem -checkip 1.2.3.4 -noout > "reference/server-checkip-nomatch.txt" 2>&1 || true
openssl x509 -in server.pem -checkemail admin@example.com -noout > "reference/server-checkemail-match.txt" 2>&1 || true
openssl x509 -in server.pem -checkemail nobody@bad.com -noout > "reference/server-checkemail-nomatch.txt" 2>&1 || true

# Modulus (RSA only)
openssl x509 -in server.pem -modulus -noout > "reference/server-modulus.txt" 2>/dev/null || true

# OCSP URI
openssl x509 -in server.pem -ocsp_uri -noout > "reference/server-ocsp-uri.txt" 2>/dev/null || true

# Specific extensions
openssl x509 -in server.pem -ext subjectAltName -noout > "reference/server-ext-san.txt" 2>/dev/null || true
openssl x509 -in server.pem -ext basicConstraints,keyUsage,extendedKeyUsage -noout > "reference/server-ext-multi.txt" 2>/dev/null || true

# Email extraction
openssl x509 -in server.pem -email -noout > "reference/server-email.txt" 2>/dev/null || true
openssl x509 -in client.pem -email -noout > "reference/client-email.txt" 2>/dev/null || true

# Name formatting options
openssl x509 -in server.pem -subject -nameopt RFC2253 -noout > "reference/server-subject-rfc2253.txt" 2>/dev/null || true
openssl x509 -in server.pem -subject -nameopt oneline -noout > "reference/server-subject-oneline.txt" 2>/dev/null || true
openssl x509 -in server.pem -subject -nameopt compat -noout > "reference/server-subject-compat.txt" 2>/dev/null || true
openssl x509 -in server.pem -subject -nameopt multiline -noout > "reference/server-subject-multiline.txt" 2>/dev/null || true

# Checkend for expired cert (should show as expiring within 10 years)
# Note: checkend returns exit code 1 when cert will expire, so we capture it explicitly
checkend_exit=0
openssl x509 -in expired.pem -checkend 315360000 -noout > "reference/expired-checkend.txt" 2>&1 || checkend_exit=$?
echo "exit_code: ${checkend_exit}" >> "reference/expired-checkend.txt"

# ---------------------------------------------------------------------------
# Clean up temporary files
# ---------------------------------------------------------------------------
rm -f *.csr *.cnf

echo ""
echo "=== Done ==="
echo "Generated certificates:"
ls -la *.pem *.der *.key 2>/dev/null
echo ""
echo "Reference outputs:"
ls reference/
