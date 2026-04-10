#!/bin/bash
# =============================================================================
# Generate a test PKCS12 keystore with a local-CA-signed RSA-2048 certificate chain
# =============================================================================
#
# CRYPTO AUDIT POINT — X.509 certificate with RSA-2048 key
#
# This keystore contains:
#   - An RSA-2048 server private key (quantum-vulnerable via Shor's algorithm)
#   - A SHA256withRSA server certificate for localhost
#   - A local demo CA certificate that signs the server certificate
#
# Quantum vulnerability:
#   - The RSA-2048 key can be broken by a sufficiently large quantum computer.
#   - The SHA256withRSA signature on the cert is also quantum-vulnerable
#     (the RSA part, not the SHA-256 part).
#
# PQC migration path:
#   - Replace with ML-DSA (Dilithium) certificate when CAs begin issuing them.
#   - Use hybrid certificates (RSA + ML-DSA) during transition.
#   - Java 24+ includes ML-DSA support via the SunEC provider.
#
# Usage:
#   cd src/main/resources
#   bash generate-keystore.sh
# =============================================================================

set -euo pipefail

echo "Generating local-CA-signed RSA-2048 keystore for TLS demo..."
echo "WARNING: RSA-2048 and SHA256withRSA remain quantum-vulnerable. This is intentional for the audit demo."
echo ""

TMP_DIR=$(mktemp -d)
CA_KEYSTORE="$TMP_DIR/demo-ca.p12"
CA_CERT="$TMP_DIR/demo-ca.pem"
SERVER_CSR="$TMP_DIR/server.csr"
SERVER_CERT="$TMP_DIR/server-cert.pem"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

rm -f keystore.p12

keytool -genkeypair \
  -alias demo-ca \
  -keyalg RSA \
  -keysize 2048 \
  -sigalg SHA256withRSA \
  -dname "CN=PQC Demo Local CA, OU=PQC Demo, O=Example Corp, L=Oslo, ST=Oslo, C=NO" \
  -validity 3650 \
  -ext bc:c \
  -storetype PKCS12 \
  -keystore "$CA_KEYSTORE" \
  -storepass changeit \
  -keypass changeit \
  -noprompt

keytool -exportcert \
  -alias demo-ca \
  -keystore "$CA_KEYSTORE" \
  -storepass changeit \
  -rfc \
  -file "$CA_CERT"

keytool -genkeypair \
  -alias server \
  -keyalg RSA \
  -keysize 2048 \
  -sigalg SHA256withRSA \
  -dname "CN=localhost, OU=PQC Demo, O=Example Corp, L=Oslo, ST=Oslo, C=NO" \
  -validity 825 \
  -ext san=dns:localhost,ip:127.0.0.1 \
  -ext eku=serverAuth \
  -storetype PKCS12 \
  -keystore keystore.p12 \
  -storepass changeit \
  -keypass changeit \
  -noprompt

keytool -certreq \
  -alias server \
  -keystore keystore.p12 \
  -storepass changeit \
  -file "$SERVER_CSR" \
  -ext san=dns:localhost,ip:127.0.0.1 \
  -ext eku=serverAuth

keytool -gencert \
  -alias demo-ca \
  -keystore "$CA_KEYSTORE" \
  -storepass changeit \
  -infile "$SERVER_CSR" \
  -outfile "$SERVER_CERT" \
  -rfc \
  -sigalg SHA256withRSA \
  -validity 825 \
  -ext san=dns:localhost,ip:127.0.0.1 \
  -ext eku=serverAuth

keytool -importcert \
  -alias demo-ca \
  -file "$CA_CERT" \
  -keystore keystore.p12 \
  -storepass changeit \
  -noprompt

keytool -importcert \
  -alias server \
  -file "$SERVER_CERT" \
  -keystore keystore.p12 \
  -storepass changeit \
  -noprompt

echo ""
echo "Keystore generated: keystore.p12"
echo ""
echo "Certificate details:"
keytool -list -v -keystore keystore.p12 -storepass changeit | head -20

echo ""
echo "Crypto algorithms used (all quantum-vulnerable):"
echo "  - Root CA algorithm:   RSA-2048 / SHA256withRSA"
echo "  - Server key:          RSA-2048"
echo "  - Server signature:    SHA256withRSA"
echo "  - Keystore format:     PKCS12"
echo ""
echo "For PQC-safe alternative, generate with ML-DSA (Java 24+):"
echo "  keytool -genkeypair -alias server -keyalg ML-DSA -keysize 65 \\"
echo "    -dname 'CN=localhost' -validity 365 \\"
echo "    -storetype PKCS12 -keystore keystore-pqc.p12 -storepass changeit"
