#!/usr/bin/env bash
set -euo pipefail

if (( BASH_VERSINFO[0] < 4 )); then
    echo "These checks and crypto-audit.sh require Bash 4 or later." >&2
    exit 1
fi

for tool in java javac; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'Missing %s: run these checks with a JDK on PATH.\n' "$tool" >&2
        exit 1
    fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/crypto-audit-tests.XXXXXX")
trap 'rm -rf -- "$TEST_DIR"' EXIT

assert_contains() {
    if ! grep -Fq -- "$2" "$1"; then
        printf 'FAIL: expected "%s" in %s\n' "$2" "$1" >&2
        cat "$1" >&2
        exit 1
    fi
}

assert_release_neutral_guidance() {
    if grep -iE '(jdk|java([[:space:]]+se)?)[[:space:]]*[0-9]+|jep[[:space:]]*[0-9]+' "$1" >&2; then
        printf 'FAIL: release-specific guidance in %s\n' "$1" >&2
        exit 1
    fi
}

mkdir -p "$TEST_DIR/bin" "$TEST_DIR/project/src" "$TEST_DIR/classes"
cat > "$TEST_DIR/bin/java" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${AUDIT_TEST_JAVA_CALLS_FILE:?}"
if [ "$#" -ne 1 ] || [ "${1:-}" != -version ]; then
    printf 'Unexpected java invocation: %s\n' "$*" >&2
    exit 2
fi
if [ "${AUDIT_TEST_JAVA_VERSION:?}" = unavailable ]; then
    echo "Java runtime unavailable" >&2
    exit 1
fi
printf 'openjdk version "%s"\n' "$AUDIT_TEST_JAVA_VERSION" >&2
EOF
chmod +x "$TEST_DIR/bin/java"

cat > "$TEST_DIR/project/src/CryptoUsage.java" <<'EOF'
class CryptoUsage {
    void useCrypto() throws Exception {
        java.security.Signature.getInstance("SHA256withRSA");
        javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        javax.crypto.Mac.getInstance("HmacSHA256");
        // KeyPairGenerator.getInstance("RSA");
    }
}
EOF

# These are version-report mocks, not executions on the named JDK builds.
printf '%s\n' '-version' > "$TEST_DIR/expected-java-calls"
for version in 1.8.0_482 17.0.16 25 26 27 28-ea 99-internal unavailable; do
    : > "$TEST_DIR/java-calls"
    PATH="$TEST_DIR/bin:$PATH" AUDIT_TEST_JAVA_VERSION="$version" \
        AUDIT_TEST_JAVA_CALLS_FILE="$TEST_DIR/java-calls" \
        "$BASH" "$SCRIPT_DIR/crypto-audit.sh" "$TEST_DIR/project" > "$TEST_DIR/raw-output" 2>&1 || {
            cat "$TEST_DIR/raw-output" >&2
            exit 1
        }
    diff -u "$TEST_DIR/expected-java-calls" "$TEST_DIR/java-calls"
    sed $'s/\033\\[[0-9;]*m//g' "$TEST_DIR/raw-output" > "$TEST_DIR/output"

    assert_contains "$TEST_DIR/output" "Total crypto usage points found: 4"
    assert_contains "$TEST_DIR/output" "QUANTUM-VULNERABLE (requires PQC migration): 1"
    assert_contains "$TEST_DIR/output" "ATTENTION (review recommended): 1"
    assert_contains "$TEST_DIR/output" "LOW-RISK (minimal quantum impact): 2"
    assert_contains "$TEST_DIR/output" "comment-only references detected (not counted as findings)"
    assert_contains "$TEST_DIR/output" "PQC algorithms and hybrid TLS named groups"
    assert_contains "$TEST_DIR/output" "Static findings do not prove runtime capability or negotiated TLS groups."
    if [ "$version" = unavailable ]; then
        assert_contains "$TEST_DIR/output" "Java runtime unavailable"
    else
        assert_contains "$TEST_DIR/output" "openjdk version \"$version\""
    fi

    sed -n '/^PQC CRYPTOGRAPHIC AUDIT SUMMARY$/,$p' "$TEST_DIR/output" > "$TEST_DIR/summary"
    assert_release_neutral_guidance "$TEST_DIR/summary"

    if [ -f "$TEST_DIR/baseline-summary" ]; then
        diff -u "$TEST_DIR/baseline-summary" "$TEST_DIR/summary"
    else
        cp "$TEST_DIR/summary" "$TEST_DIR/baseline-summary"
    fi
done

"$BASH" "$SCRIPT_DIR/crypto-audit.sh" --help > "$TEST_DIR/help"
assert_contains "$TEST_DIR/help" "No JDK release is assumed for the static scan."

cat > "$TEST_DIR/AuditGuidanceTest.java" <<'EOF'
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;

public class AuditGuidanceTest {
    public static void main(String[] args) {
        Provider[] originalProviders = Security.getProviders();
        try {
            for (Provider provider : originalProviders) {
                Security.removeProvider(provider.getName());
            }
            checkJceGuidance(false);

            // Enumeration must depend on registrations, not a JDK release number.
            Provider provider = new Provider("AuditTest", "1.0", "Test-only inventory") {};
            provider.put("Signature.ML-DSA", "UnusedImplementation");
            Security.addProvider(provider);
            checkJceGuidance(true);
        } finally {
            Security.removeProvider("AuditTest");
            for (Provider provider : originalProviders) {
                Security.addProvider(provider);
            }
        }

        checkReplacement("RSA", "ML-DSA for signatures, or ML-KEM for key establishment / wrapping");
        for (String algorithm : new String[]{"ECDSA", "ED25519", "ED448"}) {
            checkReplacement(algorithm, "ML-DSA-44 or ML-DSA-65 for signatures");
        }
        for (String algorithm : new String[]{"ECDH", "DH", "X25519", "X448"}) {
            checkReplacement(algorithm, "ML-KEM-768 or ML-KEM-1024 for key establishment");
        }
        checkReplacement("DSA", "ML-DSA-44 for signatures");
        checkReplacement("UNKNOWN", "Consult FIPS 203 / 204 / 205 and separate signature vs key-establishment migration");
    }

    private static void checkJceGuidance(boolean expectPqc) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        PrintStream originalOut = System.out;
        try (PrintStream capture = new PrintStream(bytes, true, StandardCharsets.UTF_8)) {
            System.setOut(capture);
            CryptoAuditJce.main(new String[0]);
        } finally {
            System.setOut(originalOut);
        }
        String report = bytes.toString(StandardCharsets.UTF_8);
        require(report.contains("Recognized PQC algorithm services registered") == expectPqc,
                "PQC guidance must follow the registered provider services");
        require(report.contains("No recognized PQC algorithms registered") != expectPqc,
                "Missing PQC support must be reported without assuming a JDK release");
        if (!expectPqc) {
            require(report.contains("(none recognized in the current provider inventory)"),
                    "Empty inventory must not imply a release-specific upgrade");
            require(report.contains("configure a provider supplying ML-KEM/ML-DSA"),
                    "Missing PQC support must have actionable provider guidance");
        }
        require(report.contains("target JSSE provider and configuration"),
                "TLS guidance must consider the provider and configuration");
        require(report.contains("Algorithm registration does not prove application use or TLS negotiation"),
                "Inventory must not be presented as runtime evidence");
        int start = report.indexOf("RECOMMENDATIONS:");
        require(start >= 0, "Missing JCE recommendations");
        String guidance = report.substring(start);
        require(!guidance.matches("(?is).*(?:jdk|java(?:\\s+se)?|jep)\\s*[0-9]+.*"),
                "Release-specific JCE guidance: " + guidance);
    }

    private static void checkReplacement(String algorithm, String expected) {
        require(expected.equals(KeystoreAudit.suggestPqcReplacement(algorithm)),
                "Unexpected replacement guidance for " + algorithm);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
EOF

javac -d "$TEST_DIR/classes" "$SCRIPT_DIR/CryptoAuditJce.java" \
    "$SCRIPT_DIR/KeystoreAudit.java" "$SCRIPT_DIR/../../ciphercheck-demo/CipherSuiteCheck.java" \
    "$TEST_DIR/AuditGuidanceTest.java"
java -cp "$TEST_DIR/classes" AuditGuidanceTest

for named_groups in default x25519; do
    tls_java_args=(-cp "$TEST_DIR/classes")
    if [ "$named_groups" != default ]; then
        tls_java_args+=("-Djdk.tls.namedGroups=$named_groups")
    fi
    java "${tls_java_args[@]}" CipherSuiteCheck > "$TEST_DIR/tls-raw-output"
    sed $'s/\033\\[[0-9;]*m//g' "$TEST_DIR/tls-raw-output" > "$TEST_DIR/tls-output"
    assert_contains "$TEST_DIR/tls-output" "RECOMMENDATIONS:"
    assert_contains "$TEST_DIR/tls-output" "local capability alone is not handshake evidence"
    if grep -Eq 'Post-Quantum:[[:space:]]+[1-9][0-9]*$' "$TEST_DIR/tls-output"; then
        assert_contains "$TEST_DIR/tls-output" "Recognized PQC named groups reported"
    else
        assert_contains "$TEST_DIR/tls-output" "No recognized PQC named groups reported"
    fi
    if [ "$named_groups" = x25519 ]; then
        assert_contains "$TEST_DIR/tls-output" "No recognized PQC named groups reported"
    fi
    sed -n '/^  RECOMMENDATIONS:$/,$p' "$TEST_DIR/tls-output" > "$TEST_DIR/tls-guidance"
    assert_release_neutral_guidance "$TEST_DIR/tls-guidance"
done

echo "PASS: static results are release-independent; companion guidance follows provider capabilities."
