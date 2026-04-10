#!/usr/bin/env bash
# ============================================================================
# PQC Cryptographic Audit Script
#
# Scans a Java project to discover all cryptographic usage points
# and identifies quantum-vulnerable algorithms that need PQC migration.
#
# Supports: Maven and Gradle projects
# Frameworks: Spring Boot, Quarkus, Micronaut, Jakarta EE, plain Java
#
# Usage: ./crypto-audit.sh [--phase-pause | --phase-pause-seconds N] [project-dir]
#
# Three-phase audit:
#   Phase 1: Dependency scan — crypto libraries in the dependency tree
#   Phase 2: Source code scan — JCE/JCA API calls + framework patterns
#   Phase 3: Keystore audit — X.509 certificates and key algorithms
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# ANSI colour codes (presentation-friendly)
# ---------------------------------------------------------------------------
RED='\033[1;31m'
YELLOW='\033[1;33m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
MAGENTA='\033[1;35m'
BLUE='\033[1;34m'
WHITE='\033[1;37m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

# Emoji risk tags
VULN="${RED}🔴 QUANTUM-VULNERABLE${RESET}"
ATTN="${YELLOW}🟡 ATTENTION${RESET}"
LOW="${GREEN}🟢 LOW-RISK${RESET}"

# ---------------------------------------------------------------------------
# Globals — counters for the summary
# ---------------------------------------------------------------------------
declare -a FINDINGS_VULN=()
declare -a FINDINGS_ATTN=()
declare -a FINDINGS_LOW=()

# ---------------------------------------------------------------------------
# Helper: banner / section header
# ---------------------------------------------------------------------------
banner() {
    echo ""
    echo -e "${CYAN}============================================================${RESET}"
    echo -e "${WHITE}$1${RESET}"
    echo -e "${CYAN}============================================================${RESET}"
    echo ""
}

section() {
    echo ""
    echo -e "  ${MAGENTA}────────────────────────────────────────────────${RESET}"
    echo -e "  ${BOLD}$1${RESET}"
    echo -e "  ${MAGENTA}────────────────────────────────────────────────${RESET}"
}

finding_vuln() {
    echo -e "    ${RED}🔴${RESET} $1"
    FINDINGS_VULN+=("$1")
}

finding_attn() {
    echo -e "    ${YELLOW}🟡${RESET} $1"
    FINDINGS_ATTN+=("$1")
}

finding_low() {
    echo -e "    ${GREEN}🟢${RESET} $1"
    FINDINGS_LOW+=("$1")
}

info() {
    echo -e "    ${DIM}ℹ  $1${RESET}"
}

usage() {
    cat <<EOF
Usage: $(basename "$0") [--phase-pause | --phase-pause-seconds N] [project-dir]

Options:
  --phase-pause             Wait for Enter between major phases
  --phase-pause-seconds N   Sleep N seconds between major phases
  -h, --help                Show this help
EOF
}

PHASE_PAUSE_WARNING_EMITTED=0

pause_between_phases() {
    local next_phase="$1"

    case "${PHASE_PAUSE_MODE:-off}" in
        prompt)
            if [ -r /dev/tty ]; then
                echo ""
                echo -e "  ${DIM}Paused before ${next_phase}.${RESET}"
                read -r -p "  Press Enter to continue... " < /dev/tty
                echo ""
            elif [ "$PHASE_PAUSE_WARNING_EMITTED" -eq 0 ]; then
                echo -e "  ${YELLOW}⚠  --phase-pause requested, but no interactive TTY is available — continuing without pauses${RESET}"
                PHASE_PAUSE_WARNING_EMITTED=1
            fi
            ;;
        sleep)
            if [ "${PHASE_PAUSE_SECONDS:-0}" -gt 0 ]; then
                echo ""
                echo -e "  ${DIM}Pausing ${PHASE_PAUSE_SECONDS}s before ${next_phase}...${RESET}"
                sleep "$PHASE_PAUSE_SECONDS"
                echo ""
            fi
            ;;
    esac
}

record_finding() {
    local risk="$1"
    local message="$2"

    case "$risk" in
        VULN) finding_vuln "$message" ;;
        ATTN) finding_attn "$message" ;;
        LOW)  finding_low  "$message" ;;
    esac
}

comment_syntax_mode() {
    local file="$1"

    case "$file" in
        *.java|*.kt|*.kts|*.groovy|*.scala) echo "java-like" ;;
        *.properties) echo "hash-bang" ;;
        *.yml|*.yaml) echo "hash" ;;
        *.xml) echo "xml" ;;
        *) echo "generic" ;;
    esac
}

classify_phase2_match() {
    local file="$1"
    local line_no="$2"
    local pattern="$3"
    local ignore_case="${4:-0}"
    local awk_pattern
    local mode

    awk_pattern="${pattern//\\/\\\\}"
    mode=$(comment_syntax_mode "$file")
    if [ "$mode" = "generic" ]; then
        echo "code"
        return
    fi

    awk -v target="$line_no" -v pattern="$awk_pattern" -v mode="$mode" -v ignore_case="$ignore_case" '
        function reset_spans(    i) {
            for (i in span_start) delete span_start[i]
            for (i in span_end) delete span_end[i]
            span_count = 0
        }

        function add_span(start, end) {
            if (start < 1) start = 1
            if (end < start) end = start
            span_count++
            span_start[span_count] = start
            span_end[span_count] = end
        }

        function match_is_in_comment(start, len,    end, i) {
            end = start + len - 1
            for (i = 1; i <= span_count; i++) {
                if (start >= span_start[i] && end <= span_end[i]) {
                    return 1
                }
            }
            return 0
        }

        function emit_classification(line,    cursor, absolute_start, match_len, has_match) {
            cursor = 1
            has_match = 0

            while (cursor <= length(line) && match(substr(line, cursor), pattern)) {
                has_match = 1
                absolute_start = cursor + RSTART - 1
                match_len = RLENGTH

                if (!match_is_in_comment(absolute_start, match_len)) {
                    print "code"
                    return
                }

                cursor = absolute_start + (match_len > 0 ? match_len : 1)
            }

            if (has_match) {
                print "comment"
            } else {
                print "code"
            }
        }

        function update_java_state(line,    pos, remaining, single_pos, block_pos, block_end_rel) {
            pos = 1

            if (in_block) {
                remaining = substr(line, pos)
                if (match(remaining, /\*\//)) {
                    pos += RSTART + RLENGTH - 1
                    in_block = 0
                } else {
                    return
                }
            }

            while (pos <= length(line)) {
                remaining = substr(line, pos)
                single_pos = match(remaining, /\/\//)
                block_pos = match(remaining, /\/\*/)

                if (single_pos && (!block_pos || single_pos < block_pos)) {
                    return
                }

                if (!block_pos) {
                    return
                }

                block_end_rel = match(substr(remaining, block_pos + 2), /\*\//)
                if (block_end_rel) {
                    pos = pos + block_pos + block_end_rel + 2
                } else {
                    in_block = 1
                    return
                }
            }
        }

        function analyse_java_line(line,    pos, remaining, single_pos, block_pos, block_end_rel, comment_start, comment_end) {
            reset_spans()
            pos = 1

            if (in_block) {
                remaining = substr(line, pos)
                if (match(remaining, /\*\//)) {
                    comment_end = pos + RSTART + RLENGTH - 2
                    add_span(pos, comment_end)
                    pos = comment_end + 1
                    in_block = 0
                } else {
                    add_span(pos, length(line))
                    return
                }
            }

            while (pos <= length(line)) {
                remaining = substr(line, pos)
                single_pos = match(remaining, /\/\//)
                block_pos = match(remaining, /\/\*/)

                if (single_pos && (!block_pos || single_pos < block_pos)) {
                    add_span(pos + single_pos - 1, length(line))
                    break
                }

                if (!block_pos) {
                    break
                }

                comment_start = pos + block_pos - 1
                block_end_rel = match(substr(remaining, block_pos + 2), /\*\//)

                if (block_end_rel) {
                    comment_end = comment_start + block_end_rel + 2
                    add_span(comment_start, comment_end)
                    pos = comment_end + 1
                } else {
                    add_span(comment_start, length(line))
                    in_block = 1
                    break
                }
            }
        }

        function update_xml_state(line,    pos, remaining, block_pos, block_end_rel) {
            pos = 1

            if (in_block) {
                remaining = substr(line, pos)
                if (match(remaining, /-->/)) {
                    pos += RSTART + RLENGTH - 1
                    in_block = 0
                } else {
                    return
                }
            }

            while (pos <= length(line)) {
                remaining = substr(line, pos)
                block_pos = match(remaining, /<!--/)

                if (!block_pos) {
                    return
                }

                block_end_rel = match(substr(remaining, block_pos + 4), /-->/)
                if (block_end_rel) {
                    pos = pos + block_pos + block_end_rel + 5
                } else {
                    in_block = 1
                    return
                }
            }
        }

        function analyse_xml_line(line,    pos, remaining, block_pos, block_end_rel, comment_start, comment_end) {
            reset_spans()
            pos = 1

            if (in_block) {
                remaining = substr(line, pos)
                if (match(remaining, /-->/)) {
                    comment_end = pos + RSTART + RLENGTH - 2
                    add_span(pos, comment_end)
                    pos = comment_end + 1
                    in_block = 0
                } else {
                    add_span(pos, length(line))
                    return
                }
            }

            while (pos <= length(line)) {
                remaining = substr(line, pos)
                block_pos = match(remaining, /<!--/)

                if (!block_pos) {
                    break
                }

                comment_start = pos + block_pos - 1
                block_end_rel = match(substr(remaining, block_pos + 4), /-->/)

                if (block_end_rel) {
                    comment_end = comment_start + block_end_rel + 5
                    add_span(comment_start, comment_end)
                    pos = comment_end + 1
                } else {
                    add_span(comment_start, length(line))
                    in_block = 1
                    break
                }
            }
        }

        BEGIN {
            IGNORECASE = ignore_case + 0
            in_block = 0
            reset_spans()
        }

        NR < target {
            if (mode == "java-like") {
                update_java_state($0)
            } else if (mode == "xml") {
                update_xml_state($0)
            }
            next
        }

        NR == target {
            if (mode == "hash-bang") {
                if ($0 ~ /^[[:space:]]*[#!]/) {
                    print "comment"
                } else {
                    print "code"
                }
                exit
            }

            if (mode == "hash") {
                if ($0 ~ /^[[:space:]]*#/) {
                    print "comment"
                    exit
                }

                reset_spans()
                if (match($0, /(^|[[:space:]])#/)) {
                    add_span(RSTART + RLENGTH - 1, length($0))
                }
                emit_classification($0)
                exit
            }

            if (mode == "java-like") {
                analyse_java_line($0)
                emit_classification($0)
                exit
            }

            if (mode == "xml") {
                analyse_xml_line($0)
                emit_classification($0)
                exit
            }

            print "code"
            exit
        }

        END {
            if (NR < target) {
                print "code"
            }
        }
    ' "$file"
}

print_phase2_match_lines() {
    local matches="$1"
    local prefix="${2:-}"
    local max_lines="${3:-0}"
    local count=0
    local total=0
    local line
    local rel

    [ -z "$matches" ] && return

    total=$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l | tr -d ' ')
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        count=$((count + 1))
        if [ "$max_lines" -gt 0 ] && [ "$count" -gt "$max_lines" ]; then
            break
        fi

        rel="${line#"$PROJECT_DIR"/}"
        echo -e "      ${DIM}${prefix}${rel}${RESET}"
    done <<< "$matches"

    if [ "$max_lines" -gt 0 ] && [ "$total" -gt "$max_lines" ]; then
        echo -e "      ${DIM}... and $((total - max_lines)) more${RESET}"
    fi
}

PHASE2_LAST_REAL_MATCH=0
PHASE2_LAST_COMMENT_MATCH=0

report_phase2_matches() {
    local description="$1"
    local risk="$2"
    local pattern="$3"
    local matches="${4:-}"
    local extra_info="${5:-}"
    local ignore_case="${6:-0}"
    local max_lines="${7:-0}"
    local code_matches=""
    local comment_matches=""
    local line
    local file_path
    local rest
    local line_no
    local classification
    local -A seen_matches=()

    PHASE2_LAST_REAL_MATCH=0
    PHASE2_LAST_COMMENT_MATCH=0
    [ -z "$matches" ] && return

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        if [ -n "${seen_matches["$line"]+x}" ]; then
            continue
        fi
        seen_matches["$line"]=1

        file_path="${line%%:*}"
        rest="${line#*:}"
        line_no="${rest%%:*}"
        classification=$(classify_phase2_match "$file_path" "$line_no" "$pattern" "$ignore_case")
        classification="${classification:-code}"

        if [ "$classification" = "comment" ]; then
            comment_matches+="$line"$'\n'
        else
            code_matches+="$line"$'\n'
        fi
    done <<< "$matches"

    if [ -n "$code_matches" ]; then
        PHASE2_LAST_REAL_MATCH=1
        record_finding "$risk" "$description"
        [ -n "$extra_info" ] && info "$extra_info"
        print_phase2_match_lines "$code_matches" "" "$max_lines"

        if [ -n "$comment_matches" ]; then
            PHASE2_LAST_COMMENT_MATCH=1
            info "${description}: comment-only references shown below are not counted as findings"
            print_phase2_match_lines "$comment_matches" "[comment] " "$max_lines"
        fi
    elif [ -n "$comment_matches" ]; then
        PHASE2_LAST_COMMENT_MATCH=1
        info "${description}: comment-only references detected (not counted as findings)"
        print_phase2_match_lines "$comment_matches" "[comment] " "$max_lines"
    fi
}

scan_timing_side_channel_patterns() {
    local comparison_pattern='\.equals[[:space:]]*\(|\.equalsIgnoreCase[[:space:]]*\(|\.compareTo[[:space:]]*\(|\.compareToIgnoreCase[[:space:]]*\(|Objects\.equals[[:space:]]*\(|Arrays\.equals[[:space:]]*\(|StringUtils\.equals[[:space:]]*\('
    local candidate_lines=""

    candidate_lines=$(grep -rn $SRC_INCLUDES -E "$comparison_pattern" "$PROJECT_DIR/src" 2>/dev/null || true)
    [ -z "$candidate_lines" ] && return

    printf '%s\n' "$candidate_lines" | awk '
        function is_secretish_comparison(text,    code, lowered) {
            code = text

            # Ignore quoted literals so "secret" in strings does not trigger a finding by itself.
            gsub(/"([^"\\]|\\.)*"/, "\"\"", code)
            gsub(/\047([^\\\047]|\\.)*\047/, "\047\047", code)

            # Ignore trailing single-line comments and simple inline block comments.
            sub(/\/\/.*/, "", code)
            gsub(/\/\*[^*]*\*\//, "", code)

            lowered = tolower(code)
            return lowered ~ /(token|secret|password|passwd|passphrase|credential|authtoken|bearertoken|refreshtoken|sessiontoken|apikey|accesskey|secretkey|privatekey|signingkey|sharedkey|licensekey|signature|hmac|csrf|otp|totp|pin)/
        }

        {
            line = $0
            first = index(line, ":")
            if (!first) next

            rest = substr(line, first + 1)
            second = index(rest, ":")
            if (!second) next

            content = substr(rest, second + 1)
            if (is_secretish_comparison(content)) {
                print line
            }
        }
    '
}

# ---------------------------------------------------------------------------
# Resolve project directory / options
# ---------------------------------------------------------------------------
PHASE_PAUSE_MODE="off"
PHASE_PAUSE_SECONDS=2
PROJECT_DIR=""

while [ $# -gt 0 ]; do
    case "$1" in
        --phase-pause)
            PHASE_PAUSE_MODE="prompt"
            shift
            ;;
        --phase-pause-seconds)
            if [ $# -lt 2 ]; then
                echo "Missing value for --phase-pause-seconds" >&2
                usage >&2
                exit 1
            fi
            case "$2" in
                ''|*[!0-9]*)
                    echo "Phase pause seconds must be a non-negative integer: $2" >&2
                    usage >&2
                    exit 1
                    ;;
            esac
            PHASE_PAUSE_MODE="sleep"
            PHASE_PAUSE_SECONDS="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
        *)
            if [ -n "$PROJECT_DIR" ]; then
                echo "Only one project directory may be specified." >&2
                usage >&2
                exit 1
            fi
            PROJECT_DIR="$1"
            shift
            ;;
    esac
done

if [ $# -gt 0 ]; then
    if [ -n "$PROJECT_DIR" ]; then
        echo "Only one project directory may be specified." >&2
        usage >&2
        exit 1
    fi
    PROJECT_DIR="$1"
    shift
fi

if [ $# -gt 0 ]; then
    echo "Unexpected arguments: $*" >&2
    usage >&2
    exit 1
fi

PROJECT_DIR="${PROJECT_DIR:-.}"
PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd)"

banner "PQC CRYPTOGRAPHIC AUDIT"
echo -e "  ${BOLD}Target project:${RESET} ${PROJECT_DIR}"
echo -e "  ${BOLD}Date:${RESET}           $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "  ${BOLD}Java version:${RESET}   $(java -version 2>&1 | head -1 || echo 'not found')"
case "$PHASE_PAUSE_MODE" in
    prompt)
        echo -e "  ${BOLD}Phase pauses:${RESET}   manual (press Enter)"
        ;;
    sleep)
        echo -e "  ${BOLD}Phase pauses:${RESET}   ${PHASE_PAUSE_SECONDS}s"
        ;;
esac
echo ""

# ===================================================================
# PHASE 1: Dependency Scan
# ===================================================================
banner "PHASE 1 — DEPENDENCY SCAN"

# Known crypto library patterns with risk classification
declare -A DEP_PATTERNS=(
    ["io.jsonwebtoken"]="jjwt — JWT signing (likely RSA/ECDSA)|VULN"
    ["com.nimbusds:nimbus-jose-jwt"]="Nimbus JOSE+JWT — JWT/JWE crypto|VULN"
    ["org.bouncycastle"]="Bouncy Castle — general-purpose crypto provider|ATTN"
    ["org.postgresql"]="PostgreSQL JDBC — internal TLS for DB connections|ATTN"
    ["com.auth0:java-jwt"]="Auth0 Java JWT — JWT signing|VULN"
    ["org.springframework.security"]="Spring Security — contains crypto primitives|ATTN"
    ["io.quarkus:quarkus-smallrye-jwt"]="Quarkus SmallRye JWT — MP-JWT signing|VULN"
    ["io.quarkus:quarkus-security"]="Quarkus Security — crypto primitives|ATTN"
    ["io.micronaut.security"]="Micronaut Security — JWT/crypto primitives|ATTN"
    ["io.micronaut:micronaut-security-jwt"]="Micronaut JWT — JWT signing|VULN"
    ["org.eclipse.microprofile.jwt"]="MicroProfile JWT — JWT signing spec|VULN"
    ["io.smallrye:smallrye-jwt"]="SmallRye JWT — MicroProfile JWT impl|VULN"
    ["commons-codec"]="Apache Commons Codec — hashing/encoding utilities|LOW"
    ["com.google.crypto.tink"]="Google Tink — crypto abstraction library|ATTN"
)

MVN_TREE_FILE=$(mktemp)
GRADLE_TREE_FILE=$(mktemp)
trap 'rm -f "$MVN_TREE_FILE" "$GRADLE_TREE_FILE"' EXIT

# Detect build system
BUILD_SYSTEM="none"
if [ -f "$PROJECT_DIR/pom.xml" ]; then
    BUILD_SYSTEM="maven"
elif [ -f "$PROJECT_DIR/build.gradle" ] || [ -f "$PROJECT_DIR/build.gradle.kts" ]; then
    BUILD_SYSTEM="gradle"
fi

echo -e "  ${BOLD}Build system:${RESET} ${BUILD_SYSTEM}"
echo -e "  Scanning dependency tree for crypto libraries…"
echo ""

DEP_TREE_FILE=""

if [ "$BUILD_SYSTEM" = "maven" ]; then
    if mvn -f "$PROJECT_DIR/pom.xml" dependency:tree \
         -DoutputType=text -DoutputFile="$MVN_TREE_FILE" \
         -q 2>/dev/null; then
        DEP_TREE_FILE="$MVN_TREE_FILE"
    else
        echo -e "    ${YELLOW}⚠  Maven dependency:tree failed — skipping dependency scan${RESET}"
    fi
elif [ "$BUILD_SYSTEM" = "gradle" ]; then
    GRADLE_CMD="gradle"
    [ -f "$PROJECT_DIR/gradlew" ] && GRADLE_CMD="$PROJECT_DIR/gradlew"
    if $GRADLE_CMD -p "$PROJECT_DIR" dependencies --configuration runtimeClasspath \
         > "$GRADLE_TREE_FILE" 2>/dev/null; then
        DEP_TREE_FILE="$GRADLE_TREE_FILE"
    else
        echo -e "    ${YELLOW}⚠  Gradle dependencies failed — skipping dependency scan${RESET}"
    fi
else
    echo -e "    ${YELLOW}⚠  No pom.xml or build.gradle found — skipping dependency scan${RESET}"
fi

if [ -n "$DEP_TREE_FILE" ] && [ -s "$DEP_TREE_FILE" ]; then
    for pattern in "${!DEP_PATTERNS[@]}"; do
        IFS='|' read -r description risk <<< "${DEP_PATTERNS[$pattern]}"
        match=$(grep -i "$pattern" "$DEP_TREE_FILE" || true)
        if [ -n "$match" ]; then
            case "$risk" in
                VULN) finding_vuln "${description}: $(echo "$match" | head -1 | sed 's/^[| +-\\]*//')" ;;
                ATTN) finding_attn "${description}: $(echo "$match" | head -1 | sed 's/^[| +-\\]*//')" ;;
                LOW)  finding_low  "${description}: $(echo "$match" | head -1 | sed 's/^[| +-\\]*//')" ;;
            esac
        fi
    done

    # Always flag JDK built-in crypto
    info "JDK built-in crypto (javax.crypto, java.security) is always available"
    finding_attn "JDK built-in JCA/JCE — review algorithm choices in source code"
fi

pause_between_phases "PHASE 2 — SOURCE CODE SCAN"

# ===================================================================
# PHASE 2: Source Code Scan
# ===================================================================
banner "PHASE 2 — SOURCE CODE SCAN"
echo -e "  Scanning *.java, *.kt, *.groovy, *.properties, *.xml files…"
echo ""

# File types to scan for source code patterns
SRC_INCLUDES="--include=*.java --include=*.kt --include=*.kts --include=*.groovy --include=*.scala"

# ---------------------------------------------------------------------------
# 2a. JCE API calls — Cipher, Signature, KeyPairGenerator, etc.
# ---------------------------------------------------------------------------
section "JCE / JCA API Calls"

declare -A JCE_PATTERNS=(
    ["Cipher\\.getInstance"]="Cipher.getInstance — encryption/decryption|ATTN"
    ["Signature\\.getInstance"]="Signature.getInstance — digital signatures|VULN"
    ["KeyPairGenerator\\.getInstance"]="KeyPairGenerator.getInstance — key generation|VULN"
    ["KeyAgreement\\.getInstance"]="KeyAgreement.getInstance — key agreement (DH/ECDH)|VULN"
    ["Mac\\.getInstance"]="Mac.getInstance — HMAC computation|LOW"
    ["MessageDigest\\.getInstance"]="MessageDigest.getInstance — hashing|LOW"
    ["SecretKeyFactory\\.getInstance"]="SecretKeyFactory.getInstance — secret key derivation|LOW"
    ["KeyStore\\.getInstance"]="KeyStore.getInstance — keystore access|ATTN"
    ["SSLContext\\.getInstance"]="SSLContext.getInstance — TLS configuration|ATTN"
    ["javax\\.crypto\\.KEM|java\\.security\\.KEM"]="KEM API — Key Encapsulation Mechanism (PQC-ready!)|LOW"
    ["KeyFactory\\.getInstance"]="KeyFactory.getInstance — key material loading|ATTN"
    ["CertificateFactory\\.getInstance"]="CertificateFactory.getInstance — certificate parsing|ATTN"
    ["TrustManagerFactory\\.getInstance"]="TrustManagerFactory.getInstance — TLS trust config|ATTN"
    ["KeyManagerFactory\\.getInstance"]="KeyManagerFactory.getInstance — TLS key config|ATTN"
)

for pattern in "${!JCE_PATTERNS[@]}"; do
    IFS='|' read -r description risk <<< "${JCE_PATTERNS[$pattern]}"

    matches=$(grep -rn $SRC_INCLUDES -E "$pattern" "$PROJECT_DIR/src" 2>/dev/null || true)
    report_phase2_matches "$description" "$risk" "$pattern" "$matches"
done

# ---------------------------------------------------------------------------
# 2b. Algorithm name strings — RSA, ECDSA, AES, etc.
# ---------------------------------------------------------------------------
section "Algorithm Name Strings"

declare -A ALGO_PATTERNS=(
    ["\"RSA\""]="RSA algorithm reference|VULN"
    ["\"EC\""]="EC (Elliptic Curve) algorithm reference|VULN"
    ["\"ECDSA\""]="ECDSA algorithm reference|VULN"
    ["\"ECDH\""]="ECDH key agreement reference|VULN"
    ["\"DSA\""]="DSA algorithm reference|VULN"
    ["\"DH\""]="Diffie-Hellman algorithm reference|VULN"
    ["\"AES\""]="AES algorithm reference|ATTN"
    ["HmacSHA"]="HMAC-SHA algorithm reference|LOW"
    ["ML-KEM\\|ML_KEM\\|MLKEM"]="ML-KEM (Post-Quantum KEM!) reference|LOW"
    ["ML-DSA\\|ML_DSA\\|MLDSA"]="ML-DSA (Post-Quantum Signature!) reference|LOW"
    ["SignatureAlgorithm\\.RS"]="Spring/JWT RS256/RS384/RS512 enum reference|VULN"
    ["SignatureAlgorithm\\.ES"]="Spring/JWT ES256/ES384/ES512 enum reference|VULN"
    ["SignatureAlgorithm\\.PS"]="Spring/JWT PS256/PS384/PS512 enum reference|VULN"
)

for pattern in "${!ALGO_PATTERNS[@]}"; do
    IFS='|' read -r description risk <<< "${ALGO_PATTERNS[$pattern]}"

    matches=$(grep -rn $SRC_INCLUDES -E "$pattern" "$PROJECT_DIR/src" 2>/dev/null || true)
    report_phase2_matches "$description" "$risk" "$pattern" "$matches"
done

# ---------------------------------------------------------------------------
# 2b-2. OID-based algorithm detection
# ---------------------------------------------------------------------------
section "Algorithm OIDs (ASN.1 Object Identifiers)"

declare -A OID_PATTERNS=(
    ["1\\.2\\.840\\.113549\\.1\\.1"]="RSA OID family (PKCS#1)|VULN"
    ["1\\.2\\.840\\.10040\\.4"]="DSA OID family|VULN"
    ["1\\.2\\.840\\.10045"]="ECDSA/EC OID family|VULN"
    ["1\\.3\\.6\\.1\\.4\\.1\\.11591\\.15"]="EdDSA OID (Curve25519/Ed25519)|VULN"
    ["2\\.16\\.840\\.1\\.101\\.3\\.4\\.3\\.17\\|2\\.16\\.840\\.1\\.101\\.3\\.4\\.3\\.18\\|2\\.16\\.840\\.1\\.101\\.3\\.4\\.3\\.19"]="ML-DSA OID family (FIPS 204)|LOW"
)

for pattern in "${!OID_PATTERNS[@]}"; do
    IFS='|' read -r description risk <<< "${OID_PATTERNS[$pattern]}"
    matches=$(grep -rn $SRC_INCLUDES --include='*.properties' --include='*.yml' --include='*.yaml' --include='*.xml' \
        -E "$pattern" "$PROJECT_DIR/src" 2>/dev/null || true)
    report_phase2_matches "$description" "$risk" "$pattern" "$matches"
done

# ---------------------------------------------------------------------------
# 2c. Configuration / properties scan (Spring Boot, Quarkus, Micronaut)
# ---------------------------------------------------------------------------
section "Configuration & Properties"

# --- TLS / SSL configuration ---
# Spring Boot: server.ssl.*
ssl_spring=$(grep -rn --include='*.properties' --include='*.yml' --include='*.yaml' \
    'server\.ssl\.' "$PROJECT_DIR/src" 2>/dev/null || true)
report_phase2_matches "server.ssl.* — Spring Boot TLS configuration found" "ATTN" 'server\.ssl\.' "$ssl_spring"

# Quarkus: quarkus.http.ssl.*, quarkus.tls.*
ssl_quarkus=$(grep -rn --include='*.properties' --include='*.yml' --include='*.yaml' \
    -E 'quarkus\.http\.ssl\.|quarkus\.tls\.' "$PROJECT_DIR/src" 2>/dev/null || true)
report_phase2_matches "quarkus.http.ssl.* / quarkus.tls.* — Quarkus TLS configuration found" "ATTN" \
    'quarkus\.http\.ssl\.|quarkus\.tls\.' "$ssl_quarkus"

# Micronaut: micronaut.ssl.*, micronaut.server.ssl.*
ssl_micronaut=$(grep -rn --include='*.properties' --include='*.yml' --include='*.yaml' \
    -E 'micronaut\.ssl\.|micronaut\.server\.ssl\.' "$PROJECT_DIR/src" 2>/dev/null || true)
report_phase2_matches "micronaut.ssl.* — Micronaut TLS configuration found" "ATTN" \
    'micronaut\.ssl\.|micronaut\.server\.ssl\.' "$ssl_micronaut"

# --- Datasource with SSL (all frameworks) ---
ds_ssl=$(grep -rn --include='*.properties' --include='*.yml' --include='*.yaml' \
    -iE '(datasource|jdbc).*ssl' "$PROJECT_DIR/src" 2>/dev/null || true)
report_phase2_matches "Datasource with SSL params — DB connection uses TLS" "ATTN" \
    '(datasource|jdbc).*ssl' "$ds_ssl" "" 1

# --- Keystore references in config (all frameworks) ---
ks_config=$(grep -rn --include='*.properties' --include='*.yml' --include='*.yaml' \
    -iE 'keystore|key-store|truststore|trust-store' "$PROJECT_DIR/src" 2>/dev/null || true)
report_phase2_matches "Keystore/truststore references in configuration" "ATTN" \
    'keystore|key-store|truststore|trust-store' "$ks_config" "" 1

# --- XML configuration (web.xml, server.xml, security.xml, etc.) ---
xml_crypto=$(grep -rn --include='*.xml' \
    -iE 'keystore|truststore|ssl|tls|cipher|algorithm|certificate|HTTPS' \
    "$PROJECT_DIR/src" "$PROJECT_DIR/src/main/webapp" "$PROJECT_DIR/src/main/resources" 2>/dev/null || true)
report_phase2_matches "Crypto references in XML configuration files" "ATTN" \
    'keystore|truststore|ssl|tls|cipher|algorithm|certificate|HTTPS' "$xml_crypto" "" 1 10

# ---------------------------------------------------------------------------
# 2d. Timing side-channel patterns
# ---------------------------------------------------------------------------
section "Timing Side-Channel Patterns"

timing_patterns=$(scan_timing_side_channel_patterns)
report_phase2_matches "Potential timing side-channel: equality/ordering comparison on secret-like data" "ATTN" \
    '\.equals[[:space:]]*\(|\.equalsIgnoreCase[[:space:]]*\(|\.compareTo[[:space:]]*\(|\.compareToIgnoreCase[[:space:]]*\(|Objects\.equals[[:space:]]*\(|Arrays\.equals[[:space:]]*\(|StringUtils\.equals[[:space:]]*\(' \
    "$timing_patterns" "Heuristic: comparison methods combined with token/secret/password/key-like identifiers. Prefer MessageDigest.isEqual() or a constant-time helper."

# ---------------------------------------------------------------------------
# 2e. Framework / Library API Patterns
# ---------------------------------------------------------------------------
section "Framework / Library API Patterns (require library knowledge)"

declare -A FRAMEWORK_PATTERNS=(
    # Google Tink patterns
    ["AeadConfig.register|PredefinedAeadParameters|AeadKeyTemplates"]="Google Tink AEAD — AES-256-GCM hidden in key template (consult PredefinedAeadParameters for actual algorithm)|ATTN"
    ["HybridConfig.register|PredefinedHybridParameters"]="Google Tink HybridEncrypt — ECIES (ECDH + AES-GCM, both quantum-vulnerable)|VULN"
    ["KeysetHandle\\.generateNew"]="Google Tink KeysetHandle — crypto algorithm determined by key template parameter|ATTN"
    # Bouncy Castle CMS patterns
    ["CMSSignedDataGenerator|CMSSignedData"]="Bouncy Castle CMS — PKCS#7 SignedData (check embedded signature algorithm OID)|ATTN"
    ["JcaContentSignerBuilder"]="Bouncy Castle ContentSigner — digital signature (algorithm string in builder constructor, e.g. SHA256withRSA)|VULN"
    ["JcaSignerInfoGeneratorBuilder"]="Bouncy Castle SignerInfoGenerator — CMS signature infrastructure|ATTN"
    # Bouncy Castle lightweight API
    ["new HMac|bouncycastle.crypto.macs"]="Bouncy Castle HMac — symmetric MAC (algorithm determined by Digest constructor argument)|LOW"
    ["new SHA256Digest|new SHA512Digest"]="Bouncy Castle digest — hashing primitive (check digest class name for algorithm)|LOW"
    # Spring Security Nimbus JWT
    ["NimbusJwtDecoder|NimbusJwtEncoder"]="Spring Security Nimbus JWT — RSA/ECDSA JWT signing (algorithm hidden in decoder/encoder config)|VULN"
    # MicroProfile JWT / SmallRye JWT (Quarkus)
    ["JsonWebToken|JWTParser|JwtClaimsBuilder"]="MicroProfile/SmallRye JWT — JWT signing (algorithm in mp.jwt.verify.publickey.algorithm)|VULN"
    ["@LoginConfig|@RolesAllowed.*jwt"]="MicroProfile JWT auth annotations — implies JWT crypto usage|ATTN"
    # Micronaut Security JWT
    ["JwtTokenGenerator|JwtTokenValidator|RefreshTokenPersistence"]="Micronaut JWT — token generation/validation (algorithm in micronaut.security.token.jwt.signatures)|VULN"
    ["@Secured|SecurityRule"]="Micronaut Security annotations — may imply crypto usage for token validation|ATTN"
    # Vert.x JWT (used by Quarkus)
    ["JWTAuth|JWTAuthOptions"]="Vert.x JWT Auth — JWT signing (algorithm in JWTAuthOptions)|VULN"
    # Jakarta Security / EE
    ["IdentityStore|HttpAuthenticationMechanism"]="Jakarta Security — authentication mechanism (may use crypto for tokens)|ATTN"
)

for pattern in "${!FRAMEWORK_PATTERNS[@]}"; do
    IFS='|' read -r description risk <<< "${FRAMEWORK_PATTERNS[$pattern]}"
    matches=$(grep -rn --include='*.java' -E "$pattern" "$PROJECT_DIR/src" 2>/dev/null || true)
    report_phase2_matches "$description" "$risk" "$pattern" "$matches"
done

pause_between_phases "PHASE 3 — KEYSTORE & CERTIFICATE AUDIT"

# ===================================================================
# PHASE 3: Keystore & Certificate Audit
# ===================================================================
banner "PHASE 3 — KEYSTORE & CERTIFICATE AUDIT"
echo -e "  Scanning for keystore files (*.jks, *.p12, *.pkcs12, *.keystore)"
echo -e "  and PEM certificate/key files (*.pem, *.crt, *.cer, *.key)…"
echo ""

# --- 3a. Binary keystores ---
KEYSTORES=$(find "$PROJECT_DIR" -type f -not -path '*/target/*' -not -path '*/.git/*' -not -path '*/node_modules/*' \( \
    -name '*.jks' -o -name '*.p12' -o -name '*.pkcs12' -o -name '*.keystore' \
    \) 2>/dev/null || true)

if [ -n "$KEYSTORES" ]; then
    while IFS= read -r ks; do
        rel="${ks#"$PROJECT_DIR"/}"
        section "Keystore: ${rel}"

        case "${ks##*.}" in
            p12|pkcs12) storetype="PKCS12" ;;
            jks)        storetype="JKS" ;;
            *)          storetype="JKS" ;;
        esac

        for pass in changeit changeme password secret ""; do
            output=$(keytool -list -v -keystore "$ks" -storetype "$storetype" \
                     -storepass "$pass" 2>/dev/null || true)
            if [ -n "$output" ]; then
                echo "$output" | grep -E '(Alias name|Entry type|Key type|Key size|Signature algorithm|Valid from)' | \
                while IFS= read -r line; do
                    echo -e "    ${DIM}${line}${RESET}"
                done

                vuln_algos=$(echo "$output" | grep -iE '(RSA|ECDSA|DSA|EC)' | grep -iE '(Key type|Signature algorithm)' || true)
                if [ -n "$vuln_algos" ]; then
                    finding_vuln "Keystore ${rel}: contains quantum-vulnerable keys/signatures"
                    echo "$vuln_algos" | while IFS= read -r line; do
                        echo -e "      ${RED}${line}${RESET}"
                    done
                fi

                pqc_algos=$(echo "$output" | grep -iE '(ML-DSA|ML-KEM|MLDSA|MLKEM|SLH-DSA|SLHDSA)' || true)
                if [ -n "$pqc_algos" ]; then
                    finding_low "Keystore ${rel}: contains PQC algorithms — ready!"
                fi

                break
            fi
        done
    done <<< "$KEYSTORES"
else
    echo -e "    ${DIM}No binary keystore files found.${RESET}"
fi

# --- 3b. PEM certificate/key files ---
section "PEM Certificate & Key Files"

PEM_FILES=$(find "$PROJECT_DIR" -type f -not -path '*/target/*' -not -path '*/.git/*' -not -path '*/node_modules/*' \( \
    -name '*.pem' -o -name '*.crt' -o -name '*.cer' -o -name '*.key' -o -name '*.cert' \
    \) 2>/dev/null || true)

if [ -n "$PEM_FILES" ]; then
    while IFS= read -r pf; do
        rel="${pf#"$PROJECT_DIR"/}"

        # Try to read certificate info with openssl
        cert_info=$(openssl x509 -in "$pf" -noout -subject -issuer -dates -pubkey 2>/dev/null || true)
        if [ -n "$cert_info" ]; then
            echo -e "    ${BOLD}Certificate: ${rel}${RESET}"
            # Extract key algorithm
            key_algo=$(openssl x509 -in "$pf" -noout -text 2>/dev/null | grep -i "Public Key Algorithm" | head -1 || true)
            sig_algo=$(openssl x509 -in "$pf" -noout -text 2>/dev/null | grep -i "Signature Algorithm" | head -1 || true)
            echo -e "      ${DIM}${key_algo}${RESET}"
            echo -e "      ${DIM}${sig_algo}${RESET}"

            if echo "$key_algo $sig_algo" | grep -qiE 'rsa|ecdsa|dsa|ec'; then
                finding_vuln "PEM ${rel}: contains quantum-vulnerable key/signature algorithm"
            fi
        else
            # Might be a private key file
            key_type=$(openssl pkey -in "$pf" -noout -text 2>/dev/null | head -3 || true)
            if [ -n "$key_type" ]; then
                echo -e "    ${BOLD}Private Key: ${rel}${RESET}"
                echo -e "      ${DIM}${key_type}${RESET}"
                if echo "$key_type" | grep -qiE 'rsa|ec|dsa'; then
                    finding_vuln "PEM ${rel}: quantum-vulnerable private key"
                fi
            else
                echo -e "    ${DIM}${rel} (could not parse — may be encrypted or non-standard)${RESET}"
            fi
        fi
    done <<< "$PEM_FILES"
else
    echo -e "    ${DIM}No PEM files found.${RESET}"
fi

pause_between_phases "SUMMARY"

# ===================================================================
# SUMMARY
# ===================================================================
banner "PQC CRYPTOGRAPHIC AUDIT SUMMARY"

TOTAL=$(( ${#FINDINGS_VULN[@]} + ${#FINDINGS_ATTN[@]} + ${#FINDINGS_LOW[@]} ))
echo -e "  ${BOLD}Total crypto usage points found: ${WHITE}${TOTAL}${RESET}"
echo ""

if [ ${#FINDINGS_VULN[@]} -gt 0 ]; then
    echo -e "  ${RED}🔴 QUANTUM-VULNERABLE (requires PQC migration): ${#FINDINGS_VULN[@]}${RESET}"
    for f in "${FINDINGS_VULN[@]}"; do
        echo -e "     - $f"
    done
    echo ""
fi

if [ ${#FINDINGS_ATTN[@]} -gt 0 ]; then
    echo -e "  ${YELLOW}🟡 ATTENTION (review recommended): ${#FINDINGS_ATTN[@]}${RESET}"
    for f in "${FINDINGS_ATTN[@]}"; do
        echo -e "     - $f"
    done
    echo ""
fi

if [ ${#FINDINGS_LOW[@]} -gt 0 ]; then
    echo -e "  ${GREEN}🟢 LOW-RISK (minimal quantum impact): ${#FINDINGS_LOW[@]}${RESET}"
    for f in "${FINDINGS_LOW[@]}"; do
        echo -e "     - $f"
    done
    echo ""
fi

echo -e "  ${CYAN}────────────────────────────────────────────────${RESET}"
echo -e "  ${BOLD}RECOMMENDED ACTIONS:${RESET}"
echo -e "    1. Migrate ${GREEN}signature workflows${RESET} (JWT, certificates, CMS) from RSA/ECDSA/DSA to ${GREEN}ML-DSA / SLH-DSA${RESET} when ecosystem support is ready"
echo -e "    2. Migrate ${GREEN}key-establishment workflows${RESET} (ECDH, DH, TLS named groups, RSA wrapping) to ${GREEN}ML-KEM / hybrid TLS${RESET}"
echo -e "    3. Keep ${GREEN}bulk symmetric crypto${RESET} (AES, ChaCha, HMAC) but review key sizes and crypto-agility boundaries"
echo -e "    4. Upgrade to ${GREEN}JDK 27${RESET} for native hybrid TLS named groups (JEP 527)"
echo -e "    5. Add a ${GREEN}crypto-agility abstraction layer${RESET} so signatures, KEM, and TLS settings can evolve independently"
echo -e "  ${CYAN}────────────────────────────────────────────────${RESET}"
echo ""
echo -e "  ${DIM}Run 'java scripts/CryptoAuditJce.java' for JCE provider enumeration${RESET}"
echo -e "  ${DIM}Run 'java ../ciphercheck-demo/CipherSuiteCheck.java' for TLS named-group capability audit${RESET}"
echo -e "  ${DIM}Run 'java scripts/KeystoreAudit.java <path> <password>' for keystore audit${RESET}"
echo ""
echo -e "${CYAN}============================================================${RESET}"
