///usr/bin/env java --enable-preview "$0" "$@"; exit $?
// ============================================================================
// CryptoAuditJce.java — JCE Provider & Algorithm Audit
//
// Lists all registered JCE Security Providers, enumerates their algorithms,
// and classifies crypto-relevant algorithms as post-quantum, quantum-vulnerable,
// needs-attention, or low-risk.
//
// This is the capability-inventory half of Layer 4. It shows what the JDK and
// providers can do, not what the application actually exercised at runtime.
//
// Usage:  java scripts/CryptoAuditJce.java
// Requires: JDK 17+ (JDK 24+ recommended for PQC algorithm detection)
// ============================================================================

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

public class CryptoAuditJce {

    // ANSI colour codes
    static final String RED     = "\033[1;31m";
    static final String YELLOW  = "\033[1;33m";
    static final String GREEN   = "\033[1;32m";
    static final String CYAN    = "\033[1;36m";
    static final String MAGENTA = "\033[1;35m";
    static final String WHITE   = "\033[1;37m";
    static final String DIM     = "\033[2m";
    static final String BOLD    = "\033[1m";
    static final String RESET   = "\033[0m";

    // Quantum-vulnerable patterns
    // Matches algorithms based on RSA, DSA, ECDSA, ECDH, DH, EC key exchange
    // that are vulnerable to Shor's algorithm.
    // Uses case-insensitive substring matching to avoid word-boundary issues
    // (e.g., "ML-DSA" contains "DSA" but the hyphen is a word boundary in regex).
    static final Pattern QUANTUM_VULN = Pattern.compile(
            "(?i)("
            // RSA-based (Cipher, Signature, KeyFactory, KeyGenerator, etc.)
          + "RSA"                          // Catches RSA, RSASSA-PSS, SHA*withRSA, MD*withRSA, SunTlsRsaPremasterSecret
            // DSA-based (exclude ML-DSA and SLH-DSA which are PQC)
          + "|(?<!ML-)(?<!SLH-)DSA"        // DSA, SHA*withDSA, NONEwithDSA, but NOT ML-DSA or SLH-DSA
            // ECDSA / ECDH
          + "|ECDSA|ECDH"
            // Diffie-Hellman (including DHKEM which uses classical DH)
          + "|DiffieHellman|DHKEM"
            // EC key operations (but not "SecureRandom", "SecretKeyFactory", etc.)
          + "|\\bEC\\b"
            // Modern curves (quantum-vulnerable via ECDLP / Shor)
          + "|X25519|X448|Ed25519|Ed448|XDH|EdDSA"
          + ")"
    );

    // Post-quantum algorithm patterns (JDK 24+ / Bouncy Castle)
    static final Pattern PQC_ALGO = Pattern.compile(
            "(?i)(ML-KEM|ML_KEM|MLKEM|ML-DSA|ML_DSA|MLDSA"
          + "|SLH-DSA|SLH_DSA|SLHDSA|HQC|BIKE|CRYSTALS|DILITHIUM|KYBER)"
    );

    // Symmetric / HMAC — low quantum risk
    static final Pattern LOW_RISK = Pattern.compile(
            "(?i)(\\bAES\\b|\\bHmacSHA|\\bPBKDF|\\bPBEWith|\\bSHA-\\d|\\bSHA\\d"
          + "|\\bChaCha20|\\bPoly1305|\\bGCM\\b|\\bCCM\\b|\\bSIV\\b)"
    );

    public static void main(String[] args) {
        banner("JCE PROVIDER & ALGORITHM AUDIT");
        System.out.printf("  %sJava version:%s %s%n", BOLD, RESET,
                System.getProperty("java.version"));
        System.out.printf("  %sJava vendor:%s  %s%n", BOLD, RESET,
                System.getProperty("java.vendor"));
        System.out.printf("  %sJava home:%s    %s%n%n", BOLD, RESET,
                System.getProperty("java.home"));

        int totalAlgos = 0;        // crypto-relevant algorithms
        int pqcCount = 0;
        int vulnCount = 0;
        int needsAttentionCount = 0;
        int lowRiskCount = 0;

        // Count ALL registered algorithm services (including non-crypto types)
        Set<String> allRegistered = new TreeSet<>();

        List<String> vulnDetails = new ArrayList<>();
        List<String> pqcDetails = new ArrayList<>();
        List<String> attentionDetails = new ArrayList<>();

        Provider[] providers = Security.getProviders();
        System.out.printf("  %sRegistered providers:%s %d%n%n", BOLD, RESET, providers.length);

        for (Provider provider : providers) {
            System.out.printf("  %s%s──── Provider: %s (v%s) ────%s%n",
                    MAGENTA, BOLD, provider.getName(), provider.getVersionStr(), RESET);
            System.out.printf("  %s%s%s%n%n", DIM, provider.getInfo(), RESET);

            // Group algorithms by service type (Cipher, Signature, etc.)
            Map<String, Set<String>> serviceAlgos = new LinkedHashMap<>();
            for (Provider.Service service : provider.getServices()) {
                serviceAlgos
                    .computeIfAbsent(service.getType(), k -> new TreeSet<>())
                    .add(service.getAlgorithm());
                // Track all registered services globally (for the total count)
                allRegistered.add(service.getType() + "." + service.getAlgorithm());
            }

            for (var entry : serviceAlgos.entrySet()) {
                String serviceType = entry.getKey();
                Set<String> algos = entry.getValue();

                // Only show crypto-relevant service types in detail
                if (!isCryptoServiceType(serviceType)) continue;

                System.out.printf("    %s[%s]%s%n", CYAN, serviceType, RESET);

                for (String algo : algos) {
                    totalAlgos++;
                    String tag;
                    String colour;

                    if (PQC_ALGO.matcher(algo).find()) {
                        tag = "Post-Quantum ✨";
                        colour = GREEN;
                        pqcCount++;
                        pqcDetails.add(provider.getName() + " → " + serviceType + "." + algo);
                    } else if (QUANTUM_VULN.matcher(algo).find()) {
                        tag = "Quantum-Vulnerable";
                        colour = RED;
                        vulnCount++;
                        vulnDetails.add(provider.getName() + " → " + serviceType + "." + algo);
                    } else if (LOW_RISK.matcher(algo).find()) {
                        tag = "Low-Risk";
                        colour = GREEN;
                        lowRiskCount++;
                    } else {
                        tag = "Needs-Attention";
                        colour = YELLOW;
                        needsAttentionCount++;
                        attentionDetails.add(provider.getName() + " → " + serviceType + "." + algo);
                    }

                    System.out.printf("      %s%-45s%s  %s(%s)%s%n",
                            colour, algo, RESET, colour, tag, RESET);
                }
                System.out.println();
            }
        }

        // Summary
        banner("AUDIT SUMMARY");

        System.out.printf("  %sTotal registered algorithm services:%s  %d%n",
                BOLD, RESET, allRegistered.size());
        System.out.printf("  %sOf which, crypto-relevant algorithms:%s %d%n%n",
                BOLD, RESET, totalAlgos);

        System.out.printf("  %s✅ Post-Quantum algorithms available:    %s%d%s%n",
                GREEN, WHITE, pqcCount, RESET);
        if (!pqcDetails.isEmpty()) {
            for (String d : pqcDetails) {
                System.out.printf("     %s+ %s%s%n", GREEN, d, RESET);
            }
        } else {
            System.out.printf("     %s(none — upgrade to JDK 24+ for ML-KEM/ML-DSA)%s%n", DIM, RESET);
        }
        System.out.println();

        System.out.printf("  %s🔴 Quantum-Vulnerable algorithms found:  %s%d%s%n",
                RED, WHITE, vulnCount, RESET);
        if (vulnDetails.size() <= 15) {
            for (String d : vulnDetails) {
                System.out.printf("     %s- %s%s%n", RED, d, RESET);
            }
        } else {
            for (int i = 0; i < 10; i++) {
                System.out.printf("     %s- %s%s%n", RED, vulnDetails.get(i), RESET);
            }
            System.out.printf("     %s... and %d more%s%n", DIM, vulnDetails.size() - 10, RESET);
        }
        System.out.println();

        System.out.printf("  %s🟡 Needs-Attention algorithms:           %s%d%s%n",
                YELLOW, WHITE, needsAttentionCount, RESET);
        if (attentionDetails.size() <= 15) {
            for (String d : attentionDetails) {
                System.out.printf("     %s~ %s%s%n", YELLOW, d, RESET);
            }
        } else {
            for (int i = 0; i < 10; i++) {
                System.out.printf("     %s~ %s%s%n", YELLOW, attentionDetails.get(i), RESET);
            }
            System.out.printf("     %s... and %d more%s%n", DIM, attentionDetails.size() - 10, RESET);
        }
        System.out.println();

        System.out.printf("  %s🟢 Low-Risk algorithms (symmetric/HMAC): %s%d%s%n",
                GREEN, WHITE, lowRiskCount, RESET);
        System.out.println();

        // Recommendations
        System.out.printf("  %s────────────────────────────────────────────────%s%n", CYAN, RESET);
        System.out.printf("  %sRECOMMENDATIONS:%s%n", BOLD, RESET);
        System.out.printf("    → Treat this output as %scapability inventory%s for the current JDK/providers%n", GREEN, RESET);
        if (pqcCount > 0) {
            System.out.printf("    %s✅ PQC algorithms detected — your JDK supports post-quantum crypto!%s%n",
                    GREEN, RESET);
            System.out.printf("    → Migrate %ssignature%s usage from RSA/ECDSA/DSA to %sML-DSA / SLH-DSA%s%n",
                    GREEN, RESET, GREEN, RESET);
            System.out.printf("    → Migrate %skey-establishment%s usage from ECDH/DH to %sML-KEM%s%n",
                    GREEN, RESET, GREEN, RESET);
        } else {
            System.out.printf("    %s⚠  No PQC algorithms found. Upgrade to JDK 24+ for ML-KEM/ML-DSA.%s%n",
                    YELLOW, RESET);
        }
        System.out.printf("    → Upgrade to JDK 28 for native hybrid TLS named-group support (JEP 527)%n");
        System.out.printf("    → Use java ../ciphercheck-demo/CipherSuiteCheck.java to inspect supported TLS named groups%n");
        System.out.printf("    → Use java scripts/CryptoAuditRuntime.java to compare capability with observed runtime behaviour%n");
        System.out.printf("    → Build crypto-agility layer to ease future algorithm transitions%n");
        System.out.printf("  %s────────────────────────────────────────────────%s%n", CYAN, RESET);
        System.out.println();
    }

    static boolean isCryptoServiceType(String type) {
        return switch (type) {
            case "Cipher", "Signature", "KeyPairGenerator", "KeyAgreement",
                 "Mac", "MessageDigest", "SecretKeyFactory", "KeyFactory",
                 "KeyGenerator", "AlgorithmParameters", "AlgorithmParameterGenerator",
                 "KeyStore", "SSLContext", "CertificateFactory", "CertPathValidator",
                 "CertPathBuilder", "CertStore",
                 "SecureRandom", "KEM", "KDF" -> true;
            default -> false;
        };
    }

    static void banner(String title) {
        System.out.println();
        System.out.printf("%s============================================================%s%n", CYAN, RESET);
        System.out.printf("%s%s%s%n", WHITE, title, RESET);
        System.out.printf("%s============================================================%s%n", CYAN, RESET);
        System.out.println();
    }
}
