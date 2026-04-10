///usr/bin/env java --enable-preview "$0" "$@"; exit $?
// ============================================================================
// KeystoreAudit.java — X.509 Certificate & Key Algorithm Audit
//
// Reads a Java keystore (PKCS12 or JKS), enumerates all entries, and flags
// quantum-vulnerable key algorithms and signature schemes.
//
// Usage:  java scripts/KeystoreAudit.java <keystore-path> [password]
// Requires: JDK 17+ (JDK 24+ recommended for PQC detection)
// ============================================================================

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

public class KeystoreAudit {

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

    static int vulnCount = 0;
    static int attnCount = 0;
    static int safeCount = 0;

    static final List<String> vulnEntries = new ArrayList<>();
    static final List<String> attnEntries = new ArrayList<>();
    static final List<String> safeEntries = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: java KeystoreAudit.java <keystore-path> [password]");
            System.err.println();
            System.err.println("  keystore-path   Path to .p12, .jks, or .pkcs12 keystore file");
            System.err.println("  password         Keystore password (default: changeit)");
            System.exit(1);
        }

        String keystorePath = args[0];
        String password = args.length > 1 ? args[1] : "changeit";

        banner("X.509 KEYSTORE AUDIT");
        System.out.printf("  %sKeystore:%s  %s%n", BOLD, RESET, keystorePath);
        System.out.printf("  %sDate:%s      %s%n", BOLD, RESET, new Date());
        System.out.printf("  %sJava:%s      %s%n%n", BOLD, RESET, System.getProperty("java.version"));

        // Determine keystore type from extension
        String storeType = keystorePath.toLowerCase().endsWith(".jks") ? "JKS" : "PKCS12";
        System.out.printf("  %sStore type:%s %s%n%n", BOLD, RESET, storeType);

        KeyStore ks = KeyStore.getInstance(storeType);
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            ks.load(fis, password.toCharArray());
        }

        List<String> aliases = Collections.list(ks.aliases());
        System.out.printf("  %sEntries found:%s %d%n%n", BOLD, RESET, aliases.size());

        for (String alias : aliases) {
            separator();
            System.out.printf("  %s%sAlias: %s%s%n", BOLD, WHITE, alias, RESET);

            if (ks.isKeyEntry(alias)) {
                System.out.printf("  %sEntry type:%s PrivateKeyEntry%n", DIM, RESET);
                auditKeyEntry(ks, alias, password);
            } else if (ks.isCertificateEntry(alias)) {
                System.out.printf("  %sEntry type:%s TrustedCertificateEntry%n", DIM, RESET);
                Certificate cert = ks.getCertificate(alias);
                if (cert instanceof X509Certificate x509) {
                    auditCertificate(alias, x509);
                }
            } else {
                System.out.printf("  %sEntry type:%s SecretKeyEntry%n", DIM, RESET);
                auditSecretKey(ks, alias, password);
            }
            System.out.println();
        }

        // Summary
        banner("KEYSTORE AUDIT SUMMARY");

        int total = vulnCount + attnCount + safeCount;
        System.out.printf("  %sTotal entries audited:%s %d%n%n", BOLD, RESET, total);

        if (!vulnEntries.isEmpty()) {
            System.out.printf("  %s🔴 QUANTUM-VULNERABLE: %d%s%n", RED, vulnCount, RESET);
            for (String e : vulnEntries) {
                System.out.printf("     - %s%n", e);
            }
            System.out.println();
        }

        if (!attnEntries.isEmpty()) {
            System.out.printf("  %s🟡 ATTENTION: %d%s%n", YELLOW, attnCount, RESET);
            for (String e : attnEntries) {
                System.out.printf("     - %s%n", e);
            }
            System.out.println();
        }

        if (!safeEntries.isEmpty()) {
            System.out.printf("  %s🟢 PQC-READY / LOW-RISK: %d%s%n", GREEN, safeCount, RESET);
            for (String e : safeEntries) {
                System.out.printf("     - %s%n", e);
            }
            System.out.println();
        }

        // Migration recommendations
        System.out.printf("  %s────────────────────────────────────────────────%s%n", CYAN, RESET);
        System.out.printf("  %sMIGRATION GUIDE:%s%n", BOLD, RESET);
        System.out.println();

        printMigrationRow("RSA / ECDSA / DSA cert signatures", "ML-DSA / SLH-DSA", "signature migration, FIPS 204/205");
        printMigrationRow("ECDH / DH key establishment", "ML-KEM-768 / ML-KEM-1024", "key establishment, FIPS 203");
        printMigrationRow("RSA key wrapping / transport", "ML-KEM-768 + symmetric wrapping", "key establishment, FIPS 203");
        printMigrationRow("Ed25519 / Ed448 signatures", "ML-DSA-65", "signature migration, FIPS 204");
        printMigrationRow("AES / ChaCha / HMAC", "keep, review key size", "symmetric crypto remains acceptable");

        System.out.println();
        System.out.printf("  %sNote:%s certificate migration and key-establishment migration are different workstreams.%n",
                BOLD, RESET);
        System.out.printf("  %sTLS 1.3 harvest-now-decrypt-later risk sits first in key establishment, not in the certificate signature alone.%s%n",
                DIM, RESET);

        System.out.println();
        System.out.printf("  %s────────────────────────────────────────────────%s%n", CYAN, RESET);
        System.out.println();
    }

    static void auditKeyEntry(KeyStore ks, String alias, String password) {
        try {
            // Get the certificate chain
            Certificate[] chain = ks.getCertificateChain(alias);
            if (chain != null && chain.length > 0 && chain[0] instanceof X509Certificate x509) {
                auditCertificate(alias, x509);
            }

            // Try to get the key to inspect its type
            Key key = null;
            try {
                key = ks.getKey(alias, password.toCharArray());
            } catch (Exception e) {
                // Key may not be extractable; that's fine
            }

            if (key != null) {
                String keyAlgo = key.getAlgorithm();
                int keySize = getKeySize(key);
                System.out.printf("  %sPrivate key:%s %s", DIM, RESET, keyAlgo);
                if (keySize > 0) {
                    System.out.printf(" (%d-bit)", keySize);
                }
                System.out.println();
                classifyAlgorithm(alias, "PrivateKey", keyAlgo, keySize);
            }
        } catch (Exception e) {
            System.out.printf("  %s⚠  Could not inspect key entry: %s%s%n", YELLOW, e.getMessage(), RESET);
        }
    }

    static void auditCertificate(String alias, X509Certificate cert) {
        String sigAlg = cert.getSigAlgName();
        String keyAlg = cert.getPublicKey().getAlgorithm();
        int keySize = getKeySize(cert.getPublicKey());

        System.out.printf("  %sSubject:%s     %s%n", DIM, RESET, cert.getSubjectX500Principal());
        System.out.printf("  %sIssuer:%s      %s%n", DIM, RESET, cert.getIssuerX500Principal());
        System.out.printf("  %sValid:%s       %s → %s%n", DIM, RESET,
                cert.getNotBefore(), cert.getNotAfter());
        System.out.printf("  %sSig algorithm:%s %s%n", DIM, RESET, sigAlg);
        System.out.printf("  %sKey algorithm:%s %s", DIM, RESET, keyAlg);
        if (keySize > 0) {
            System.out.printf(" (%d-bit)", keySize);
        }
        System.out.println();
        System.out.printf("  %sSerial:%s      %s%n", DIM, RESET, cert.getSerialNumber().toString(16));

        // Check expiry
        try {
            cert.checkValidity();
        } catch (Exception e) {
            System.out.printf("  %s⚠  Certificate is EXPIRED or not yet valid!%s%n", YELLOW, RESET);
        }

        // Classify both the signature algorithm and key algorithm
        classifyAlgorithm(alias, "Certificate Signature", sigAlg, 0);
        classifyAlgorithm(alias, "Certificate Public Key", keyAlg, keySize);
    }

    static void auditSecretKey(KeyStore ks, String alias, String password) {
        try {
            Key key = ks.getKey(alias, password.toCharArray());
            if (key != null) {
                String algo = key.getAlgorithm();
                System.out.printf("  %sAlgorithm:%s %s%n", DIM, RESET, algo);
                if (isSymmetric(algo)) {
                    System.out.printf("    %s🟢 Symmetric key — low quantum risk%s%n", GREEN, RESET);
                    safeCount++;
                    safeEntries.add(alias + " → " + algo + " (symmetric)");
                } else {
                    System.out.printf("    %s🟡 Review recommended%s%n", YELLOW, RESET);
                    attnCount++;
                    attnEntries.add(alias + " → " + algo);
                }
            }
        } catch (Exception e) {
            System.out.printf("  %s⚠  Could not inspect secret key: %s%s%n", YELLOW, e.getMessage(), RESET);
        }
    }

    static void classifyAlgorithm(String alias, String context, String algorithm, int keySize) {
        String algoUpper = algorithm.toUpperCase();

        if (isPqcAlgorithm(algoUpper)) {
            System.out.printf("    %s✅ %s: %s — Post-Quantum Ready!%s%n",
                    GREEN, context, algorithm, RESET);
            safeCount++;
            safeEntries.add(alias + " → " + context + ": " + algorithm + " (PQC)");
            return;
        }

        if (isQuantumVulnerable(algoUpper)) {
            System.out.printf("    %s🔴 %s: %s — QUANTUM-VULNERABLE%s%n",
                    RED, context, algorithm, RESET);
            String replacement = suggestPqcReplacement(algoUpper);
            System.out.printf("    %s   → Replace with: %s%s%n", DIM, replacement, RESET);
            vulnCount++;
            vulnEntries.add(alias + " → " + context + ": " + algorithm
                    + (keySize > 0 ? " (" + keySize + "-bit)" : ""));
            return;
        }

        if (isSymmetric(algoUpper)) {
            System.out.printf("    %s🟢 %s: %s — Low quantum risk%s%n",
                    GREEN, context, algorithm, RESET);
            safeCount++;
            safeEntries.add(alias + " → " + context + ": " + algorithm);
            return;
        }

        // Unknown — flag for attention
        System.out.printf("    %s🟡 %s: %s — Review recommended%s%n",
                YELLOW, context, algorithm, RESET);
        attnCount++;
        attnEntries.add(alias + " → " + context + ": " + algorithm);
    }

    static boolean isQuantumVulnerable(String algo) {
        return algo.contains("RSA") || algo.contains("ECDSA") || algo.contains("ECDH")
            || algo.contains("DSA") || algo.contains("DH")
            || algo.contains("EC") || algo.contains("ED25519") || algo.contains("ED448")
            || algo.contains("X25519") || algo.contains("X448");
    }

    static boolean isPqcAlgorithm(String algo) {
        return algo.contains("ML-KEM") || algo.contains("ML_KEM") || algo.contains("MLKEM")
            || algo.contains("ML-DSA") || algo.contains("ML_DSA") || algo.contains("MLDSA")
            || algo.contains("SLH-DSA") || algo.contains("SLH_DSA") || algo.contains("SLHDSA")
            || algo.contains("DILITHIUM") || algo.contains("KYBER");
    }

    static boolean isSymmetric(String algo) {
        return algo.contains("AES") || algo.contains("CHACHA") || algo.contains("HMAC")
            || algo.contains("SHA") || algo.contains("PBKDF") || algo.contains("PBE");
    }

    static String suggestPqcReplacement(String algo) {
        if (algo.contains("RSA") && !algo.contains("ECDSA")) {
            return "ML-DSA for signatures, or ML-KEM for key establishment / wrapping — JDK 24+";
        }
        if (algo.contains("ECDSA") || algo.contains("ED25519") || algo.contains("ED448")) {
            return "ML-DSA-44 or ML-DSA-65 for signatures — JDK 24+";
        }
        if (algo.contains("ECDH") || algo.contains("DH") || algo.contains("X25519") || algo.contains("X448")) {
            return "ML-KEM-768 or ML-KEM-1024 for key establishment — JDK 24+";
        }
        if (algo.contains("DSA")) {
            return "ML-DSA-44 for signatures — JDK 24+";
        }
        return "Consult FIPS 203 / 204 / 205 and separate signature vs key-establishment migration";
    }

    static int getKeySize(Key key) {
        if (key instanceof RSAKey rsaKey) {
            return rsaKey.getModulus().bitLength();
        }
        if (key instanceof ECKey ecKey) {
            return ecKey.getParams().getOrder().bitLength();
        }
        if (key instanceof DSAKey dsaKey && dsaKey.getParams() != null) {
            return dsaKey.getParams().getP().bitLength();
        }
        return -1;
    }

    static int getKeySize(java.security.PublicKey key) {
        return getKeySize((Key) key);
    }

    static void banner(String title) {
        System.out.println();
        System.out.printf("%s============================================================%s%n", CYAN, RESET);
        System.out.printf("%s%s%s%n", WHITE, title, RESET);
        System.out.printf("%s============================================================%s%n", CYAN, RESET);
        System.out.println();
    }

    static void separator() {
        System.out.printf("  %s────────────────────────────────────────────────%s%n", MAGENTA, RESET);
    }

    static void printMigrationRow(String current, String replacement, String standard) {
        System.out.printf("    %s%-22s%s → %s%-28s%s %s(%s)%s%n",
                RED, current, RESET,
                GREEN, replacement, RESET,
                DIM, standard, RESET);
    }
}
