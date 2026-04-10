///usr/bin/env java --enable-preview "$0" "$@"; exit $?
// ============================================================================
// CipherSuiteCheck.java — SSL/TLS Cipher Suite & Named Group Audit
//
// Lists all supported SSL/TLS cipher suites and named groups (key exchange
// curves) for each protocol version, and flags quantum-vulnerable entries.
//
// Usage:  java CipherSuiteCheck.java
// Requires: JDK 17+
// ============================================================================

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

public class CipherSuiteCheck {

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

    // Quantum-vulnerable cipher suite patterns
    static final Pattern VULN_CIPHER = Pattern.compile(
            "(?i)(RSA|ECDSA|ECDHE|DHE|ECDH|_DSS_)"
    );

    // Post-quantum named group patterns
    static final Pattern PQC_GROUP = Pattern.compile(
            "(?i)(MLKEM|ML-KEM|X25519MLKEM|SecP256r1MLKEM|SecP384r1MLKEM)"
    );

    // Quantum-vulnerable named group patterns
    static final Pattern VULN_GROUP = Pattern.compile(
            "(?i)(x25519|x448|secp256r1|secp384r1|secp521r1|ffdhe|brainpool"
          + "|sect\\d|prime\\d|X25519$|X448$)"
    );

    public static void main(String[] args) throws Exception {
        banner("SSL/TLS CIPHER SUITE & NAMED GROUP AUDIT");
        System.out.printf("  %sJava version:%s %s%n", BOLD, RESET,
                System.getProperty("java.version"));
        System.out.printf("  %sJava vendor:%s  %s%n", BOLD, RESET,
                System.getProperty("java.vendor"));
        System.out.printf("  %sJSSE provider:%s %s%n%n", BOLD, RESET,
                SSLContext.getDefault().getProvider().getName());

        // ── Supported protocols ──
        SSLContext ctx = SSLContext.getDefault();
        SSLParameters params = ctx.getDefaultSSLParameters();

        String[] supportedProtocols = params.getProtocols();
        String[] enabledProtocols = ctx.createSSLEngine().getEnabledProtocols();

        section("SUPPORTED PROTOCOLS");
        for (String proto : supportedProtocols) {
            boolean enabled = Arrays.asList(enabledProtocols).contains(proto);
            String marker = enabled ? GREEN + "✅ ENABLED" : DIM + "⬚  disabled";
            System.out.printf("    %s%-12s%s  %s%s%n", BOLD, proto, RESET, marker, RESET);
        }
        System.out.println();

        // ── Cipher suites ──
        section("CIPHER SUITES");

        String[] defaultCiphers = params.getCipherSuites();
        String[] supportedCiphers = ctx.createSSLEngine().getSupportedCipherSuites();

        // Group by protocol hint (TLS 1.3 vs TLS 1.2/earlier)
        Map<String, Set<String>> grouped = new LinkedHashMap<>();
        grouped.put("TLS 1.3", new TreeSet<>());
        grouped.put("TLS 1.2 and earlier", new TreeSet<>());

        Set<String> defaultSet = Set.of(defaultCiphers);

        int totalCiphers = 0;
        int vulnCiphers = 0;
        int tls13Count = 0;

        for (String cipher : supportedCiphers) {
            totalCiphers++;
            // TLS 1.3 cipher suites start with TLS_ and use AEAD
            if (cipher.startsWith("TLS_AES_") || cipher.startsWith("TLS_CHACHA20_")) {
                grouped.get("TLS 1.3").add(cipher);
                tls13Count++;
            } else {
                grouped.get("TLS 1.2 and earlier").add(cipher);
                if (VULN_CIPHER.matcher(cipher).find()) {
                    vulnCiphers++;
                }
            }
        }

        for (var entry : grouped.entrySet()) {
            String group = entry.getKey();
            Set<String> ciphers = entry.getValue();

            System.out.printf("  %s%s── %s (%d suites) ──%s%n", MAGENTA, BOLD, group, ciphers.size(), RESET);

            for (String cipher : ciphers) {
                boolean isDefault = defaultSet.contains(cipher);
                String colour;
                String tag;

                if (group.equals("TLS 1.3")) {
                    // TLS 1.3 cipher suites use AEAD only — key exchange is separate
                    colour = GREEN;
                    tag = isDefault ? "default" : "";
                } else if (VULN_CIPHER.matcher(cipher).find()) {
                    colour = RED;
                    tag = "Quantum-Vulnerable" + (isDefault ? ", default" : "");
                } else {
                    colour = DIM;
                    tag = isDefault ? "default" : "";
                }

                if (!tag.isEmpty()) {
                    System.out.printf("    %s%-55s%s  %s(%s)%s%n",
                            colour, cipher, RESET, colour, tag, RESET);
                } else {
                    System.out.printf("    %s%s%s%n", colour, cipher, RESET);
                }
            }
            System.out.println();
        }

        // ── Named groups (key exchange curves) ──
        section("NAMED GROUPS (Key Exchange)");

        // SSLParameters.getNamedGroups() is available from JDK 20+
        String[] namedGroups = null;
        try {
            namedGroups = params.getNamedGroups();
        } catch (NoSuchMethodError e) {
            // JDK < 20 does not have this method
        }

        int totalGroups = 0;
        int pqcGroups = 0;
        int vulnGroups = 0;

        if (namedGroups != null && namedGroups.length > 0) {
            for (String group : namedGroups) {
                totalGroups++;
                String colour;
                String tag;

                if (PQC_GROUP.matcher(group).find()) {
                    colour = GREEN;
                    tag = "Post-Quantum ✨";
                    pqcGroups++;
                } else if (VULN_GROUP.matcher(group).find()) {
                    colour = RED;
                    tag = "Quantum-Vulnerable (ECDLP/DLP)";
                    vulnGroups++;
                } else {
                    colour = DIM;
                    tag = "";
                }

                if (!tag.isEmpty()) {
                    System.out.printf("    %s%-30s%s  %s(%s)%s%n",
                            colour, group, RESET, colour, tag, RESET);
                } else {
                    System.out.printf("    %s%s%s%n", colour, group, RESET);
                }
            }
        } else {
            System.out.printf("    %s(SSLParameters.getNamedGroups() not available — requires JDK 20+)%s%n",
                    DIM, RESET);
            System.out.printf("    %sTip: use -Djdk.tls.namedGroups to configure named groups%s%n",
                    DIM, RESET);
        }
        System.out.println();

        // ── Summary ──
        banner("AUDIT SUMMARY");

        System.out.printf("  %sCipher Suites%s%n", BOLD, RESET);
        System.out.printf("    Total supported:       %s%d%s%n", WHITE, totalCiphers, RESET);
        System.out.printf("    TLS 1.3 (AEAD-only):   %s%s%d%s%n", GREEN, WHITE, tls13Count, RESET);
        System.out.printf("    TLS 1.2 and earlier:   %s%d%s%n", WHITE, totalCiphers - tls13Count, RESET);
        System.out.printf("    %sQuantum-Vulnerable:%s     %s%d%s  %s(key exchange uses RSA/ECDHE/DHE)%s%n",
                RED, RESET, WHITE, vulnCiphers, RESET, DIM, RESET);
        System.out.printf("    Enabled by default:    %s%d%s%n%n", WHITE, defaultCiphers.length, RESET);

        System.out.printf("  %sNamed Groups (Key Exchange)%s%n", BOLD, RESET);
        if (namedGroups != null) {
            System.out.printf("    Total available:       %s%d%s%n", WHITE, totalGroups, RESET);
            System.out.printf("    %s✅ Post-Quantum:%s         %s%d%s%n", GREEN, RESET, WHITE, pqcGroups, RESET);
            System.out.printf("    %s🔴 Quantum-Vulnerable:%s  %s%d%s%n", RED, RESET, WHITE, vulnGroups, RESET);
        } else {
            System.out.printf("    %s(not available — JDK 20+ required)%s%n", DIM, RESET);
        }
        System.out.println();

        // ── Recommendations ──
        System.out.printf("  %s────────────────────────────────────────────────%s%n", CYAN, RESET);
        System.out.printf("  %sRECOMMENDATIONS:%s%n", BOLD, RESET);

        // Check TLS 1.3
        boolean hasTls13 = Arrays.asList(enabledProtocols).contains("TLSv1.3");
        if (hasTls13) {
            System.out.printf("    %s✅ TLS 1.3 is enabled — good.%s%n", GREEN, RESET);
        } else {
            System.out.printf("    %s⚠  TLS 1.3 is NOT enabled — upgrade before adding PQC.%s%n", YELLOW, RESET);
        }

        // Check PQC named groups
        if (pqcGroups > 0) {
            System.out.printf("    %s✅ PQC named groups detected (X25519MLKEM768 etc.) — hybrid PQC TLS is available!%s%n",
                    GREEN, RESET);
        } else {
            System.out.printf("    %s⚠  No PQC named groups found. Upgrade to JDK 27 for JEP 527 (hybrid PQC TLS).%s%n",
                    YELLOW, RESET);
            System.out.printf("    → Or add Bouncy Castle JSSE (BCJSSE) provider for PQC named groups on JDK 24-26.%n");
        }

        System.out.printf("    → Prefer TLS_AES_256_GCM_SHA384 and TLS_CHACHA20_POLY1305_SHA256 for TLS 1.3.%n");
        System.out.printf("    → Disable TLS 1.0/1.1 if still enabled.%n");
        System.out.printf("  %s────────────────────────────────────────────────%s%n", CYAN, RESET);
        System.out.println();
    }

    static void banner(String title) {
        System.out.println();
        System.out.printf("%s============================================================%s%n", CYAN, RESET);
        System.out.printf("%s%s%s%n", WHITE, title, RESET);
        System.out.printf("%s============================================================%s%n", CYAN, RESET);
        System.out.println();
    }

    static void section(String title) {
        System.out.printf("  %s%s── %s ──%s%n%n", CYAN, BOLD, title, RESET);
    }
}
