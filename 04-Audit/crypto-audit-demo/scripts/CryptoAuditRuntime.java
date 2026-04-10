///usr/bin/env java --enable-preview "$0" "$@"; exit $?
// ============================================================================
// CryptoAuditRuntime.java — JFR-Based Runtime Cryptographic Usage Auditor
//
// Attaches to a running local JVM on the same host via Attach API + JMX
// and captures actual cryptographic operations in real time: TLS handshakes,
// X.509 certificate validations, deserialization events, and security
// property changes.
//
// This is the runtime-evidence half of Layer 4 in the 4-layer crypto audit.
// It complements the static analysis done by crypto-audit.sh (Layers 1-3)
// and the capability inventory provided by CryptoAuditJce.java and
// CipherSuiteCheck.java.
//
// Usage:
//   Attach to running process:
//     java scripts/CryptoAuditRuntime.java --pid <pid> [--duration <seconds>]
//   Record from JFR file:
//     java scripts/CryptoAuditRuntime.java --file <recording.jfr>
//
// Requires: JDK 17+ (JDK 24+ for full event coverage)
// ============================================================================

import com.sun.tools.attach.VirtualMachine;
import jdk.jfr.consumer.EventStream;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;
import jdk.management.jfr.RemoteRecordingStream;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;

public class CryptoAuditRuntime {

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
    static final Pattern QUANTUM_VULN = Pattern.compile(
            "(?i)(RSA|(?<!ML-)(?<!SLH-)DSA|ECDSA|ECDH|DiffieHellman|DHKEM|\\bEC\\b"
          + "|X25519|X448|Ed25519|Ed448|XDH|EdDSA)"
    );

    static final Pattern PQC_ALGO = Pattern.compile(
            "(?i)(ML-KEM|ML_KEM|MLKEM|ML-DSA|ML_DSA|MLDSA"
          + "|SLH-DSA|SLH_DSA|SLHDSA|HQC)"
    );

    static final Pattern PQC_NAMED_GROUP = Pattern.compile(
            "(?i)(MLKEM|ML-KEM|X25519MLKEM|SecP256r1MLKEM|SecP384r1MLKEM)"
    );

    static final Pattern VULN_NAMED_GROUP = Pattern.compile(
            "(?i)(x25519|x448|secp256r1|secp384r1|secp521r1|ffdhe|brainpool"
          + "|sect\\d|prime\\d|X25519$|X448$)"
    );

    // Counters
    static final Map<String, AtomicInteger> tlsCipherSuites = new ConcurrentHashMap<>();
    static final Map<String, AtomicInteger> tlsProtocols = new ConcurrentHashMap<>();
    static final Map<String, AtomicInteger> tlsNamedGroups = new ConcurrentHashMap<>();
    static final Map<String, AtomicInteger> certAlgorithms = new ConcurrentHashMap<>();
    static final Map<String, AtomicInteger> deserializationTypes = new ConcurrentHashMap<>();
    static final Map<String, String> securityPropertyChanges = new ConcurrentHashMap<>();
    static final List<String> classLoads = Collections.synchronizedList(new ArrayList<>());

    static final AtomicInteger tlsHandshakeCount = new AtomicInteger();
    static final AtomicInteger certValidationCount = new AtomicInteger();
    static final AtomicInteger deserializationCount = new AtomicInteger();
    static final AtomicInteger secPropChangeCount = new AtomicInteger();

    // Vulnerability counters
    static final AtomicInteger legacyVulnCipherSuites = new AtomicInteger();
    static final AtomicInteger pqcNamedGroupsObserved = new AtomicInteger();
    static final AtomicInteger vulnNamedGroupsObserved = new AtomicInteger();
    static final AtomicInteger tls13WithoutNamedGroupVisibility = new AtomicInteger();
    static final AtomicInteger vulnCertAlgos = new AtomicInteger();
    static final AtomicInteger pqcCertAlgos = new AtomicInteger();

    static final Duration STREAM_RETENTION = Duration.ofMinutes(5);
    static final String LOCAL_JMX_CONNECTOR_ADDRESS = "com.sun.management.jmxremote.localConnectorAddress";

    public static void main(String[] args) throws Exception {
        int duration = 30; // default 30 seconds
        String jfrFile = null;
        String pid = null;
        boolean durationSpecified = false;

        // Parse arguments
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--duration", "-d" -> {
                    duration = Integer.parseInt(requireValue(args, ++i, "--duration"));
                    durationSpecified = true;
                }
                case "--file", "-f" -> jfrFile = requireValue(args, ++i, "--file");
                case "--pid", "-p" -> pid = requireValue(args, ++i, "--pid");
                case "--help", "-h" -> { printUsage(); return; }
                default -> throw new IllegalArgumentException("Unknown option: " + args[i]);
            }
        }

        if (duration <= 0) {
            throw new IllegalArgumentException("Duration must be greater than zero");
        }
        if (pid != null && jfrFile != null) {
            throw new IllegalArgumentException("--pid and --file are mutually exclusive");
        }
        if (pid == null && jfrFile == null) {
            throw new IllegalArgumentException("Either --pid or --file is required. Self-audit mode has been removed.");
        }
        if (durationSpecified && pid == null) {
            throw new IllegalArgumentException("--duration requires --pid");
        }

        banner("JFR RUNTIME CRYPTOGRAPHIC AUDIT");
        System.out.printf("  %sJava version:%s %s%n", BOLD, RESET, System.getProperty("java.version"));
        System.out.printf("  %sJava vendor:%s  %s%n", BOLD, RESET, System.getProperty("java.vendor"));

        if (pid != null) {
            System.out.printf("  %sMode:%s         Live recording (target JVM)%n", BOLD, RESET);
            System.out.printf("  %sPID:%s          %s%n", BOLD, RESET, pid);
            System.out.printf("  %sDuration:%s     %d seconds%n%n", BOLD, RESET, duration);
            liveRecordTargetJvm(pid, duration);
        } else if (jfrFile != null) {
            System.out.printf("  %sMode:%s         Analysing JFR recording file%n", BOLD, RESET);
            System.out.printf("  %sFile:%s         %s%n%n", BOLD, RESET, jfrFile);
            analyseRecordingFile(Path.of(jfrFile));
        }

        printSummary();
    }

    static void liveRecordTargetJvm(String pid, int durationSeconds) throws Exception {
        System.out.printf("  %sConnecting to target JVM %s via local JMX…%s%n", CYAN, pid, RESET);
        System.out.printf("  %sThe script will start a temporary local management agent if needed.%s%n%n", DIM, RESET);

        var latch = new CountDownLatch(1);
        JMXConnector connector = connectToTargetJvm(pid);
        try (var rs = new RemoteRecordingStream(connector.getMBeanServerConnection())) {
            configureSecurityEvents(rs, latch);

            rs.startAsync();

            printRuntimeCaptureGuidance(durationSeconds,
                    "Generate HTTPS traffic against the target JVM while this stream is active.");

            latch.await(durationSeconds, TimeUnit.SECONDS);
            rs.stop();
        } finally {
            closeJmxConnector(connector, pid);
        }
    }

    static void analyseRecordingFile(Path path) throws IOException {
        System.out.printf("  %sParsing JFR recording…%s%n%n", CYAN, RESET);

        try (var rf = new RecordingFile(path)) {
            while (rf.hasMoreEvents()) {
                RecordedEvent event = rf.readEvent();
                String name = event.getEventType().getName();

                switch (name) {
                    case "jdk.TLSHandshake" -> handleTlsHandshake(event);
                    case "jdk.X509Validation" -> handleX509Validation(event);
                    case "jdk.X509Certificate" -> handleX509Certificate(event);
                    case "jdk.SecurityPropertyModification" -> handleSecurityPropertyModification(event);
                    case "jdk.Deserialization" -> handleDeserialization(event);
                }
            }
        }
    }

    static void configureSecurityEvents(RemoteRecordingStream stream, CountDownLatch latch) {
        stream.setMaxAge(STREAM_RETENTION);
        enableSecurityEvents(stream);
        registerEventHandlers(stream, latch);
    }

    static void enableSecurityEvents(RemoteRecordingStream stream) {
        stream.enable("jdk.TLSHandshake").withStackTrace();
        stream.enable("jdk.X509Validation").withStackTrace();
        stream.enable("jdk.X509Certificate").withStackTrace();
        stream.enable("jdk.SecurityPropertyModification").withStackTrace();
        stream.enable("jdk.Deserialization").withStackTrace();
        stream.enable("jdk.SerializationMisdeclaration");
        stream.enable("jdk.InitialSecurityProperty");
    }

    static void registerEventHandlers(EventStream stream, CountDownLatch latch) {
        stream.onEvent("jdk.TLSHandshake", CryptoAuditRuntime::handleTlsHandshake);
        stream.onEvent("jdk.X509Validation", CryptoAuditRuntime::handleX509Validation);
        stream.onEvent("jdk.X509Certificate", CryptoAuditRuntime::handleX509Certificate);
        stream.onEvent("jdk.SecurityPropertyModification", CryptoAuditRuntime::handleSecurityPropertyModification);
        stream.onEvent("jdk.Deserialization", CryptoAuditRuntime::handleDeserialization);
        stream.onEvent("jdk.SerializationMisdeclaration", CryptoAuditRuntime::handleSerializationMisdeclaration);
        stream.onError(error -> {
            System.err.printf("  %sJFR stream error:%s %s%n", RED, RESET, error.getMessage());
            latch.countDown();
        });
        stream.onClose(latch::countDown);
    }

    static JMXConnector connectToTargetJvm(String pid) throws Exception {
        VirtualMachine vm = VirtualMachine.attach(pid);
        try {
            String connectorAddress = vm.getAgentProperties().getProperty(LOCAL_JMX_CONNECTOR_ADDRESS);
            if (connectorAddress == null || connectorAddress.isBlank()) {
                connectorAddress = vm.startLocalManagementAgent();
            }
            if (connectorAddress == null || connectorAddress.isBlank()) {
                throw new IOException("Could not obtain local JMX connector address for PID " + pid);
            }
            return JMXConnectorFactory.connect(new JMXServiceURL(connectorAddress));
        } finally {
            vm.detach();
        }
    }

    static void closeJmxConnector(JMXConnector connector, String pid) {
        if (connector == null) {
            return;
        }
        try {
            connector.close();
        } catch (IOException e) {
            System.err.printf("  %sWarning:%s failed to close JMX connector for PID %s cleanly: %s%n",
                    YELLOW, RESET, pid, e.getMessage());
        }
    }

    // ── Event Handlers ──

    static void handleTlsHandshake(RecordedEvent event) {
        tlsHandshakeCount.incrementAndGet();

        String cipher = getField(event, "cipherSuite", "unknown");
        String protocol = getField(event, "protocolVersion", "unknown");
        String namedGroup = getOptionalField(event,
                "namedGroup",
                "namedGroupName",
                "group",
                "keyExchangeGroup",
                "negotiatedNamedGroup");

        tlsCipherSuites.computeIfAbsent(cipher, k -> new AtomicInteger()).incrementAndGet();
        tlsProtocols.computeIfAbsent(protocol, k -> new AtomicInteger()).incrementAndGet();

        // TLS 1.3 cipher suites are AEAD-only, so they do not reveal the
        // negotiated key exchange group. Only classify legacy suites directly.
        if (!protocol.startsWith("TLSv1.3") && QUANTUM_VULN.matcher(cipher).find()) {
            legacyVulnCipherSuites.incrementAndGet();
        }

        if (namedGroup != null) {
            tlsNamedGroups.computeIfAbsent(namedGroup, k -> new AtomicInteger()).incrementAndGet();
            if (PQC_NAMED_GROUP.matcher(namedGroup).find()) {
                pqcNamedGroupsObserved.incrementAndGet();
            } else if (VULN_NAMED_GROUP.matcher(namedGroup).find()) {
                vulnNamedGroupsObserved.incrementAndGet();
            }
        } else if (protocol.startsWith("TLSv1.3")) {
            tls13WithoutNamedGroupVisibility.incrementAndGet();
        }

        if (namedGroup != null) {
            System.out.printf("    %s🔗 TLS: %s (%s) [group=%s]%s%n", DIM, cipher, protocol, namedGroup, RESET);
        } else if (protocol.startsWith("TLSv1.3")) {
            System.out.printf("    %s🔗 TLS: %s (%s) [key exchange group not exposed by jdk.TLSHandshake]%s%n",
                    DIM, cipher, protocol, RESET);
        } else {
            System.out.printf("    %s🔗 TLS: %s (%s)%s%n", DIM, cipher, protocol, RESET);
        }
    }

    static void handleX509Validation(RecordedEvent event) {
        certValidationCount.incrementAndGet();
    }

    static void handleX509Certificate(RecordedEvent event) {
        String algo = getField(event, "algorithm", "unknown");

        certAlgorithms.computeIfAbsent(algo, k -> new AtomicInteger()).incrementAndGet();

        if (QUANTUM_VULN.matcher(algo).find()) {
            vulnCertAlgos.incrementAndGet();
        } else if (PQC_ALGO.matcher(algo).find()) {
            pqcCertAlgos.incrementAndGet();
        }
    }

    static void handleSecurityPropertyModification(RecordedEvent event) {
        secPropChangeCount.incrementAndGet();

        String key = getField(event, "key", "unknown");
        String newValue = getField(event, "newValue", "");

        securityPropertyChanges.put(key, newValue);

        // This is always critical — runtime security property changes are almost never legitimate
        System.out.printf("    %s🔴 SECURITY PROPERTY CHANGED: %s = %s%s%n", RED, key, newValue, RESET);
    }

    static void handleDeserialization(RecordedEvent event) {
        deserializationCount.incrementAndGet();

        String type = getField(event, "type", "unknown");
        String filterStatus = getField(event, "filterStatus", "UNDECIDED");

        deserializationTypes.computeIfAbsent(type + " (" + filterStatus + ")", k -> new AtomicInteger())
                .incrementAndGet();

        if ("REJECTED".equals(filterStatus)) {
            System.out.printf("    %s🔴 DESERIALIZATION REJECTED: %s%s%n", RED, type, RESET);
        }
    }

    static void handleSerializationMisdeclaration(RecordedEvent event) {
        String cls = getField(event, "misdeclaredClass", "unknown");
        String msg = getField(event, "message", "");
        System.out.printf("    %s⚠  Serialization misdeclaration: %s — %s%s%n", YELLOW, cls, msg, RESET);
    }

    // ── Summary ──

    static void printSummary() {
        banner("RUNTIME CRYPTO AUDIT SUMMARY");

        // TLS
        section("TLS Handshakes");
        System.out.printf("    %sTotal handshakes observed:%s %d%n", BOLD, RESET, tlsHandshakeCount.get());

        if (!tlsCipherSuites.isEmpty()) {
            System.out.printf("    %sCipher suites in use:%s%n", BOLD, RESET);
            tlsCipherSuites.entrySet().stream()
                    .sorted(Map.Entry.<String, AtomicInteger>comparingByValue(
                            Comparator.comparingInt(AtomicInteger::get)).reversed())
                    .forEach(e -> {
                        String cipher = e.getKey();
                        boolean legacyVisibleKeyExchange = !cipher.startsWith("TLS_AES_")
                                && !cipher.startsWith("TLS_CHACHA20_")
                                && QUANTUM_VULN.matcher(cipher).find();
                        String colour = legacyVisibleKeyExchange ? RED : DIM;
                        String tag = legacyVisibleKeyExchange
                                ? " 🔴 Classical key exchange visible in cipher suite"
                                : "";
                        System.out.printf("      %s%-50s %dx%s%s%n", colour, cipher, e.getValue().get(), tag, RESET);
                    });
        }

        if (!tlsProtocols.isEmpty()) {
            System.out.printf("    %sProtocol versions:%s%n", BOLD, RESET);
            tlsProtocols.forEach((proto, count) ->
                    System.out.printf("      %s%-20s %dx%s%n", DIM, proto, count.get(), RESET));
        }

        if (!tlsNamedGroups.isEmpty()) {
            System.out.printf("    %sNamed groups observed:%s%n", BOLD, RESET);
            tlsNamedGroups.entrySet().stream()
                    .sorted(Map.Entry.<String, AtomicInteger>comparingByValue(
                            Comparator.comparingInt(AtomicInteger::get)).reversed())
                    .forEach(e -> {
                        String group = e.getKey();
                        boolean pqc = PQC_NAMED_GROUP.matcher(group).find();
                        boolean classical = VULN_NAMED_GROUP.matcher(group).find();
                        String colour = pqc ? GREEN : classical ? RED : DIM;
                        String tag = pqc ? " ✨ Post-Quantum / Hybrid"
                                : classical ? " 🔴 Classical group" : "";
                        System.out.printf("      %s%-30s %dx%s%s%n", colour, group, e.getValue().get(), tag, RESET);
                    });
        } else if (tls13WithoutNamedGroupVisibility.get() > 0) {
            System.out.printf("    %sNamed groups:%s not exposed by jdk.TLSHandshake in this JDK build%n",
                    BOLD, RESET);
            System.out.printf("    %sRuntime evidence proves TLS activity, but not whether TLS 1.3 used classical or hybrid key establishment.%s%n",
                    YELLOW, RESET);
            System.out.printf("    %sInspect capability separately with java ../ciphercheck-demo/CipherSuiteCheck.java.%s%n",
                    DIM, RESET);
        }
        System.out.println();

        // Certificates
        section("Certificate Algorithms Observed");
        System.out.printf("    %sCertificate validations:%s %d%n", BOLD, RESET, certValidationCount.get());

        if (!certAlgorithms.isEmpty()) {
            certAlgorithms.forEach((algo, count) -> {
                String colour = QUANTUM_VULN.matcher(algo).find() ? RED :
                               PQC_ALGO.matcher(algo).find() ? GREEN : DIM;
                String tag = QUANTUM_VULN.matcher(algo).find() ? " 🔴 Quantum-Vulnerable" :
                            PQC_ALGO.matcher(algo).find() ? " ✨ Post-Quantum" : "";
                System.out.printf("      %s%-40s %dx%s%s%n", colour, algo, count.get(), tag, RESET);
            });
        }
        System.out.println();

        // Security Property Changes
        section("Security Property Modifications");
        if (secPropChangeCount.get() > 0) {
            System.out.printf("    %s🔴 CRITICAL: %d security property changes detected!%s%n",
                    RED, secPropChangeCount.get(), RESET);
            securityPropertyChanges.forEach((key, value) ->
                    System.out.printf("      %s%s = %s%s%n", RED, key, value, RESET));
        } else {
            System.out.printf("    %s✅ No security property modifications (good)%s%n", GREEN, RESET);
        }
        System.out.println();

        // Deserialization
        section("Deserialization Events");
        System.out.printf("    %sTotal deserialization events:%s %d%n", BOLD, RESET, deserializationCount.get());
        if (!deserializationTypes.isEmpty()) {
            deserializationTypes.entrySet().stream()
                    .sorted(Map.Entry.<String, AtomicInteger>comparingByValue(
                            Comparator.comparingInt(AtomicInteger::get)).reversed())
                    .limit(10)
                    .forEach(e -> System.out.printf("      %s%-50s %dx%s%n", DIM, e.getKey(), e.getValue().get(), RESET));
        }
        System.out.println();

        // Overall verdict
        banner("QUANTUM READINESS VERDICT");
        int totalVuln = legacyVulnCipherSuites.get() + vulnNamedGroupsObserved.get() + vulnCertAlgos.get();
        int totalPqc = pqcNamedGroupsObserved.get() + pqcCertAlgos.get();

        System.out.printf("  %sRuntime crypto operations observed:%s%n", BOLD, RESET);
        System.out.printf("    TLS handshakes:        %d%n", tlsHandshakeCount.get());
        System.out.printf("    Cert validations:      %d%n", certValidationCount.get());
        System.out.printf("    Deserializations:      %d%n", deserializationCount.get());
        System.out.printf("    Security prop changes: %d%n%n", secPropChangeCount.get());

        if (totalVuln > 0) {
            System.out.printf("  %s🔴 QUANTUM-VULNERABLE operations detected: %d%s%n", RED, totalVuln, RESET);
            if (legacyVulnCipherSuites.get() > 0) {
                System.out.printf("     → Legacy TLS cipher suites with classical key exchange visible: %d%n",
                        legacyVulnCipherSuites.get());
            }
            if (vulnNamedGroupsObserved.get() > 0) {
                System.out.printf("     → Named groups observed as classical-only: %d%n", vulnNamedGroupsObserved.get());
            }
            if (vulnCertAlgos.get() > 0) {
                System.out.printf("     → Certificates with RSA/ECDSA/DSA: %d%n", vulnCertAlgos.get());
            }
        }
        if (totalPqc > 0) {
            System.out.printf("  %s✅ POST-QUANTUM operations detected: %d%s%n", GREEN, totalPqc, RESET);
            if (pqcNamedGroupsObserved.get() > 0) {
                System.out.printf("     → Named groups observed as hybrid/PQC-capable: %d%n", pqcNamedGroupsObserved.get());
            }
            if (pqcCertAlgos.get() > 0) {
                System.out.printf("     → Certificate algorithms observed as PQC: %d%n", pqcCertAlgos.get());
            }
        }

        if (tls13WithoutNamedGroupVisibility.get() > 0) {
            System.out.printf("  %s🟡 TLS 1.3 handshakes observed, but the negotiated named group is not exposed by jdk.TLSHandshake in this JDK build.%s%n",
                    YELLOW, RESET);
            System.out.printf("     → This tool proves TLS activity, not classical vs hybrid key exchange.%n");
        }

        if (tlsHandshakeCount.get() == 0 && certValidationCount.get() == 0) {
            System.out.printf("  %s⚠  No TLS/cert events captured. Generate HTTPS traffic during recording.%s%n",
                    YELLOW, RESET);
            System.out.printf("  %s   Tip: curl https://localhost:8443/ or trigger JWT operations.%s%n", DIM, RESET);
        }

        System.out.println();
        System.out.printf("  %s────────────────────────────────────────────────%s%n", CYAN, RESET);
        System.out.printf("  %sRECOMMENDATIONS:%s%n", BOLD, RESET);
        System.out.printf("    → Treat this tool as runtime evidence: it shows what the JVM exercised under traffic%n");
        System.out.printf("    → Pair it with capability audit: java scripts/CryptoAuditJce.java%n");
        System.out.printf("    → Inspect JSSE named groups separately: java ../ciphercheck-demo/CipherSuiteCheck.java%n");
        if (legacyVulnCipherSuites.get() > 0 || vulnNamedGroupsObserved.get() > 0) {
            System.out.printf("    → Migrate classical key establishment to ML-KEM / hybrid TLS named groups%n");
        }
        if (vulnCertAlgos.get() > 0) {
            System.out.printf("    → Track certificate/signature migration separately from key establishment%n");
        }
        if (secPropChangeCount.get() > 0) {
            System.out.printf("    %s→ INVESTIGATE: Runtime security property changes are a red flag!%s%n", RED, RESET);
        }
        System.out.printf("    → Combine with static inventory: ./scripts/crypto-audit.sh%n");
        System.out.printf("  %s────────────────────────────────────────────────%s%n", CYAN, RESET);
        System.out.println();
    }

    // ── Helpers ──

    static String requireValue(String[] args, int index, String option) {
        if (index >= args.length) {
            throw new IllegalArgumentException("Missing value for " + option);
        }
        return args[index];
    }

    static void printRuntimeCaptureGuidance(int durationSeconds, String trafficHint) {
        System.out.printf("  %sRecording for %d seconds…%s%n", YELLOW, durationSeconds, RESET);
        System.out.printf("  %sNote: All security events (TLS, X.509, Deserialization, SecurityProperty)%s%n", DIM, RESET);
        System.out.printf("  %sare disabled in default.jfc — this script enables them explicitly.%s%n", DIM, RESET);
        System.out.printf("  %sTLSHandshake gives protocolVersion and cipherSuite in this JDK build;%s%n", DIM, RESET);
        System.out.printf("  %snegotiated named groups may require a separate capability check.%s%n", DIM, RESET);
        System.out.printf("  %s%s%s%n", DIM, trafficHint, RESET);
        System.out.printf("  %s  curl https://localhost:8443/   or   curl https://example.com%s%n%n", DIM, RESET);
    }

    static String getField(RecordedEvent event, String fieldName, String defaultValue) {
        try {
            var value = event.getValue(fieldName);
            return value != null ? value.toString() : defaultValue;
        } catch (Exception e) {
            return defaultValue;
        }
    }

    static String getOptionalField(RecordedEvent event, String... fieldNames) {
        for (String fieldName : fieldNames) {
            String value = getField(event, fieldName, null);
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    static void banner(String title) {
        System.out.println();
        System.out.printf("%s============================================================%s%n", CYAN, RESET);
        System.out.printf("%s%s%s%n", WHITE, title, RESET);
        System.out.printf("%s============================================================%s%n", CYAN, RESET);
        System.out.println();
    }

    static void section(String title) {
        System.out.printf("  %s%s── %s ──%s%n", MAGENTA, BOLD, title, RESET);
    }

    static void printUsage() {
        System.out.println("CryptoAuditRuntime — JFR-Based Runtime Cryptographic Usage Auditor");
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  java CryptoAuditRuntime.java --pid <process-id> [--duration <seconds>]");
        System.out.println("  java CryptoAuditRuntime.java --file <path.jfr>");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --pid <process-id>     Attach to a running local JVM by PID (same host only)");
        System.out.println("  --duration <seconds>   Recording duration for --pid mode (default: 30)");
        System.out.println("  --file <path.jfr>      Analyse existing JFR recording file");
        System.out.println("  --help                 Show this help");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  # Stream security events from a running local JVM on this host:");
        System.out.println("  java CryptoAuditRuntime.java --pid 12345 --duration 60");
        System.out.println();
        System.out.println("  # Analyse a saved JFR recording:");
        System.out.println("  java CryptoAuditRuntime.java --file /tmp/recording.jfr");
        System.out.println();
        System.out.println("  # Create a recording from a running app:");
        System.out.println("  jcmd <pid> JFR.start duration=60s filename=/tmp/recording.jfr");
        System.out.println("  java CryptoAuditRuntime.java --file /tmp/recording.jfr");
    }
}
