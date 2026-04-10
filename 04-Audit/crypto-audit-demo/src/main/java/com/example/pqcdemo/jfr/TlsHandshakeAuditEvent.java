package com.example.pqcdemo.jfr;

import jdk.jfr.*;

/**
 * Custom JFR event that fills the gap in {@code jdk.TLSHandshake}:
 * the built-in event does not expose the negotiated named group, which is
 * the key field needed to verify that a hybrid PQC key-exchange (e.g.
 * {@code X25519MLKEM768}) was actually used.
 *
 * <p>Fire this event after every outbound TLS handshake in the demo by calling
 * {@link #begin()}, populating the fields, then {@link #commit()}.
 *
 * <p><b>JVM args required for negotiatedNamedGroup capture:</b>
 * {@code --add-opens java.base/sun.security.ssl=ALL-UNNAMED}
 */
@Name("com.example.pqcdemo.TlsHandshakeAudit")
@Label("TLS Handshake Audit")
@Description("Named-group capture for PQC audit — fills the gap in jdk.TLSHandshake")
@Category({"Security", "PQC Audit"})
@StackTrace(false)
public class TlsHandshakeAuditEvent extends Event {

    @Label("Target URL")
    public String targetUrl;

    @Label("TLS Version")
    public String tlsVersion;

    @Label("Cipher Suite")
    public String cipherSuite;

    /**
     * The named group that was actually negotiated for key exchange.
     * Captured during certificate validation from JSSE handshake internals
     * ({@code key_share} server share).
     * Value is {@code "unavailable"} if {@code --add-opens} is missing.
     */
    @Label("Negotiated Named Group")
    public String negotiatedNamedGroup;

    /**
     * Comma-separated list of named groups configured in the {@code SSLContext}
     * (from {@code SSLParameters.getNamedGroups()}, Java 21+ standard API).
     * Shows whether hybrid groups like {@code X25519MLKEM768} are enabled.
     */
    @Label("Configured Named Groups")
    public String configuredNamedGroups;

    @Label("Cert Signature Algorithm")
    public String certSigAlgorithm;

    @Label("Peer Subject")
    public String peerSubject;
}
