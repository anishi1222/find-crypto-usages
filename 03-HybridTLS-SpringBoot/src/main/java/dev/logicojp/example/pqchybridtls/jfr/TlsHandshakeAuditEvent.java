package dev.logicojp.example.pqchybridtls.jfr;

import jdk.jfr.Category;
import jdk.jfr.Description;
import jdk.jfr.Event;
import jdk.jfr.Label;
import jdk.jfr.Name;
import jdk.jfr.StackTrace;

@Name("dev.logicojp.example.pqchybridtls.TlsHandshakeAudit")
@Label("TLS Handshake Audit")
@Description("Named-group capture for Hybrid TLS audits that complements jdk.TLSHandshake")
@Category({"Security", "PQC Audit"})
@StackTrace(true)
public class TlsHandshakeAuditEvent extends Event {

    @Label("Target URL")
    public String targetUrl;

    @Label("TLS Version")
    public String tlsVersion;

    @Label("Cipher Suite")
    public String cipherSuite;

    @Label("Negotiated Named Group")
    public String negotiatedNamedGroup;

    @Label("Configured Named Groups")
    public String configuredNamedGroups;

    @Label("Cert Signature Algorithm")
    public String certSigAlgorithm;

    @Label("Peer Subject")
    public String peerSubject;
}
