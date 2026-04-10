package com.example.pqcdemo.service;

import com.example.pqcdemo.jfr.TlsHandshakeAuditEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import java.lang.reflect.Field;
import java.lang.reflect.InaccessibleObjectException;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.Socket;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Triggers outbound HTTPS certificate validation inside the same JVM.
 *
 * <p>The app exposes HTTPS with a local CA-signed certificate chain. This
 * service loads the trust anchor into an in-memory trust store, then performs
 * an HTTPS call back to the demo app. That path gives JFR a realistic way to
 * emit {@code jdk.X509Validation} events during the demo.</p>
 */
@Service
public class X509ValidationDemoService {

    private static final Logger log = LoggerFactory.getLogger(X509ValidationDemoService.class);
    private static final String ADD_OPENS_HINT = "unavailable (add --add-opens java.base/sun.security.ssl=ALL-UNNAMED)";

    private final ResourceLoader resourceLoader;
    private final String keystorePath;
    private final String keystorePassword;
    private final String keyAlias;
    private final String targetUrl;

    public X509ValidationDemoService(
            ResourceLoader resourceLoader,
            @Value("${server.ssl.key-store}") String keystorePath,
            @Value("${server.ssl.key-store-password}") String keystorePassword,
            @Value("${app.demo.x509.keystore.alias:server}") String keyAlias,
            @Value("${app.demo.x509.target-url:https://localhost:${server.port}/api/health}") String targetUrl
    ) {
        this.resourceLoader = resourceLoader;
        this.keystorePath = keystorePath;
        this.keystorePassword = keystorePassword;
        this.keyAlias = keyAlias;
        this.targetUrl = targetUrl;
    }

    public X509ValidationResult triggerValidation() throws Exception {
        X509Certificate trustAnchorCertificate = loadTrustAnchorCertificate();
        AtomicReference<String> negotiatedNamedGroupCapture = new AtomicReference<>();
        SSLContext sslContext = buildSslContext(trustAnchorCertificate, negotiatedNamedGroupCapture);

        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .sslContext(sslContext)
                .build();

        HttpRequest request = HttpRequest.newBuilder(URI.create(targetUrl))
                .timeout(Duration.ofSeconds(5))
                .header("Accept", "application/json")
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        SSLSession sslSession = response.sslSession()
                .orElseThrow(() -> new IllegalStateException("No SSL session was attached to the HTTPS response."));
        X509Certificate peerCertificate = (X509Certificate) sslSession.getPeerCertificates()[0];
        validateServerCertificatePath();
        String negotiatedNamedGroup = resolveNegotiatedNamedGroup(
                negotiatedNamedGroupCapture.get(),
                sslSession
        );

        // Fire custom JFR event — jdk.TLSHandshake does not include namedGroup.
        TlsHandshakeAuditEvent jfrEvent = new TlsHandshakeAuditEvent();
        jfrEvent.begin();
        jfrEvent.targetUrl          = targetUrl;
        jfrEvent.tlsVersion         = sslSession.getProtocol();
        jfrEvent.cipherSuite        = sslSession.getCipherSuite();
        jfrEvent.negotiatedNamedGroup  = negotiatedNamedGroup;
        jfrEvent.configuredNamedGroups = extractConfiguredNamedGroups(sslContext);
        jfrEvent.certSigAlgorithm   = peerCertificate.getSigAlgName();
        jfrEvent.peerSubject        = peerCertificate.getSubjectX500Principal().getName();
        jfrEvent.commit();

        log.info("Triggered outbound HTTPS validation against {} | named group: {}",
                targetUrl, negotiatedNamedGroup);

        return new X509ValidationResult(
                targetUrl,
                response.statusCode(),
                sslSession.getProtocol(),
                sslSession.getCipherSuite(),
                negotiatedNamedGroup,
                peerCertificate.getSubjectX500Principal().getName(),
                peerCertificate.getSigAlgName(),
                "This request performs a real HTTPS self-call, an explicit PKIX path validation, " +
                "and a custom TLS JFR event for named-group visibility."
        );
    }

    /**
     * Resolves the negotiated group captured during certificate validation.
     * Falls back to session reflection for older JDK layouts.
     */
    private String resolveNegotiatedNamedGroup(String capturedNamedGroup, SSLSession session) {
        if (!isUnavailable(capturedNamedGroup)) {
            return capturedNamedGroup;
        }
        String sessionDerivedNamedGroup = extractNegotiatedNamedGroupFromSession(session);
        if (!isUnavailable(sessionDerivedNamedGroup)) {
            return sessionDerivedNamedGroup;
        }
        return capturedNamedGroup != null ? capturedNamedGroup : sessionDerivedNamedGroup;
    }

    private boolean isUnavailable(String value) {
        return value == null || value.isBlank() || value.startsWith("unavailable");
    }

    /**
     * Legacy fallback: attempts to read {@code SSLSessionImpl.namedGroup}.
     * Modern JDKs (including Java 27) may not expose this field.
     */
    private String extractNegotiatedNamedGroupFromSession(SSLSession session) {
        try {
            Field field = session.getClass().getDeclaredField("namedGroup");
            field.setAccessible(true);
            Object namedGroup = field.get(session);
            return namedGroup != null ? namedGroup.toString() : "none";
        } catch (InaccessibleObjectException e) {
            return ADD_OPENS_HINT;
        } catch (NoSuchFieldException | IllegalAccessException e) {
            return "unavailable (" + e.getClass().getSimpleName() + ")";
        }
    }

    /**
     * Returns the named groups configured in the SSLContext using the standard
     * {@code SSLParameters.getNamedGroups()} API (Java 21+).
     * Useful to verify that hybrid groups (e.g. {@code X25519MLKEM768}) are enabled
     * even before inspecting the negotiated group.
     */
    private String extractConfiguredNamedGroups(SSLContext sslContext) {
        SSLParameters params = sslContext.getDefaultSSLParameters();
        String[] groups = params.getNamedGroups();
        return (groups != null && groups.length > 0)
                ? String.join(", ", groups)
                : "default (set -Djdk.tls.namedGroups=X25519MLKEM768,x25519,secp256r1 to enable hybrid)";
    }

    private X509Certificate loadTrustAnchorCertificate() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        char[] passwordChars = keystorePassword.toCharArray();
        try {
            try (var inputStream = resourceLoader.getResource(keystorePath).getInputStream()) {
                keyStore.load(inputStream, passwordChars);
            }
            var chain = keyStore.getCertificateChain(keyAlias);
            if (chain != null && chain.length > 1 && chain[chain.length - 1] instanceof X509Certificate trustAnchor) {
                return trustAnchor;
            }
            var certificate = keyStore.getCertificate(keyAlias);
            if (!(certificate instanceof X509Certificate x509Certificate)) {
                throw new IllegalStateException(
                    "Certificate for alias '" + keyAlias + "' is missing or not X.509 in " + keystorePath + "."
                );
            }
            return x509Certificate;
        } finally {
            java.util.Arrays.fill(passwordChars, '\0');
        }
    }

    private void validateServerCertificatePath() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        char[] passwordChars = keystorePassword.toCharArray();
        try {
            try (var inputStream = resourceLoader.getResource(keystorePath).getInputStream()) {
                keyStore.load(inputStream, passwordChars);
            }

            Certificate[] chain = keyStore.getCertificateChain(keyAlias);
            if (chain == null || chain.length < 2) {
                throw new IllegalStateException(
                    "Certificate alias '" + keyAlias + "' in " + keystorePath + " must include a CA-signed chain."
                );
            }

            X509Certificate[] x509Chain = new X509Certificate[chain.length];
            for (int i = 0; i < chain.length; i++) {
                if (!(chain[i] instanceof X509Certificate x509Certificate)) {
                    throw new IllegalStateException(
                        "Certificate chain entry " + i + " for alias '" + keyAlias + "' is not X.509 in " + keystorePath + "."
                    );
                }
                x509Chain[i] = x509Certificate;
            }

            X509Certificate trustAnchor = x509Chain[x509Chain.length - 1];
            List<X509Certificate> certificatePathEntries = Arrays.asList(
                    Arrays.copyOf(x509Chain, x509Chain.length - 1)
            );
            CertPath certPath = CertificateFactory.getInstance("X.509")
                    .generateCertPath(certificatePathEntries);

            PKIXParameters parameters = new PKIXParameters(Set.of(new TrustAnchor(trustAnchor, null)));
            parameters.setRevocationEnabled(false);

            CertPathValidator.getInstance("PKIX").validate(certPath, parameters);
        } finally {
            java.util.Arrays.fill(passwordChars, '\0');
        }
    }

    private SSLContext buildSslContext(
            X509Certificate trustAnchorCertificate,
            AtomicReference<String> negotiatedNamedGroupCapture
    ) throws Exception {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        trustStore.setCertificateEntry("demo-ca", trustAnchorCertificate);

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm()
        );
        trustManagerFactory.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(
                null,
                wrapTrustManagers(trustManagerFactory.getTrustManagers(), negotiatedNamedGroupCapture),
                new SecureRandom()
        );
        return sslContext;
    }

    private TrustManager[] wrapTrustManagers(
            TrustManager[] trustManagers,
            AtomicReference<String> negotiatedNamedGroupCapture
    ) {
        TrustManager[] wrapped = Arrays.copyOf(trustManagers, trustManagers.length);
        for (int i = 0; i < wrapped.length; i++) {
            if (wrapped[i] instanceof X509ExtendedTrustManager trustManager) {
                wrapped[i] = new NegotiatedNamedGroupCaptureTrustManager(
                        trustManager,
                        negotiatedNamedGroupCapture
                );
            }
        }
        return wrapped;
    }

    private static final class NegotiatedNamedGroupCaptureTrustManager extends X509ExtendedTrustManager {
        private final X509ExtendedTrustManager delegate;
        private final AtomicReference<String> negotiatedNamedGroupCapture;

        private NegotiatedNamedGroupCaptureTrustManager(
                X509ExtendedTrustManager delegate,
                AtomicReference<String> negotiatedNamedGroupCapture
        ) {
            this.delegate = delegate;
            this.negotiatedNamedGroupCapture = negotiatedNamedGroupCapture;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
            delegate.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
            delegate.checkServerTrusted(chain, authType);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return delegate.getAcceptedIssuers();
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws java.security.cert.CertificateException {
            delegate.checkClientTrusted(chain, authType, socket);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws java.security.cert.CertificateException {
            captureFromTransport(socket);
            delegate.checkServerTrusted(chain, authType, socket);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws java.security.cert.CertificateException {
            delegate.checkClientTrusted(chain, authType, engine);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws java.security.cert.CertificateException {
            captureFromTransport(engine);
            delegate.checkServerTrusted(chain, authType, engine);
        }

        private void captureFromTransport(Object transport) {
            if (transport == null || hasCapturedNamedGroup()) {
                return;
            }

            try {
                Object transportContext = readField(transport, "conContext");
                Object handshakeContext = readField(transportContext, "handshakeContext");
                if (handshakeContext == null) {
                    return;
                }

                String namedGroup = extractNamedGroupFromHandshakeContext(handshakeContext);
                if (namedGroup != null && !namedGroup.isBlank()) {
                    negotiatedNamedGroupCapture.set(namedGroup);
                } else {
                    setUnavailableIfAbsent("unavailable (key_share extension missing)");
                }
            } catch (InaccessibleObjectException e) {
                setUnavailableIfAbsent(ADD_OPENS_HINT);
            } catch (ReflectiveOperationException e) {
                setUnavailableIfAbsent("unavailable (" + e.getClass().getSimpleName() + ")");
            }
        }

        private boolean hasCapturedNamedGroup() {
            String current = negotiatedNamedGroupCapture.get();
            return current != null && !current.startsWith("unavailable");
        }

        private void setUnavailableIfAbsent(String reason) {
            negotiatedNamedGroupCapture.compareAndSet(null, reason);
        }

        private static String extractNamedGroupFromHandshakeContext(Object handshakeContext)
                throws ReflectiveOperationException {
            Object extensionsObject = readField(handshakeContext, "handshakeExtensions");
            if (!(extensionsObject instanceof Map<?, ?> extensions)) {
                return null;
            }

            for (Object extensionSpec : extensions.values()) {
                if (extensionSpec == null) {
                    continue;
                }
                String simpleName = extensionSpec.getClass().getSimpleName();
                if ("SHKeyShareSpec".equals(simpleName)) {
                    Object serverShare = readField(extensionSpec, "serverShare");
                    int namedGroupId = ((Number) readField(serverShare, "namedGroupId")).intValue();
                    return namedGroupName(namedGroupId);
                }
                if ("HRRKeyShareSpec".equals(simpleName)) {
                    int namedGroupId = ((Number) readField(extensionSpec, "selectedGroup")).intValue();
                    return namedGroupName(namedGroupId);
                }
            }

            return null;
        }

        private static String namedGroupName(int namedGroupId) throws ReflectiveOperationException {
            Class<?> namedGroupClass = Class.forName("sun.security.ssl.NamedGroup");
            Method nameOf = namedGroupClass.getDeclaredMethod("nameOf", int.class);
            nameOf.setAccessible(true);
            Object groupName = nameOf.invoke(null, namedGroupId);
            return groupName != null ? groupName.toString() : "UNDEFINED-NAMED-GROUP(" + namedGroupId + ")";
        }

        private static Object readField(Object target, String fieldName) throws ReflectiveOperationException {
            Field field = findField(target.getClass(), fieldName);
            field.setAccessible(true);
            return field.get(target);
        }

        private static Field findField(Class<?> type, String fieldName) throws NoSuchFieldException {
            Class<?> current = type;
            while (current != null) {
                try {
                    return current.getDeclaredField(fieldName);
                } catch (NoSuchFieldException ignored) {
                    current = current.getSuperclass();
                }
            }
            throw new NoSuchFieldException(fieldName);
        }
    }

    public record X509ValidationResult(
            String targetUrl,
            int statusCode,
            String tlsProtocol,
            String cipherSuite,
            String negotiatedNamedGroup,
            String peerSubject,
            String certificateSignatureAlgorithm,
            String note
    ) {
    }
}
