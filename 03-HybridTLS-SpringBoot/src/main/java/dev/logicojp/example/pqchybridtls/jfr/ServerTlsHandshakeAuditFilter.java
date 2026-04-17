package dev.logicojp.example.pqchybridtls.jfr;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InaccessibleObjectException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class ServerTlsHandshakeAuditFilter extends OncePerRequestFilter {

    private static final String DEFAULT_NEGOTIATED_GROUP_NOTE =
            "unavailable (ssl_session_mgr attribute was not available on the request)";
    private static final String DEFAULT_CONFIGURED_GROUPS_NOTE =
            "unavailable (JSSE did not expose any effective named groups)";
    private static final String DEFAULT_TLS_VERSION_NOTE =
            "unavailable (container did not expose TLS protocol attribute)";
    private static final String SSL_SESSION_MANAGER_ATTRIBUTE = "jakarta.servlet.request.ssl_session_mgr";
    private static final String NEGOTIATED_GROUP_HEADER = "X-PQC-Negotiated-Named-Group";

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        try {
            filterChain.doFilter(request, response);
        } finally {
            if (!request.isSecure()) {
                return;
            }
            emitServerHandshakeAuditEvent(request);
        }
    }

    private void emitServerHandshakeAuditEvent(HttpServletRequest request) {
        X509Certificate[] certificates =
                (X509Certificate[]) request.getAttribute("jakarta.servlet.request.X509Certificate");
        X509Certificate peerCertificate = certificates != null && certificates.length > 0 ? certificates[0] : null;

        TlsHandshakeAuditEvent event = new TlsHandshakeAuditEvent();
        event.begin();
        event.targetUrl = requestUrl(request);
        event.tlsVersion = resolveTlsVersion(request);
        event.cipherSuite = attributeAsString(
                request,
                "jakarta.servlet.request.cipher_suite",
                "unavailable"
        );
        event.negotiatedNamedGroup = resolveNegotiatedNamedGroup(request);
        event.configuredNamedGroups = resolveConfiguredNamedGroups();
        event.certSigAlgorithm = peerCertificate != null ? peerCertificate.getSigAlgName() : "unavailable";
        event.peerSubject = peerCertificate != null
                ? peerCertificate.getSubjectX500Principal().getName()
                : "unavailable";
        event.commit();
    }

    private static String requestUrl(HttpServletRequest request) {
        String query = request.getQueryString();
        return query == null
                ? request.getRequestURL().toString()
                : request.getRequestURL() + "?" + query;
    }

    private static String resolveTlsVersion(HttpServletRequest request) {
        String jakartaSecureProtocol = attributeAsString(request, "jakarta.servlet.request.secure_protocol", null);
        if (jakartaSecureProtocol != null) {
            return jakartaSecureProtocol;
        }
        String javaxSecureProtocol = attributeAsString(request, "javax.servlet.request.secure_protocol", null);
        if (javaxSecureProtocol != null) {
            return javaxSecureProtocol;
        }
        String jakartaProtocol = attributeAsString(request, "jakarta.servlet.request.ssl_protocol", null);
        if (jakartaProtocol != null) {
            return jakartaProtocol;
        }
        String javaxProtocol = attributeAsString(request, "javax.servlet.request.ssl_protocol", null);
        if (javaxProtocol != null) {
            return javaxProtocol;
        }
        try {
            SSLSession session = resolveSslSession(request);
            if (session != null) {
                String sessionProtocol = session.getProtocol();
                if (sessionProtocol != null && !sessionProtocol.isBlank()) {
                    return sessionProtocol;
                }
            }
        } catch (ReflectiveOperationException exception) {
            return "unavailable (" + exception.getClass().getSimpleName() + ")";
        }
        return DEFAULT_TLS_VERSION_NOTE;
    }

    private static String resolveConfiguredNamedGroups() {
        String override = System.getProperty("jdk.tls.namedGroups");
        if (override != null && !override.isBlank()) {
            return override;
        }

        try {
            String[] namedGroups = SSLContext.getDefault().getDefaultSSLParameters().getNamedGroups();
            return namedGroups != null && namedGroups.length > 0
                    ? String.join(", ", namedGroups)
                    : DEFAULT_CONFIGURED_GROUPS_NOTE;
        } catch (NoSuchAlgorithmException exception) {
            return "unavailable (" + exception.getClass().getSimpleName() + ")";
        }
    }

    private static String resolveNegotiatedNamedGroup(HttpServletRequest request) {
        String sessionManagerDerived = resolveNegotiatedNamedGroupFromSessionManager(request);
        if (!isUnavailable(sessionManagerDerived)) {
            return sessionManagerDerived;
        }
        String clientReported = request.getHeader(NEGOTIATED_GROUP_HEADER);
        if (clientReported != null && !clientReported.isBlank()) {
            return clientReported;
        }
        return sessionManagerDerived;
    }

    private static String resolveNegotiatedNamedGroupFromSessionManager(HttpServletRequest request) {
        if (request.getAttribute(SSL_SESSION_MANAGER_ATTRIBUTE) == null) {
            return DEFAULT_NEGOTIATED_GROUP_NOTE;
        }

        try {
            SSLSession session = resolveSslSession(request);
            if (session == null) {
                return "unavailable (ssl_session_mgr did not expose SSLSession)";
            }
            String capturedNamedGroup = NegotiatedNamedGroupCaptureSupport.getCapturedNegotiatedNamedGroup(session);
            if (!NegotiatedNamedGroupCaptureSupport.isUnavailable(capturedNamedGroup)) {
                return capturedNamedGroup;
            }
            return extractNegotiatedNamedGroupFromSession(session);
        } catch (InaccessibleObjectException exception) {
            return NegotiatedNamedGroupCaptureSupport.ADD_OPENS_HINT;
        } catch (ReflectiveOperationException exception) {
            return "unavailable (" + exception.getClass().getSimpleName() + ")";
        }
    }

    private static SSLSession resolveSslSession(HttpServletRequest request) throws ReflectiveOperationException {
        Object sessionManager = request.getAttribute(SSL_SESSION_MANAGER_ATTRIBUTE);
        if (sessionManager == null) {
            return null;
        }
        Object sessionObject = readField(sessionManager, "session");
        if (sessionObject instanceof SSLSession session) {
            return session;
        }
        return null;
    }

    private static boolean isUnavailable(String value) {
        return value == null || value.isBlank() || value.startsWith("unavailable");
    }

    private static String extractNegotiatedNamedGroupFromSession(SSLSession session) {
        try {
            Field field = session.getClass().getDeclaredField("namedGroup");
            field.setAccessible(true);
            Object namedGroup = field.get(session);
            return namedGroup != null ? namedGroup.toString() : "none";
        } catch (InaccessibleObjectException exception) {
            return NegotiatedNamedGroupCaptureSupport.ADD_OPENS_HINT;
        } catch (NoSuchFieldException | IllegalAccessException exception) {
            return "unavailable (" + exception.getClass().getSimpleName() + ")";
        }
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

    private static String attributeAsString(HttpServletRequest request, String attributeName, String fallback) {
        Object value = request.getAttribute(attributeName);
        if (value == null) {
            return fallback;
        }
        String text = value.toString();
        return text.isBlank() ? fallback : text;
    }
}
