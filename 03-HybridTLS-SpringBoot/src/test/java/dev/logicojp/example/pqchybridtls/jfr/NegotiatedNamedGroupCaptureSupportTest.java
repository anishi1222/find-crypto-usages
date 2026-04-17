package dev.logicojp.example.pqchybridtls.jfr;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class NegotiatedNamedGroupCaptureSupportTest {

    @Test
    void captureFromEngineStoresSelectedNamedGroupOnSession() {
        SSLSession session = mockSession();
        FakeHandshakeContext handshakeContext = new FakeHandshakeContext(new FakeNamedGroup("X25519MLKEM768"));
        SSLEngine engine = new FakeSslEngine(session, new FakeConnectionContext(session, handshakeContext));

        NegotiatedNamedGroupCaptureSupport.captureFromEngine(engine);

        assertEquals(
                "X25519MLKEM768",
                NegotiatedNamedGroupCaptureSupport.getCapturedNegotiatedNamedGroup(session)
        );
    }

    @Test
    void captureFromEngineReadsSelectedGroupFromServerHelloKeyShareExtension() {
        SSLSession session = mockSession();
        Map<Object, Object> handshakeExtensions = new HashMap<>();
        handshakeExtensions.put("server-hello", new SHKeyShareSpec(new KeyShareEntry(0x11EC)));
        FakeHandshakeContext handshakeContext = new FakeHandshakeContext(null, handshakeExtensions);
        SSLEngine engine = new FakeSslEngine(session, new FakeConnectionContext(session, handshakeContext));

        NegotiatedNamedGroupCaptureSupport.captureFromEngine(engine);

        assertEquals(
                "X25519MLKEM768",
                NegotiatedNamedGroupCaptureSupport.getCapturedNegotiatedNamedGroup(session)
        );
    }

    @Test
    void serverFilterPrefersCapturedSessionValueBeforeLegacySessionReflection() throws Exception {
        SSLSession session = mockSession();
        session.putValue(NegotiatedNamedGroupCaptureSupport.SESSION_VALUE_KEY, "X25519MLKEM768");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute("jakarta.servlet.request.ssl_session_mgr", new FakeSessionManager(session));

        Method method = ServerTlsHandshakeAuditFilter.class.getDeclaredMethod(
                "resolveNegotiatedNamedGroupFromSessionManager",
                jakarta.servlet.http.HttpServletRequest.class
        );
        method.setAccessible(true);

        String negotiatedNamedGroup = (String) method.invoke(null, request);

        assertEquals("X25519MLKEM768", negotiatedNamedGroup);
    }

    @Test
    void serverFilterFallsBackToSslSessionProtocolWhenRequestAttributeIsMissing() throws Exception {
        SSLSession session = mockSession();
        when(session.getProtocol()).thenReturn("TLSv1.3");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute("jakarta.servlet.request.ssl_session_mgr", new FakeSessionManager(session));

        Method method = ServerTlsHandshakeAuditFilter.class.getDeclaredMethod(
                "resolveTlsVersion",
                jakarta.servlet.http.HttpServletRequest.class
        );
        method.setAccessible(true);

        String tlsVersion = (String) method.invoke(null, request);

        assertEquals("TLSv1.3", tlsVersion);
    }

    @Test
    void serverFilterReportsEffectiveDefaultNamedGroupsWhenNoOverrideIsSet() throws Exception {
        String originalOverride = System.getProperty("jdk.tls.namedGroups");
        try {
            System.clearProperty("jdk.tls.namedGroups");

            Method method = ServerTlsHandshakeAuditFilter.class.getDeclaredMethod("resolveConfiguredNamedGroups");
            method.setAccessible(true);

            String configuredNamedGroups = (String) method.invoke(null);
            String[] defaultNamedGroups = SSLContext.getDefault().getDefaultSSLParameters().getNamedGroups();

            assertEquals(String.join(", ", defaultNamedGroups), configuredNamedGroups);
        } finally {
            if (originalOverride == null) {
                System.clearProperty("jdk.tls.namedGroups");
            } else {
                System.setProperty("jdk.tls.namedGroups", originalOverride);
            }
        }
    }

    private static SSLSession mockSession() {
        SSLSession session = mock(SSLSession.class);
        Map<String, Object> values = new HashMap<>();

        when(session.getValue(anyString())).thenAnswer(invocation -> values.get(invocation.getArgument(0)));
        doAnswer(invocation -> {
            values.put(invocation.getArgument(0), invocation.getArgument(1));
            return null;
        }).when(session).putValue(anyString(), any());

        return session;
    }

    private static final class FakeConnectionContext {
        private final SSLSession conSession;
        private final Object handshakeContext;

        private FakeConnectionContext(SSLSession conSession, Object handshakeContext) {
            this.conSession = conSession;
            this.handshakeContext = handshakeContext;
        }
    }

    private static final class FakeHandshakeContext {
        private final Object serverSelectedNamedGroup;
        private final Map<Object, Object> handshakeExtensions;

        private FakeHandshakeContext(Object serverSelectedNamedGroup) {
            this(serverSelectedNamedGroup, new HashMap<>());
        }

        private FakeHandshakeContext(Object serverSelectedNamedGroup, Map<Object, Object> handshakeExtensions) {
            this.serverSelectedNamedGroup = serverSelectedNamedGroup;
            this.handshakeExtensions = handshakeExtensions;
        }
    }

    private static final class FakeNamedGroup {
        private final String name;

        private FakeNamedGroup(String name) {
            this.name = name;
        }

        @Override
        public String toString() {
            return name;
        }
    }

    private static final class FakeSessionManager {
        private final SSLSession session;

        private FakeSessionManager(SSLSession session) {
            this.session = session;
        }
    }

    private static final class SHKeyShareSpec {
        private final KeyShareEntry serverShare;

        private SHKeyShareSpec(KeyShareEntry serverShare) {
            this.serverShare = serverShare;
        }
    }

    private static final class KeyShareEntry {
        private final int namedGroupId;

        private KeyShareEntry(int namedGroupId) {
            this.namedGroupId = namedGroupId;
        }
    }

    private static final class FakeSslEngine extends SSLEngine {
        private final SSLSession session;
        private final Object conContext;

        private FakeSslEngine(SSLSession session, Object conContext) {
            this.session = session;
            this.conContext = conContext;
        }

        @Override
        public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) throws SSLException {
            throw new UnsupportedOperationException();
        }

        @Override
        public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
                throws SSLException {
            throw new UnsupportedOperationException();
        }

        @Override
        public Runnable getDelegatedTask() {
            return null;
        }

        @Override
        public void closeInbound() {
        }

        @Override
        public boolean isInboundDone() {
            return false;
        }

        @Override
        public void closeOutbound() {
        }

        @Override
        public boolean isOutboundDone() {
            return false;
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return new String[0];
        }

        @Override
        public String[] getEnabledCipherSuites() {
            return new String[0];
        }

        @Override
        public void setEnabledCipherSuites(String[] suites) {
        }

        @Override
        public String[] getSupportedProtocols() {
            return new String[0];
        }

        @Override
        public String[] getEnabledProtocols() {
            return new String[0];
        }

        @Override
        public void setEnabledProtocols(String[] protocols) {
        }

        @Override
        public SSLSession getSession() {
            return session;
        }

        @Override
        public void beginHandshake() {
        }

        @Override
        public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
            return SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
        }

        @Override
        public void setUseClientMode(boolean mode) {
        }

        @Override
        public boolean getUseClientMode() {
            return false;
        }

        @Override
        public void setNeedClientAuth(boolean need) {
        }

        @Override
        public boolean getNeedClientAuth() {
            return false;
        }

        @Override
        public void setWantClientAuth(boolean want) {
        }

        @Override
        public boolean getWantClientAuth() {
            return false;
        }

        @Override
        public void setEnableSessionCreation(boolean flag) {
        }

        @Override
        public boolean getEnableSessionCreation() {
            return false;
        }
    }
}
