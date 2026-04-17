package dev.logicojp.example.pqchybridtls.jfr;

import java.nio.ByteBuffer;
import java.security.KeyManagementException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.function.BiFunction;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import org.apache.tomcat.util.net.SSLContext;

final class CapturingTomcatSslContext implements SSLContext {

    private final SSLContext delegate;

    CapturingTomcatSslContext(SSLContext delegate) {
        this.delegate = delegate;
    }

    @Override
    public void init(KeyManager[] kms, TrustManager[] tms, SecureRandom sr) throws KeyManagementException {
        delegate.init(kms, tms, sr);
    }

    @Override
    public void destroy() {
        delegate.destroy();
    }

    @Override
    public SSLSessionContext getServerSessionContext() {
        return delegate.getServerSessionContext();
    }

    @Override
    public SSLEngine createSSLEngine() {
        return new CapturingSslEngine(delegate.createSSLEngine());
    }

    @Override
    public SSLServerSocketFactory getServerSocketFactory() {
        return delegate.getServerSocketFactory();
    }

    @Override
    public SSLParameters getSupportedSSLParameters() {
        return delegate.getSupportedSSLParameters();
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        return delegate.getCertificateChain(alias);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }

    private static final class CapturingSslEngine extends SSLEngine {
        private final SSLEngine delegate;

        private CapturingSslEngine(SSLEngine delegate) {
            super(delegate.getPeerHost(), delegate.getPeerPort());
            this.delegate = delegate;
        }

        @Override
        public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) throws SSLException {
            SSLEngineResult result = delegate.wrap(srcs, offset, length, dst);
            NegotiatedNamedGroupCaptureSupport.captureFromEngine(delegate);
            return result;
        }

        @Override
        public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
                throws SSLException {
            SSLEngineResult result = delegate.unwrap(src, dsts, offset, length);
            NegotiatedNamedGroupCaptureSupport.captureFromEngine(delegate);
            return result;
        }

        @Override
        public Runnable getDelegatedTask() {
            return delegate.getDelegatedTask();
        }

        @Override
        public void closeInbound() throws SSLException {
            delegate.closeInbound();
        }

        @Override
        public boolean isInboundDone() {
            return delegate.isInboundDone();
        }

        @Override
        public void closeOutbound() {
            delegate.closeOutbound();
        }

        @Override
        public boolean isOutboundDone() {
            return delegate.isOutboundDone();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return delegate.getSupportedCipherSuites();
        }

        @Override
        public String[] getEnabledCipherSuites() {
            return delegate.getEnabledCipherSuites();
        }

        @Override
        public void setEnabledCipherSuites(String[] suites) {
            delegate.setEnabledCipherSuites(suites);
        }

        @Override
        public String[] getSupportedProtocols() {
            return delegate.getSupportedProtocols();
        }

        @Override
        public String[] getEnabledProtocols() {
            return delegate.getEnabledProtocols();
        }

        @Override
        public void setEnabledProtocols(String[] protocols) {
            delegate.setEnabledProtocols(protocols);
        }

        @Override
        public SSLSession getSession() {
            NegotiatedNamedGroupCaptureSupport.captureFromEngine(delegate);
            return delegate.getSession();
        }

        @Override
        public SSLSession getHandshakeSession() {
            NegotiatedNamedGroupCaptureSupport.captureFromEngine(delegate);
            return delegate.getHandshakeSession();
        }

        @Override
        public void beginHandshake() throws SSLException {
            delegate.beginHandshake();
            NegotiatedNamedGroupCaptureSupport.captureFromEngine(delegate);
        }

        @Override
        public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
            NegotiatedNamedGroupCaptureSupport.captureFromEngine(delegate);
            return delegate.getHandshakeStatus();
        }

        @Override
        public void setUseClientMode(boolean mode) {
            delegate.setUseClientMode(mode);
        }

        @Override
        public boolean getUseClientMode() {
            return delegate.getUseClientMode();
        }

        @Override
        public void setNeedClientAuth(boolean need) {
            delegate.setNeedClientAuth(need);
        }

        @Override
        public boolean getNeedClientAuth() {
            return delegate.getNeedClientAuth();
        }

        @Override
        public void setWantClientAuth(boolean want) {
            delegate.setWantClientAuth(want);
        }

        @Override
        public boolean getWantClientAuth() {
            return delegate.getWantClientAuth();
        }

        @Override
        public void setEnableSessionCreation(boolean flag) {
            delegate.setEnableSessionCreation(flag);
        }

        @Override
        public boolean getEnableSessionCreation() {
            return delegate.getEnableSessionCreation();
        }

        @Override
        public SSLParameters getSSLParameters() {
            return delegate.getSSLParameters();
        }

        @Override
        public void setSSLParameters(SSLParameters params) {
            delegate.setSSLParameters(params);
        }

        @Override
        public String getApplicationProtocol() {
            return delegate.getApplicationProtocol();
        }

        @Override
        public String getHandshakeApplicationProtocol() {
            return delegate.getHandshakeApplicationProtocol();
        }

        @Override
        public void setHandshakeApplicationProtocolSelector(
                BiFunction<SSLEngine, List<String>, String> selector
        ) {
            delegate.setHandshakeApplicationProtocolSelector(selector);
        }

        @Override
        public BiFunction<SSLEngine, List<String>, String> getHandshakeApplicationProtocolSelector() {
            return delegate.getHandshakeApplicationProtocolSelector();
        }
    }
}
