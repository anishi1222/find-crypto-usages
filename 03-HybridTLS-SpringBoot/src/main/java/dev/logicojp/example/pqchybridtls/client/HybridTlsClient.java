package dev.logicojp.example.pqchybridtls.client;

import dev.logicojp.example.pqchybridtls.jfr.TlsHandshakeAuditEvent;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.lang.reflect.Field;
import java.lang.reflect.InaccessibleObjectException;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;

public final class HybridTlsClient {

    private static final String DEFAULT_URL = "https://localhost:8443/api/hello?name=HybridTLS";
    private static final String DEFAULT_NAMED_GROUP = "X25519MLKEM768";
    private static final String DEFAULT_STORE_TYPE = "PKCS12";
    private static final String NEGOTIATED_NAMED_GROUP_HEADER = "X-PQC-Negotiated-Named-Group";
    private static final String ADD_OPENS_HINT =
            "unavailable (add --add-opens java.base/sun.security.ssl=ALL-UNNAMED)";

    private HybridTlsClient() {
    }

    public static void main(String[] args) throws Exception {
        ClientOptions options = ClientOptions.parse(args);

        if (options.help()) {
            System.out.println(ClientOptions.usage());
            return;
        }

        try {
            ResponseDetails response = connect(options);
            printReport(options, response);
        } catch (Exception exception) {
            if (options.outputFormat() == OutputFormat.JSON) {
                System.out.println(buildErrorJson(options, exception));
                System.exit(1);
            }
            throw exception;
        }
    }

    static ResponseDetails connect(ClientOptions options) throws IOException, GeneralSecurityException {
        URI uri = options.uri();
        SslRuntime sslRuntime = createSslContext(options);
        SSLSocketFactory socketFactory = sslRuntime.sslContext().getSocketFactory();
        int port = uri.getPort() == -1 ? 443 : uri.getPort();

        try (SSLSocket socket = (SSLSocket) socketFactory.createSocket()) {
            socket.connect(new InetSocketAddress(uri.getHost(), port), options.connectTimeoutMillis());
            socket.setSoTimeout(options.readTimeoutMillis());

            SSLParameters sslParameters = socket.getSSLParameters();
            sslParameters.setProtocols(new String[]{"TLSv1.3"});
            sslParameters.setNamedGroups(new String[]{options.namedGroup()});
            sslParameters.setEndpointIdentificationAlgorithm("HTTPS");
            socket.setSSLParameters(sslParameters);

            socket.startHandshake();

            SSLSession sslSession = socket.getSession();
            String tlsProtocol = sslSession.getProtocol();
            String cipherSuite = sslSession.getCipherSuite();
            String negotiatedNamedGroup = resolveNegotiatedNamedGroup(
                    sslRuntime.negotiatedNamedGroupCapture().get(),
                    sslSession
            );
            X509Certificate peerCertificate = resolvePeerCertificate(sslSession);
            emitTlsHandshakeAuditEvent(
                    uri,
                    sslRuntime.sslContext(),
                    tlsProtocol,
                    cipherSuite,
                    negotiatedNamedGroup,
                    peerCertificate
            );
            String peerPrincipal = peerPrincipal(socket);
            String statusLine;
            String responseBody;

            try (BufferedWriter writer = new BufferedWriter(
                    new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));
                 BufferedReader reader = new BufferedReader(
                         new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8))) {

                writer.write("GET " + requestPath(uri) + " HTTP/1.1\r\n");
                writer.write("Host: " + hostHeader(uri) + "\r\n");
                writer.write("Accept: application/json\r\n");
                writer.write(NEGOTIATED_NAMED_GROUP_HEADER + ": " + negotiatedNamedGroup + "\r\n");
                writer.write("Connection: close\r\n");
                writer.write("\r\n");
                writer.flush();

                statusLine = reader.readLine();
                Map<String, String> headers = readHeaders(reader);
                responseBody = readBody(reader, headers);
            }

            return new ResponseDetails(tlsProtocol, cipherSuite, peerPrincipal, statusLine, responseBody);
        }
    }

    private static SslRuntime createSslContext(ClientOptions options) throws IOException, GeneralSecurityException {
        AtomicReference<String> negotiatedNamedGroupCapture = new AtomicReference<>();
        KeyManager[] keyManagers = null;
        if (options.clientKeyStorePath() != null) {
            keyManagers = loadKeyManagers(
                    options.clientKeyStorePath(),
                    options.clientKeyStorePassword(),
                    options.clientKeyPassword(),
                    options.clientKeyStoreType()
            );
        }

        TrustManager[] trustManagers = resolveTrustManagers(options, negotiatedNamedGroupCapture);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagers, trustManagers, new SecureRandom());
        return new SslRuntime(sslContext, negotiatedNamedGroupCapture);
    }

    private static KeyManager[] loadKeyManagers(
            Path keyStorePath,
            String keyStorePassword,
            String keyPassword,
            String keyStoreType
    ) throws IOException, GeneralSecurityException {
        KeyStore keyStore = loadKeyStore(keyStorePath, keyStorePassword, keyStoreType);
        KeyManagerFactory keyManagerFactory =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, keyPassword.toCharArray());
        return keyManagerFactory.getKeyManagers();
    }

    private static TrustManager[] loadTrustManagers(
            Path trustStorePath,
            String trustStorePassword,
            String trustStoreType
    ) throws IOException, GeneralSecurityException {
        KeyStore trustStore = loadKeyStore(trustStorePath, trustStorePassword, trustStoreType);
        TrustManagerFactory trustManagerFactory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        return trustManagerFactory.getTrustManagers();
    }

    private static TrustManager[] loadDefaultTrustManagers() throws GeneralSecurityException {
        TrustManagerFactory trustManagerFactory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init((KeyStore) null);
        return trustManagerFactory.getTrustManagers();
    }

    private static TrustManager[] resolveTrustManagers(
            ClientOptions options,
            AtomicReference<String> negotiatedNamedGroupCapture
    ) throws IOException, GeneralSecurityException {
        TrustManager[] trustManagers;
        if (options.trustAll()) {
            trustManagers = insecureTrustManagers();
        } else if (options.trustStorePath() != null) {
            trustManagers = loadTrustManagers(
                    options.trustStorePath(),
                    options.trustStorePassword(),
                    options.trustStoreType()
            );
        } else {
            trustManagers = loadDefaultTrustManagers();
        }
        return wrapTrustManagers(trustManagers, negotiatedNamedGroupCapture);
    }

    private static KeyStore loadKeyStore(Path keyStorePath, String password, String keyStoreType)
            throws IOException, GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        try (InputStream inputStream = Files.newInputStream(keyStorePath)) {
            keyStore.load(inputStream, password.toCharArray());
        }
        return keyStore;
    }

    private static String requestPath(URI uri) {
        String path = (uri.getRawPath() == null || uri.getRawPath().isBlank()) ? "/" : uri.getRawPath();
        return uri.getRawQuery() == null ? path : path + "?" + uri.getRawQuery();
    }

    private static String hostHeader(URI uri) {
        int port = uri.getPort();
        if (port == -1 || port == 443) {
            return uri.getHost();
        }
        return uri.getHost() + ":" + port;
    }

    private static Map<String, String> readHeaders(BufferedReader reader) throws IOException {
        Map<String, String> headers = new LinkedHashMap<>();
        String line;
        while ((line = reader.readLine()) != null) {
            if (line.isEmpty()) {
                return headers;
            }
            int separatorIndex = line.indexOf(':');
            if (separatorIndex > 0) {
                String name = line.substring(0, separatorIndex).trim().toLowerCase(Locale.ROOT);
                String value = line.substring(separatorIndex + 1).trim();
                headers.put(name, value);
            }
        }
        return headers;
    }

    private static String readBody(BufferedReader reader, Map<String, String> headers) throws IOException {
        String transferEncoding = headers.get("transfer-encoding");
        if (transferEncoding != null && transferEncoding.toLowerCase(Locale.ROOT).contains("chunked")) {
            return readChunkedBody(reader);
        }

        String contentLength = headers.get("content-length");
        if (contentLength != null) {
            return readFixedLengthBody(reader, Integer.parseInt(contentLength));
        }

        return readUntilEnd(reader);
    }

    private static String readChunkedBody(BufferedReader reader) throws IOException {
        StringBuilder body = new StringBuilder();
        while (true) {
            String sizeLine = reader.readLine();
            if (sizeLine == null) {
                return body.toString();
            }

            int chunkSize = Integer.parseInt(sizeLine.split(";", 2)[0].trim(), 16);
            if (chunkSize == 0) {
                while (true) {
                    String trailerLine = reader.readLine();
                    if (trailerLine == null || trailerLine.isEmpty()) {
                        return body.toString();
                    }
                }
            }

            body.append(readExactChars(reader, chunkSize));
            reader.readLine();
        }
    }

    private static String readFixedLengthBody(BufferedReader reader, int contentLength) throws IOException {
        return readExactChars(reader, contentLength);
    }

    private static String readUntilEnd(BufferedReader reader) throws IOException {
        StringBuilder body = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            if (!body.isEmpty()) {
                body.append(System.lineSeparator());
            }
            body.append(line);
        }
        return body.toString();
    }

    private static String readExactChars(BufferedReader reader, int length) throws IOException {
        StringBuilder value = new StringBuilder(length);
        while (value.length() < length) {
            int next = reader.read();
            if (next == -1) {
                throw new IOException("Unexpected end of stream while reading response body.");
            }
            value.append((char) next);
        }
        return value.toString();
    }

    private static String peerPrincipal(SSLSocket socket) {
        try {
            return socket.getSession().getPeerPrincipal().getName();
        } catch (SSLPeerUnverifiedException exception) {
            return "Unavailable";
        }
    }

    private static TrustManager[] insecureTrustManagers() {
        return new TrustManager[]{
                new X509ExtendedTrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {
                    }

                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
        };
    }

    private static void printReport(ClientOptions options, ResponseDetails response) {
        if (options.outputFormat() == OutputFormat.JSON) {
            System.out.println(buildSuccessJson(options, response));
            return;
        }

        System.out.println("Hybrid TLS probe succeeded.");
        System.out.println("URL: " + options.uri());
        System.out.println("TLS protocol: " + response.tlsProtocol());
        System.out.println("Cipher suite: " + response.cipherSuite());
        System.out.println("Peer principal: " + response.peerPrincipal());
        System.out.println("Requested named group: " + options.namedGroup());
        System.out.println("Client certificate configured: " + options.mtlsEnabled());
        System.out.println("Trust mode: " + options.trustMode());
        System.out.println("HTTP status: " + response.statusLine());
        System.out.println("Response body: " + response.responseBody());
        System.out.println();
        System.out.println("Verification note:");
        System.out.println(verificationReason(options));
        System.out.println("Add -Djavax.net.debug=ssl:handshake when launching the client or server");
        System.out.println("if you also want the named group to appear explicitly in the JSSE debug trace.");
        if (options.trustAll()) {
            System.out.println();
            System.out.println("Warning: --trust-all is for local demos only.");
        }
    }

    static String buildSuccessJson(ClientOptions options, ResponseDetails response) {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        appendJsonField(json, "timestamp", Instant.now().toString(), true);
        appendJsonField(json, "url", options.uri().toString(), true);
        appendJsonField(json, "tlsProtocol", response.tlsProtocol(), true);
        appendJsonField(json, "cipherSuite", response.cipherSuite(), true);
        appendJsonField(json, "peerPrincipal", response.peerPrincipal(), true);
        appendJsonField(json, "requestedNamedGroup", options.namedGroup(), true);
        appendJsonBoolean(json, "clientCertificateConfigured", options.mtlsEnabled(), true);
        appendJsonField(json, "trustMode", options.trustMode(), true);
        appendJsonField(json, "httpStatus", response.statusLine(), true);
        appendJsonField(json, "responseBody", response.responseBody(), true);
        appendJsonBoolean(json, "verificationSucceeded", true, true);
        appendJsonField(json, "verificationReason", verificationReason(options), false);
        json.append("}");
        return json.toString();
    }

    private static String buildErrorJson(ClientOptions options, Exception exception) {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        appendJsonField(json, "timestamp", Instant.now().toString(), true);
        appendJsonField(json, "url", options.uri().toString(), true);
        appendJsonField(json, "requestedNamedGroup", options.namedGroup(), true);
        appendJsonBoolean(json, "clientCertificateConfigured", options.mtlsEnabled(), true);
        appendJsonField(json, "trustMode", options.trustMode(), true);
        appendJsonBoolean(json, "verificationSucceeded", false, true);
        appendJsonField(json, "error", exception.getMessage(), false);
        json.append("}");
        return json.toString();
    }

    private static String verificationReason(ClientOptions options) {
        String baseReason = "The client offers only " + options.namedGroup()
                + " via SSLParameters#setNamedGroups, so a successful TLS 1.3 handshake confirms that JSSE negotiated that named group.";
        if (options.mtlsEnabled()) {
            return baseReason + " A client certificate was also configured, so this probe verifies mutual TLS at the same time.";
        }
        return baseReason;
    }

    private static String resolveNegotiatedNamedGroup(String capturedNamedGroup, SSLSession session) {
        if (!isUnavailable(capturedNamedGroup)) {
            return capturedNamedGroup;
        }
        String sessionDerivedNamedGroup = extractNegotiatedNamedGroupFromSession(session);
        if (!isUnavailable(sessionDerivedNamedGroup)) {
            return sessionDerivedNamedGroup;
        }
        return capturedNamedGroup != null ? capturedNamedGroup : sessionDerivedNamedGroup;
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
            return ADD_OPENS_HINT;
        } catch (NoSuchFieldException | IllegalAccessException exception) {
            return "unavailable (" + exception.getClass().getSimpleName() + ")";
        }
    }

    private static X509Certificate resolvePeerCertificate(SSLSession session) {
        try {
            var peerCertificates = session.getPeerCertificates();
            if (peerCertificates.length > 0 && peerCertificates[0] instanceof X509Certificate certificate) {
                return certificate;
            }
            return null;
        } catch (SSLPeerUnverifiedException exception) {
            return null;
        }
    }

    private static void emitTlsHandshakeAuditEvent(
            URI targetUri,
            SSLContext sslContext,
            String tlsProtocol,
            String cipherSuite,
            String negotiatedNamedGroup,
            X509Certificate peerCertificate
    ) {
        TlsHandshakeAuditEvent event = new TlsHandshakeAuditEvent();
        event.begin();
        event.targetUrl = targetUri.toString();
        event.tlsVersion = tlsProtocol;
        event.cipherSuite = cipherSuite;
        event.negotiatedNamedGroup = negotiatedNamedGroup;
        event.configuredNamedGroups = extractConfiguredNamedGroups(sslContext);
        event.certSigAlgorithm = peerCertificate != null ? peerCertificate.getSigAlgName() : "unavailable";
        event.peerSubject = peerCertificate != null
                ? peerCertificate.getSubjectX500Principal().getName()
                : "unavailable";
        event.commit();
    }

    private static String extractConfiguredNamedGroups(SSLContext sslContext) {
        String[] namedGroups = sslContext.getDefaultSSLParameters().getNamedGroups();
        return (namedGroups != null && namedGroups.length > 0)
                ? String.join(", ", namedGroups)
                : "default";
    }

    private static TrustManager[] wrapTrustManagers(
            TrustManager[] trustManagers,
            AtomicReference<String> negotiatedNamedGroupCapture
    ) {
        TrustManager[] wrappedTrustManagers = Arrays.copyOf(trustManagers, trustManagers.length);
        for (int index = 0; index < wrappedTrustManagers.length; index++) {
            if (wrappedTrustManagers[index] instanceof X509ExtendedTrustManager trustManager) {
                wrappedTrustManagers[index] = new NegotiatedNamedGroupCaptureTrustManager(
                        trustManager,
                        negotiatedNamedGroupCapture
                );
            }
        }
        return wrappedTrustManagers;
    }

    private static void appendJsonField(StringBuilder json, String name, String value, boolean withComma) {
        json.append("  \"")
                .append(escapeJson(name))
                .append("\": ")
                .append(value == null ? "null" : "\"" + escapeJson(value) + "\"");
        if (withComma) {
            json.append(",");
        }
        json.append("\n");
    }

    private static void appendJsonBoolean(StringBuilder json, String name, boolean value, boolean withComma) {
        json.append("  \"")
                .append(escapeJson(name))
                .append("\": ")
                .append(value);
        if (withComma) {
            json.append(",");
        }
        json.append("\n");
    }

    static String escapeJson(String value) {
        StringBuilder escaped = new StringBuilder();
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '\\' -> escaped.append("\\\\");
                case '"' -> escaped.append("\\\"");
                case '\n' -> escaped.append("\\n");
                case '\r' -> escaped.append("\\r");
                case '\t' -> escaped.append("\\t");
                default -> escaped.append(character);
            }
        }
        return escaped.toString();
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
            } catch (InaccessibleObjectException exception) {
                setUnavailableIfAbsent(ADD_OPENS_HINT);
            } catch (ReflectiveOperationException exception) {
                setUnavailableIfAbsent("unavailable (" + exception.getClass().getSimpleName() + ")");
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

    private record SslRuntime(
            SSLContext sslContext,
            AtomicReference<String> negotiatedNamedGroupCapture
    ) {
    }

    record ResponseDetails(
            String tlsProtocol,
            String cipherSuite,
            String peerPrincipal,
            String statusLine,
            String responseBody
    ) {
    }

    enum OutputFormat {
        TEXT,
        JSON;

        static OutputFormat parse(String value) {
            return switch (value.toLowerCase(Locale.ROOT)) {
                case "text" -> TEXT;
                case "json" -> JSON;
                default -> throw new IllegalArgumentException("Unsupported output format: " + value);
            };
        }
    }

    static final class ClientOptions {

        private final URI uri;
        private final String namedGroup;
        private final boolean trustAll;
        private final boolean help;
        private final int connectTimeoutMillis;
        private final int readTimeoutMillis;
        private final Path trustStorePath;
        private final String trustStorePassword;
        private final String trustStoreType;
        private final Path clientKeyStorePath;
        private final String clientKeyStorePassword;
        private final String clientKeyPassword;
        private final String clientKeyStoreType;
        private final OutputFormat outputFormat;

        private ClientOptions(
                URI uri,
                String namedGroup,
                boolean trustAll,
                boolean help,
                int connectTimeoutMillis,
                int readTimeoutMillis,
                Path trustStorePath,
                String trustStorePassword,
                String trustStoreType,
                Path clientKeyStorePath,
                String clientKeyStorePassword,
                String clientKeyPassword,
                String clientKeyStoreType,
                OutputFormat outputFormat
        ) {
            this.uri = uri;
            this.namedGroup = namedGroup;
            this.trustAll = trustAll;
            this.help = help;
            this.connectTimeoutMillis = connectTimeoutMillis;
            this.readTimeoutMillis = readTimeoutMillis;
            this.trustStorePath = trustStorePath;
            this.trustStorePassword = trustStorePassword;
            this.trustStoreType = trustStoreType;
            this.clientKeyStorePath = clientKeyStorePath;
            this.clientKeyStorePassword = clientKeyStorePassword;
            this.clientKeyPassword = clientKeyPassword;
            this.clientKeyStoreType = clientKeyStoreType;
            this.outputFormat = outputFormat;
        }

        static ClientOptions parse(String[] args) {
            URI url = URI.create(DEFAULT_URL);
            String namedGroup = DEFAULT_NAMED_GROUP;
            boolean trustAll = false;
            boolean help = false;
            int connectTimeoutMillis = 5_000;
            int readTimeoutMillis = 5_000;
            Path trustStorePath = null;
            String trustStorePassword = null;
            String trustStoreType = DEFAULT_STORE_TYPE;
            Path clientKeyStorePath = null;
            String clientKeyStorePassword = null;
            String clientKeyPassword = null;
            String clientKeyStoreType = DEFAULT_STORE_TYPE;
            OutputFormat outputFormat = OutputFormat.TEXT;

            for (int index = 0; index < args.length; index++) {
                String argument = args[index];
                switch (argument) {
                    case "--url" -> url = URI.create(requireValue(args, ++index, "--url"));
                    case "--named-group" -> namedGroup = requireValue(args, ++index, "--named-group");
                    case "--trust-all" -> trustAll = true;
                    case "--truststore" -> trustStorePath = Path.of(requireValue(args, ++index, "--truststore"));
                    case "--truststore-password" ->
                            trustStorePassword = requireValue(args, ++index, "--truststore-password");
                    case "--truststore-type" -> trustStoreType = requireValue(args, ++index, "--truststore-type");
                    case "--client-keystore" ->
                            clientKeyStorePath = Path.of(requireValue(args, ++index, "--client-keystore"));
                    case "--client-keystore-password" ->
                            clientKeyStorePassword = requireValue(args, ++index, "--client-keystore-password");
                    case "--client-key-password" ->
                            clientKeyPassword = requireValue(args, ++index, "--client-key-password");
                    case "--client-keystore-type" ->
                            clientKeyStoreType = requireValue(args, ++index, "--client-keystore-type");
                    case "--output" -> outputFormat = OutputFormat.parse(requireValue(args, ++index, "--output"));
                    case "--connect-timeout-ms" ->
                            connectTimeoutMillis = Integer.parseInt(requireValue(args, ++index, "--connect-timeout-ms"));
                    case "--read-timeout-ms" ->
                            readTimeoutMillis = Integer.parseInt(requireValue(args, ++index, "--read-timeout-ms"));
                    case "--help", "-h" -> help = true;
                    default -> throw new IllegalArgumentException("Unknown argument: " + argument);
                }
            }

            if (!"https".equalsIgnoreCase(url.getScheme())) {
                throw new IllegalArgumentException("Only https URLs are supported: " + url);
            }
            if (trustAll && trustStorePath != null) {
                throw new IllegalArgumentException("Use either --trust-all or --truststore, not both.");
            }
            if (trustStorePath != null && trustStorePassword == null) {
                throw new IllegalArgumentException("--truststore-password is required when --truststore is set.");
            }
            if (clientKeyStorePath != null && clientKeyStorePassword == null) {
                throw new IllegalArgumentException(
                        "--client-keystore-password is required when --client-keystore is set.");
            }
            if (clientKeyStorePath == null && clientKeyPassword != null) {
                throw new IllegalArgumentException("--client-key-password requires --client-keystore.");
            }
            if (clientKeyPassword == null && clientKeyStorePassword != null) {
                clientKeyPassword = clientKeyStorePassword;
            }

            return new ClientOptions(
                    url,
                    namedGroup,
                    trustAll,
                    help,
                    connectTimeoutMillis,
                    readTimeoutMillis,
                    trustStorePath,
                    trustStorePassword,
                    trustStoreType,
                    clientKeyStorePath,
                    clientKeyStorePassword,
                    clientKeyPassword,
                    clientKeyStoreType,
                    outputFormat
            );
        }

        private static String requireValue(String[] args, int index, String optionName) {
            if (index >= args.length) {
                throw new IllegalArgumentException("Missing value for " + optionName);
            }
            return args[index];
        }

        static String usage() {
            return """
                                        Usage: java -cp target/classes dev.logicojp.example.pqchybridtls.client.HybridTlsClient [options]

                    Options:
                      --url <https-url>                    HTTPS endpoint to call
                      --named-group <group>                TLS named group to force (default: X25519MLKEM768)
                      --trust-all                          Trust any server certificate for local demo use only
                      --truststore <path>                 Truststore for validating the server certificate
                      --truststore-password <password>    Truststore password
                      --truststore-type <type>            Truststore type (default: PKCS12)
                      --client-keystore <path>            Client PKCS12/JKS keystore for mTLS
                      --client-keystore-password <pass>   Client keystore password
                      --client-key-password <pass>        Client private key password (defaults to keystore password)
                      --client-keystore-type <type>       Client keystore type (default: PKCS12)
                      --output <text|json>                Output format (default: text)
                      --connect-timeout-ms <millis>       Socket connect timeout (default: 5000)
                      --read-timeout-ms <millis>          Socket read timeout (default: 5000)
                      --help                              Show this message
                    """;
        }

        URI uri() {
            return uri;
        }

        String namedGroup() {
            return namedGroup;
        }

        boolean trustAll() {
            return trustAll;
        }

        boolean help() {
            return help;
        }

        int connectTimeoutMillis() {
            return connectTimeoutMillis;
        }

        int readTimeoutMillis() {
            return readTimeoutMillis;
        }

        Path trustStorePath() {
            return trustStorePath;
        }

        String trustStorePassword() {
            return trustStorePassword;
        }

        String trustStoreType() {
            return trustStoreType;
        }

        Path clientKeyStorePath() {
            return clientKeyStorePath;
        }

        String clientKeyStorePassword() {
            return clientKeyStorePassword;
        }

        String clientKeyPassword() {
            return clientKeyPassword;
        }

        String clientKeyStoreType() {
            return clientKeyStoreType;
        }

        OutputFormat outputFormat() {
            return outputFormat;
        }

        boolean mtlsEnabled() {
            return clientKeyStorePath != null;
        }

        String trustMode() {
            if (trustAll) {
                return "trust-all";
            }
            if (trustStorePath != null) {
                return "truststore";
            }
            return "default";
        }
    }
}
