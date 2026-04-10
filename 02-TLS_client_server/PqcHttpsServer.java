import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;

public class PqcHttpsServer {

    private static final String DEFAULT_KEYSTORE_PATH = "keystore.p12";
    private static final String DEFAULT_KEYSTORE_PASSWORD = "changeit";
    private static final int PORT = 8443;

    public static void main(String... args) throws Exception {
        String keystorePath = getenvOrDefault("KEYSTORE_PATH", DEFAULT_KEYSTORE_PATH);
        String keystorePassword = getenvOrDefault("KEYSTORE_PASSWORD", DEFAULT_KEYSTORE_PASSWORD);

        Path keystoreFile = Path.of(keystorePath);
        if (!Files.exists(keystoreFile)) {
            throw new IllegalStateException(
                    "Keystore not found: " + keystoreFile.toAbsolutePath()
                            + " (set KEYSTORE_PATH if you want to use a different file)"
            );
        }

        char[] password = keystorePassword.toCharArray();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(keystoreFile.toFile())) {
            keyStore.load(fis, password);
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, password);

        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());

        HttpsServer server = HttpsServer.create(new InetSocketAddress(PORT), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            @Override
            public void configure(HttpsParameters params) {
                SSLParameters sslParameters = getSSLContext().getDefaultSSLParameters();
                sslParameters.setProtocols(new String[]{sslContext.getProtocol()});
                params.setSSLParameters(sslParameters);
            }
        });

        server.createContext("/", exchange -> {
            byte[] body = ("Hello from Java " + sslContext.getProtocol()).getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(HttpURLConnection.HTTP_OK, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });

        server.start();
        System.out.println("Server started on https://localhost:" + PORT);
        System.out.println("Using keystore: " + keystoreFile.toAbsolutePath());
    }

    private static String getenvOrDefault(String key, String defaultValue) {
        String value = System.getenv(key);
        return value == null || value.isBlank() ? defaultValue : value;
    }
}
