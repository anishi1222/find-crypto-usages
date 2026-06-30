import java.io.FileInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public class PqcHttpsClient {

    static final String TRUSTSTORE_PATH = "truststore.p12";
    static final String KEYSTORE_PASSWD = "changeit";
    void main(String[] args) throws Exception {
        char[] password = KEYSTORE_PASSWD.toCharArray();
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(TRUSTSTORE_PATH)) {
            trustStore.load(fis, password);
        }

        TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(null, tmf.getTrustManagers(), null);

        HttpClient client = HttpClient.newBuilder().sslContext(sslContext).build();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://localhost:8443/"))
                .build();

        HttpResponse<String> response =
                client.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.println(response.statusCode());
        System.out.println(response.body());
    }
}