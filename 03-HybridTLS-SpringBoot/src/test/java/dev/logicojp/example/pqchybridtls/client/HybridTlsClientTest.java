package dev.logicojp.example.pqchybridtls.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class HybridTlsClientTest {

    @Test
    void parserUsesExpectedDefaults() {
        HybridTlsClient.ClientOptions options = HybridTlsClient.ClientOptions.parse(new String[0]);

        assertEquals("https://localhost:8443/api/hello?name=HybridTLS", options.uri().toString());
        assertEquals("X25519MLKEM768", options.namedGroup());
        assertEquals(HybridTlsClient.OutputFormat.TEXT, options.outputFormat());
        assertFalse(options.trustAll());
        assertFalse(options.mtlsEnabled());
    }

    @Test
    void parserAcceptsMtlsAndJsonOptions() {
        HybridTlsClient.ClientOptions options = HybridTlsClient.ClientOptions.parse(new String[]{
                "--url", "https://localhost:9445/api/tls",
                "--named-group", "SecP256r1MLKEM768",
                "--truststore", "certs/client-truststore.p12",
                "--truststore-password", "changeit",
                "--client-keystore", "certs/client-keystore.p12",
                "--client-keystore-password", "changeit",
                "--output", "json",
                "--connect-timeout-ms", "1000",
                "--read-timeout-ms", "2000"
        });

        assertEquals("https://localhost:9445/api/tls", options.uri().toString());
        assertEquals("SecP256r1MLKEM768", options.namedGroup());
        assertEquals(HybridTlsClient.OutputFormat.JSON, options.outputFormat());
        assertTrue(options.mtlsEnabled());
        assertEquals("truststore", options.trustMode());
        assertEquals(1000, options.connectTimeoutMillis());
        assertEquals(2000, options.readTimeoutMillis());
        assertEquals("changeit", options.clientKeyPassword());
    }

    @Test
    void parserRejectsNonHttpsUrls() {
        assertThrows(IllegalArgumentException.class, () ->
                HybridTlsClient.ClientOptions.parse(new String[]{"--url", "http://localhost:8080/api/hello"}));
    }

    @Test
    void parserRejectsConflictingTrustOptions() {
        assertThrows(IllegalArgumentException.class, () ->
                HybridTlsClient.ClientOptions.parse(new String[]{
                        "--trust-all",
                        "--truststore", "certs/client-truststore.p12",
                        "--truststore-password", "changeit"
                }));
    }

    @Test
    void jsonEscapingCoversSpecialCharacters() {
        assertEquals("line1\\n\\\"quoted\\\"", HybridTlsClient.escapeJson("line1\n\"quoted\""));
    }
}
