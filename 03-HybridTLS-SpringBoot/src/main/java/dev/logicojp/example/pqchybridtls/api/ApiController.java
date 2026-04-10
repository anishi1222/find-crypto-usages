package dev.logicojp.example.pqchybridtls.api;

import jakarta.servlet.http.HttpServletRequest;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ApiController {

    private static final String DEFAULT_NAMED_GROUPS_NOTE =
            "No jdk.tls.namedGroups override detected; JDK 27 JSSE defaults prefer X25519MLKEM768 for TLS 1.3 clients.";

    private final Environment environment;

    public ApiController(Environment environment) {
        this.environment = environment;
    }

    @GetMapping("/hello")
    public GreetingResponse hello(@RequestParam(defaultValue = "world") String name) {
        return new GreetingResponse(
                "Hello, " + name + "!",
                Instant.now(),
                Runtime.version().toString(),
                true
        );
    }

    @GetMapping("/tls")
    public TlsInfoResponse tls(HttpServletRequest request) {
        X509Certificate[] certificates =
                (X509Certificate[]) request.getAttribute("jakarta.servlet.request.X509Certificate");

        return new TlsInfoResponse(
                request.isSecure(),
                request.getScheme(),
                request.getProtocol(),
                (String) request.getAttribute("jakarta.servlet.request.cipher_suite"),
                (Integer) request.getAttribute("jakarta.servlet.request.key_size"),
                (String) request.getAttribute("jakarta.servlet.request.ssl_session_id"),
                List.of(environment.getActiveProfiles()),
                System.getProperty("jdk.tls.namedGroups", DEFAULT_NAMED_GROUPS_NOTE),
                certificates != null && certificates.length > 0
                        ? certificates[0].getSubjectX500Principal().getName()
                        : null,
                "Hybrid TLS named group negotiation happens inside JSSE during the TLS 1.3 handshake."
        );
    }

    public record GreetingResponse(
            String message,
            Instant timestamp,
            String javaVersion,
            boolean hybridTlsReady
    ) {
    }

    public record TlsInfoResponse(
            boolean secure,
            String scheme,
            String httpProtocol,
            String cipherSuite,
            Integer keySize,
            String sessionId,
            List<String> activeProfiles,
            String configuredNamedGroups,
            String clientCertificateSubject,
            String note
    ) {
    }
}
