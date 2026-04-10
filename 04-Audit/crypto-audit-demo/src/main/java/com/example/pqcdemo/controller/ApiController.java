package com.example.pqcdemo.controller;

import com.example.pqcdemo.service.EncryptionService;
import com.example.pqcdemo.service.HmacService;
import com.example.pqcdemo.service.JwtService;
import com.example.pqcdemo.service.LicenseService;
import com.example.pqcdemo.service.X509ValidationDemoService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * REST API controller — uses Spring Security OAuth2 Resource Server for JWT auth.
 *
 * <p><b>Key change from raw jjwt version:</b> JWT validation is now handled by
 * Spring Security's filter chain. The controller receives an already-verified
 * {@link Jwt} principal. No manual {@code jwtService.validateToken()} calls.
 *
 * <p>This is the realistic pattern — and it makes crypto harder to audit,
 * because JWT signature verification is invisible at the application code level.
 */
@RestController
@RequestMapping("/api")
public class ApiController {

    private final JwtService jwtService;
    private final EncryptionService encryptionService;
    private final HmacService hmacService;
    private final LicenseService licenseService;
    private final X509ValidationDemoService x509ValidationDemoService;

    public ApiController(JwtService jwtService,
                         EncryptionService encryptionService,
                         HmacService hmacService,
                         LicenseService licenseService,
                         X509ValidationDemoService x509ValidationDemoService) {
        this.jwtService = jwtService;
        this.encryptionService = encryptionService;
        this.hmacService = hmacService;
        this.licenseService = licenseService;
        this.x509ValidationDemoService = x509ValidationDemoService;
    }

    /**
     * Public health-check endpoint — no auth required.
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of(
                "status", "UP",
                "crypto_note", "TLS protects this response (server.ssl.enabled=true)"
        ));
    }

    /**
     * JWT-protected endpoint that returns encrypted data.
     *
     * <p>Spring Security validates the Bearer token automatically via
     * {@code NimbusJwtDecoder} — RSA signature verification happens
     * in the framework, not in this code.
     */
    @GetMapping("/data")
    public ResponseEntity<Map<String, String>> getData(
            @AuthenticationPrincipal Jwt jwt) throws Exception {

        String user = jwt != null ? jwt.getSubject() : "anonymous";

        String sensitiveData = "SSN: 123-45-6789, User: " + user;
        String encrypted = encryptionService.encrypt(sensitiveData);

        return ResponseEntity.ok(Map.of(
                "user", user,
                "encrypted_data", encrypted,
                "algorithm", "AES-256-GCM via Google Tink AEAD (quantum-safe bulk cipher)"
        ));
    }

    /**
     * HMAC-signed request verification endpoint.
     */
    @PostMapping("/verify")
    public ResponseEntity<Map<String, Object>> verifyRequest(
            @RequestBody Map<String, String> body) throws Exception {

        String message = body.getOrDefault("message", "");
        String signature = body.getOrDefault("signature", "");

        if (signature.isEmpty()) {
            String newSignature = hmacService.sign(message);
            return ResponseEntity.ok(Map.of(
                    "message", message,
                    "signature", newSignature,
                    "algorithm", "HMAC-SHA256 (quantum-resistant)"
            ));
        }

        boolean valid = hmacService.verify(message, signature);
        return ResponseEntity.ok(Map.of(
                "message", message,
                "valid", valid,
                "algorithm", "HMAC-SHA256 (quantum-resistant)"
        ));
    }

    /**
     * License verification endpoint.
     *
     * <p>Production mode: requires both {@code key} and {@code signature} params.
     * Demo mode ({@code app.license.allow-demo-signing=true}): if signature is omitted,
     * a demo signature is generated and immediately verified.
     */
    @GetMapping("/license/check")
    public ResponseEntity<Map<String, Object>> checkLicense(
            @RequestParam(defaultValue = "DEMO-LICENSE-2024") String key,
            @RequestParam(required = false) String signature) throws Exception {

        if (signature == null || signature.isBlank()) {
            if (licenseService.isDemoSigningEnabled()) {
                String demoSignature = licenseService.signLicense(key);
                boolean valid = licenseService.verifyLicense(key, demoSignature);
                return ResponseEntity.ok(Map.of(
                        "license_key", key,
                        "signature", demoSignature,
                        "valid", valid,
                        "mode", "demo-sign-and-verify",
                        "algorithm", "SHA256withRSA via Bouncy Castle CMS/PKCS#7 (quantum-VULNERABLE)"
                ));
            }

            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Missing required query parameter: signature",
                    "mode", "production-verify-only",
                    "example", "/api/license/check?key=DEMO-LICENSE-2024&signature=<base64-cms>"
            ));
        }

        boolean valid = licenseService.verifyLicense(key, signature);
        return ResponseEntity.ok(Map.of(
                "license_key", key,
                "valid", valid,
                "mode", "production-verify-only",
                "algorithm", "SHA256withRSA via Bouncy Castle CMS/PKCS#7 (quantum-VULNERABLE)"
        ));
    }

    /**
     * Demo endpoint: generate a JWT token for testing.
     * Enabled publicly only when app.security.allow-public-demo-endpoints=true.
     */
    @PostMapping("/token")
    public ResponseEntity<Map<String, String>> generateToken(
            @RequestBody Map<String, String> body) {

        String username = body.getOrDefault("username", "demo-user");
        String token = jwtService.generateToken(username);

        return ResponseEntity.ok(Map.of(
                "token", token,
                "algorithm", "RS256 / RSA (quantum-VULNERABLE)",
                "note", "Signed via Spring Security NimbusJwtEncoder"
        ));
    }

    /**
     * Demo endpoint: make an outbound HTTPS call back to the service and validate
     * the presented server certificate inside the same JVM.
     */
    @GetMapping("/x509/validate-self")
    public ResponseEntity<X509ValidationDemoService.X509ValidationResult> validateServerCertificate() throws Exception {
        return ResponseEntity.ok(x509ValidationDemoService.triggerValidation());
    }
}
