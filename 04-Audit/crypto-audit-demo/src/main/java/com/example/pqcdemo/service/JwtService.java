package com.example.pqcdemo.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * JWT token generation service — uses Spring Security's {@link JwtEncoder}.
 *
 * <h3>CRYPTO AUDIT POINT — RS256 JWT signing</h3>
 * <ul>
 *   <li><b>Algorithm:</b> RS256 (SHA-256 with RSA), key material loaded from keystore in
 *       {@link com.example.pqcdemo.config.SecurityConfig}</li>
 *   <li><b>Quantum-vulnerable?</b> YES — Shor's algorithm breaks RSA.</li>
 *   <li><b>Key difference from raw jjwt:</b> The signing happens inside
 *       Spring Security's {@code NimbusJwtEncoder}. The crypto call
 *       ({@code Signature.getInstance("SHA256withRSA")}) is buried in the
 *       Nimbus JOSE+JWT library — invisible to application-level grep.
 *       This is realistic: most production apps use framework-managed JWT.</li>
 *   <li><b>PQC migration:</b> Replace RSA key with ML-DSA key in SecurityConfig.
 *       Once nimbus-jose-jwt supports ML-DSA algorithm identifiers, the
 *       JwtEncoder/JwtDecoder will handle it transparently.</li>
 * </ul>
 */
@Service
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);

    private final JwtEncoder jwtEncoder;
    private final String jwtIssuer;

    public JwtService(JwtEncoder jwtEncoder,
                      @Value("${app.security.jwt.issuer}") String jwtIssuer) {
        this.jwtEncoder = jwtEncoder;
        this.jwtIssuer = jwtIssuer;
    }

    /**
     * Generate a signed JWT for the given username.
     *
     * <p>The actual RSA signing happens inside {@code NimbusJwtEncoder},
     * which delegates to Nimbus JOSE+JWT's signer implementation.
     *
     * @param username the subject claim
     * @return a compact JWS string signed with RS256
     */
    public String generateToken(String username) {
        Instant now = Instant.now();

        // CRYPTO AUDIT: JWS header specifies RS256 (RSA) — quantum-vulnerable
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256)
                .build();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(jwtIssuer)
                .subject(username)
                .issuedAt(now)
                .expiresAt(now.plus(1, ChronoUnit.HOURS))
                .build();

        // CRYPTO AUDIT: RSA signature happens inside the encoder
        String token = jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();

        log.info("Generated JWT for user '{}' (algorithm: RS256 — quantum-vulnerable)", username);
        return token;
    }
}
