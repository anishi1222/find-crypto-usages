package com.example.pqcdemo.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

/**
 * Spring Security configuration — OAuth2 Resource Server with JWT validation.
 *
 * <h3>CRYPTO AUDIT POINTS</h3>
 * <ul>
 *   <li><b>🔴 RSA key material for JWT signing/verification</b> — loaded from PKCS12 keystore.
 *       RSA is quantum-vulnerable via Shor's algorithm.</li>
 *   <li><b>🔴 JWT signature verification</b> — Spring Security's {@code NimbusJwtDecoder}
 *       internally verifies every incoming Bearer token using Nimbus JOSE+JWT.
 *       The crypto is <em>inside the framework</em>, invisible to application code.</li>
 *   <li><b>🟢 BCrypt password hashing</b> — Symmetric/hash primitive, low quantum risk.</li>
 * </ul>
 *
 * <p><b>Operational hardening:</b> Key material is loaded from a keystore instead of
 * generating ephemeral keys at startup, and issuer validation is enabled by default.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    private final ResourceLoader resourceLoader;
    private final String jwtIssuer;
    private final String jwtKeystorePath;
    private final String jwtKeystorePassword;
    private final String jwtKeyAlias;
    private final boolean allowPublicDemoEndpoints;

    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;

    public SecurityConfig(
            ResourceLoader resourceLoader,
            @Value("${app.security.jwt.issuer}") String jwtIssuer,
            @Value("${app.security.jwt.keystore.path}") String jwtKeystorePath,
            @Value("${app.security.jwt.keystore.password}") String jwtKeystorePassword,
            @Value("${app.security.jwt.keystore.alias}") String jwtKeyAlias,
            @Value("${app.security.allow-public-demo-endpoints:false}") boolean allowPublicDemoEndpoints
    ) {
        this.resourceLoader = resourceLoader;
        this.jwtIssuer = jwtIssuer;
        this.jwtKeystorePath = jwtKeystorePath;
        this.jwtKeystorePassword = jwtKeystorePassword;
        this.jwtKeyAlias = jwtKeyAlias;
        this.allowPublicDemoEndpoints = allowPublicDemoEndpoints;
    }

    /**
     * Loads JWT key material from keystore.
     */
    @PostConstruct
    public void initKeys() throws Exception {
        log.info("Loading JWT key pair from keystore: {} (alias: {})", jwtKeystorePath, jwtKeyAlias);

        char[] passwordChars = jwtKeystorePassword.toCharArray();
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (var is = resourceLoader.getResource(jwtKeystorePath).getInputStream()) {
                keyStore.load(is, passwordChars);
            }

            var key = keyStore.getKey(jwtKeyAlias, passwordChars);
            if (!(key instanceof RSAPrivateKey rsaPrivateKey)) {
                throw new IllegalStateException("JWT private key for alias '" + jwtKeyAlias + "' is not RSA.");
            }
            var certificate = keyStore.getCertificate(jwtKeyAlias);
            if (certificate == null || !(certificate.getPublicKey() instanceof RSAPublicKey rsaPublicKey)) {
                throw new IllegalStateException("JWT certificate for alias '" + jwtKeyAlias + "' is missing or not RSA.");
            }

            this.privateKey = rsaPrivateKey;
            this.publicKey = rsaPublicKey;
        } finally {
            Arrays.fill(passwordChars, '\0');
        }

        if (allowPublicDemoEndpoints) {
            log.warn("Demo mode enabled: /api/token, /api/verify, /api/license/check, and /api/x509/validate-self are publicly accessible.");
        }
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> {
                auth.requestMatchers("/api/health", "/error").permitAll();
                if (allowPublicDemoEndpoints) {
                    auth.requestMatchers(HttpMethod.POST, "/api/token", "/api/verify").permitAll();
                    auth.requestMatchers(HttpMethod.GET, "/api/license/check", "/api/x509/validate-self").permitAll();
                }
                auth.anyRequest().authenticated();
            })
            // CRYPTO AUDIT: OAuth2 Resource Server — JWT signature verification happens
            // inside NimbusJwtDecoder (Nimbus JOSE+JWT), invisible to application code
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.decoder(jwtDecoder()))
            );

        return http.build();
    }

    /**
     * CRYPTO AUDIT: NimbusJwtDecoder — verifies JWT signatures using RSA.
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(publicKey).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(jwtIssuer));
        return decoder;
    }

    /**
     * CRYPTO AUDIT: JwtEncoder signs JWTs with RSA — quantum-vulnerable.
     */
    @Bean
    public JwtEncoder jwtEncoder() {
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(jwtKeyAlias)
                .build();
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(rsaKey)));
    }

    /** CRYPTO AUDIT: BCrypt password encoder — low quantum risk.
     * Kept as a standalone bean to be detected by the audit script,
     * but not wired into the security filter chain for this demo. */
    // @Bean — intentionally not a bean to avoid triggering DaoAuthenticationProvider
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
