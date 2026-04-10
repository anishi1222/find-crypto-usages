package com.example.pqcdemo;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Security;

/**
 * PQC Crypto Audit Demo — a "typical" Spring Boot microservice.
 *
 * <p>This application intentionally contains ~12 cryptographic usage points
 * scattered across configuration, services, and transitive dependencies.
 * Most of these are invisible to developers during normal code review.
 *
 * <p><b>Crypto audit points registered at startup:</b>
 * <ol>
 *   <li>Bouncy Castle JCE provider registration (below)</li>
 *   <li>TLS server certificate via {@code server.ssl.*} properties</li>
 *   <li>PostgreSQL JDBC TLS (inside the driver, not in our code)</li>
 *   <li>JWT signing/verification — RS256 via Spring Security + Nimbus</li>
 *   <li>AES-256-GCM bulk encryption via Google Tink in {@code EncryptionService}</li>
 *   <li>HMAC-SHA256 request signing via BC lightweight API in {@code HmacService}</li>
 *   <li>BCrypt password hashing in {@code SecurityConfig}</li>
 *   <li>RSA license signature verification via BC CMS in {@code LicenseService}</li>
 *   <li>X.509 certificate inside the PKCS12 keystore</li>
 * </ol>
 */
@SpringBootApplication
public class PqcDemoApplication {

    public static void main(String[] args) {
        // CRYPTO AUDIT POINT #1 — Bouncy Castle provider registration.
        // Adds a full JCE/JCA provider with hundreds of algorithm implementations.
        // PQC note: BC 1.78+ already ships ML-KEM / ML-DSA implementations,
        // so this provider will be part of the migration path too.
        Security.addProvider(new BouncyCastleProvider());

        SpringApplication.run(PqcDemoApplication.class, args);
    }
}
