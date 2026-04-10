package com.example.pqcdemo.service;

import jakarta.annotation.PostConstruct;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.KeyParameter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * HMAC-based request signing service — used for API-to-API authentication
 * and message integrity verification.
 *
 * <p>This implementation uses the <b>Bouncy Castle lightweight API</b> ({@code HMac})
 * rather than the JCE {@code Mac.getInstance()} call, which is the pattern used
 * in many production libraries and frameworks.
 *
 * <h3>CRYPTO AUDIT POINT #7 — HMAC-SHA256 (via Bouncy Castle HMac)</h3>
 * <ul>
 *   <li><b>Algorithm:</b> HMAC with SHA-256 (256-bit key)</li>
 *   <li><b>CRYPTO AUDIT NOTE:</b> The algorithm is determined by the {@code Digest}
 *       passed to {@code HMac} constructor. Here {@code SHA256Digest} is used,
 *       giving HMAC-SHA256. A naive grep for "HmacSHA256" will find nothing —
 *       must inspect the {@code HMac} constructor argument.</li>
 *   <li><b>Quantum-vulnerable?</b> Partially, but low risk.
 *       Grover's algorithm halves the effective key strength: a 256-bit
 *       HMAC key would have ~128-bit post-quantum security, which is
 *       still considered safe by NIST.</li>
 *   <li><b>PQC migration path:</b> HMAC-SHA256 with a 256-bit key is
 *       considered quantum-safe. No immediate migration needed.
 *       For extra margin, use HMAC-SHA384 or HMAC-SHA512.</li>
 * </ul>
 *
 * <p><b>Important distinction:</b> Unlike RSA/ECDSA, HMAC is a symmetric
 * primitive. Shor's algorithm does NOT apply. Only Grover's algorithm
 * (quadratic speedup for search) is relevant, and it is far less
 * threatening than Shor's exponential speedup for factoring/ECDLP.
 */
@Service
public class HmacService {

    private static final Logger log = LoggerFactory.getLogger(HmacService.class);

    // CRYPTO AUDIT: HMAC-SHA256 key bytes — quantum-resistant at 256-bit level.
    // Algorithm is determined by SHA256Digest passed to HMac constructor in sign().
    private byte[] hmacKeyBytes;

    @PostConstruct
    public void init() {
        log.info("Generating HMAC-SHA256 key for API request signing...");

        // CRYPTO AUDIT: 32-byte (256-bit) random key for HMAC-SHA256
        hmacKeyBytes = new byte[32];
        new SecureRandom().nextBytes(hmacKeyBytes);

        log.info("HMAC-SHA256 key ready.");
    }

    /**
     * Compute an HMAC-SHA256 signature for the given message.
     *
     * @param message the message to sign
     * @return Base64-encoded HMAC signature
     */
    public String sign(String message) {
        // CRYPTO AUDIT: Bouncy Castle HMac with SHA256Digest — HMAC-SHA256
        // Algorithm is hidden in the digest constructor argument, not in a string literal.
        HMac hmac = new HMac(new SHA256Digest());
        hmac.init(new KeyParameter(hmacKeyBytes));
        byte[] messageBytes = message.getBytes();
        hmac.update(messageBytes, 0, messageBytes.length);
        byte[] result = new byte[hmac.getMacSize()];
        hmac.doFinal(result, 0);
        return Base64.getEncoder().encodeToString(result);
    }

    /**
     * Verify an HMAC-SHA256 signature for the given message.
     * Uses constant-time comparison to prevent timing attacks.
     *
     * @param message   the original message
     * @param signature the Base64-encoded HMAC to verify
     * @return true if the signature is valid
     */
    public boolean verify(String message, String signature) {
        byte[] expected = Base64.getDecoder().decode(sign(message));
        byte[] actual   = Base64.getDecoder().decode(signature);
        // Constant-time comparison to prevent timing side-channel attacks
        return org.bouncycastle.util.Arrays.constantTimeAreEqual(expected, actual);
    }
}
