package com.example.pqcdemo.service;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Base64;

/**
 * Data-at-rest encryption service — represents the common pattern of
 * encrypting sensitive database columns (PII, tokens, API keys).
 *
 * <p>This implementation uses <b>Google Tink</b> as a crypto abstraction layer.
 * Tink manages key material, IV generation, and algorithm selection internally.
 *
 * <h3>CRYPTO AUDIT POINT #5 — AES-256-GCM bulk encryption (via Tink)</h3>
 * <ul>
 *   <li><b>Algorithm:</b> AES-256 in GCM mode (authenticated encryption)</li>
 *   <li><b>CRYPTO AUDIT NOTE:</b> The algorithm is NOT visible in source code —
 *       must consult Tink documentation and key template to determine the actual
 *       algorithm. {@code PredefinedAeadParameters.AES256_GCM} specifies AES-256-GCM.</li>
 *   <li><b>Quantum-vulnerable?</b> Partially — Grover's algorithm reduces
 *       AES-256 to ~128-bit security. NIST considers AES-256 safe for
 *       post-quantum use, but AES-128 would drop to ~64-bit effective strength.</li>
 *   <li><b>PQC migration path:</b> AES-256-GCM is acceptable long-term.
 *       No immediate action needed for the bulk cipher itself. To migrate,
 *       change the Tink key template — no other code changes required.</li>
 * </ul>
 *
 * <p><b>Architecture pattern:</b> Google Tink manages the entire encryption
 * lifecycle: key generation, IV randomness, AEAD construction, and ciphertext
 * framing. The {@code Aead.encrypt()} call hides all of this behind a single
 * API — making the actual algorithm invisible to a naive source-code grep.
 */
@Service
public class EncryptionService {

    private static final Logger log = LoggerFactory.getLogger(EncryptionService.class);

    // CRYPTO AUDIT: Tink AEAD primitive — algorithm determined by key template,
    // NOT by this variable name. Consult PredefinedAeadParameters.AES256_GCM
    // in @PostConstruct to determine the actual algorithm (AES-256-GCM).
    private Aead aead;

    @PostConstruct
    public void init() throws Exception {
        log.info("Initializing encryption service via Google Tink...");

        // Register all Tink AEAD implementations
        AeadConfig.register();

        // CRYPTO AUDIT: Key template determines the algorithm.
        // PredefinedAeadParameters.AES256_GCM → AES-256-GCM (quantum-safe bulk cipher)
        // Tink manages the key material internally — no RSA key wrapping needed.
        KeysetHandle keysetHandle = KeysetHandle.generateNew(PredefinedAeadParameters.AES256_GCM);
        this.aead = keysetHandle.getPrimitive(Aead.class);

        log.info("Encryption service ready. Google Tink AEAD (AES-256-GCM) initialized.");
    }

    /**
     * Encrypt plaintext using the Tink AEAD primitive.
     *
     * <p>Tink handles IV generation, AEAD construction, and ciphertext framing
     * internally. The actual algorithm is AES-256-GCM as specified by the
     * key template in {@link #init()}.
     *
     * @param plaintext the data to encrypt
     * @return Base64-encoded Tink ciphertext (includes IV and GCM tag internally)
     */
    public String encrypt(String plaintext) throws Exception {
        // CRYPTO AUDIT: Tink AEAD — algorithm hidden in key template (AES-256-GCM)
        byte[] ciphertext = aead.encrypt(plaintext.getBytes(), null);
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    /**
     * Decrypt ciphertext that was encrypted with {@link #encrypt(String)}.
     *
     * @param ciphertextBase64 Base64-encoded Tink ciphertext
     * @return the original plaintext
     */
    public String decrypt(String ciphertextBase64) throws Exception {
        byte[] ciphertext = Base64.getDecoder().decode(ciphertextBase64);
        // CRYPTO AUDIT: Tink AEAD — algorithm hidden in key template (AES-256-GCM)
        return new String(aead.decrypt(ciphertext, null));
    }
}
