package com.example.pqcdemo.service;

import jakarta.annotation.PostConstruct;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

/**
 * License validation service — verifies CMS/PKCS#7 license signatures.
 *
 * <p><b>Operational hardening:</b> this service now loads certificate material
 * from keystore and defaults to verify-only behavior. Demo signing can be
 * explicitly enabled via {@code app.license.allow-demo-signing=true}.
 *
 * <h3>CRYPTO AUDIT POINT — RSA signature verification hidden in CMS API</h3>
 * <ul>
 *   <li><b>Algorithm:</b> SHA256withRSA (inside CMS SignerInfo)</li>
 *   <li><b>Risk:</b> Quantum-vulnerable (Shor's algorithm breaks RSA)</li>
 *   <li><b>Pattern:</b> Algorithm appears via BC builder/ASN.1 structures, not direct
 *       {@code Signature.getInstance(...)} calls</li>
 * </ul>
 */
@Service
public class LicenseService {

    private static final Logger log = LoggerFactory.getLogger(LicenseService.class);

    private final ResourceLoader resourceLoader;
    private final String keystorePath;
    private final String keystorePassword;
    private final String keyAlias;
    private final boolean allowDemoSigning;

    private X509CertificateHolder licenseCertHolder;
    private PrivateKey licensePrivateKey;

    public LicenseService(
            ResourceLoader resourceLoader,
            @Value("${app.license.keystore.path}") String keystorePath,
            @Value("${app.license.keystore.password}") String keystorePassword,
            @Value("${app.license.keystore.alias}") String keyAlias,
            @Value("${app.license.allow-demo-signing:false}") boolean allowDemoSigning
    ) {
        this.resourceLoader = resourceLoader;
        this.keystorePath = keystorePath;
        this.keystorePassword = keystorePassword;
        this.keyAlias = keyAlias;
        this.allowDemoSigning = allowDemoSigning;
    }

    @PostConstruct
    public void init() throws Exception {
        log.info("Loading license verification material from keystore: {} (alias: {})", keystorePath, keyAlias);

        Security.addProvider(new BouncyCastleProvider());

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        char[] passwordChars = keystorePassword.toCharArray();
        try {
            try (var is = resourceLoader.getResource(keystorePath).getInputStream()) {
                keyStore.load(is, passwordChars);
            }

            var certificate = keyStore.getCertificate(keyAlias);
            if (!(certificate instanceof X509Certificate x509Certificate)) {
                throw new IllegalStateException("License certificate for alias '" + keyAlias + "' is missing or not X.509.");
            }
            this.licenseCertHolder = new JcaX509CertificateHolder(x509Certificate);

            if (allowDemoSigning) {
                var key = keyStore.getKey(keyAlias, passwordChars);
                if (!(key instanceof PrivateKey privateKey)) {
                    throw new IllegalStateException("License private key for alias '" + keyAlias + "' is unavailable.");
                }
                this.licensePrivateKey = privateKey;
                log.warn("Demo license signing is enabled. Disable app.license.allow-demo-signing in production.");
            } else {
                this.licensePrivateKey = null;
            }
        } finally {
            java.util.Arrays.fill(passwordChars, '\0');
        }
    }

    public boolean isDemoSigningEnabled() {
        return allowDemoSigning;
    }

    /**
     * Verify a software license key against its CMS/PKCS#7 signature.
     *
     * @param licenseKey expected embedded license payload
     * @param cmsDataB64 Base64-encoded CMS {@code SignedData}
     * @return true if signature is valid and embedded payload matches licenseKey
     */
    public boolean verifyLicense(String licenseKey, String cmsDataB64) throws Exception {
        byte[] cmsBytes = Base64.getDecoder().decode(cmsDataB64);
        CMSSignedData signedData = new CMSSignedData(cmsBytes);

        Object content = signedData.getSignedContent() != null ? signedData.getSignedContent().getContent() : null;
        if (!(content instanceof byte[] payloadBytes)) {
            log.warn("CMS SignedData has no byte[] payload.");
            return false;
        }
        String payload = new String(payloadBytes, StandardCharsets.UTF_8);
        if (!payload.equals(licenseKey)) {
            log.warn("License payload mismatch. expected='{}' embedded='{}'", licenseKey, payload);
            return false;
        }

        for (SignerInformation signerInfo : signedData.getSignerInfos().getSigners()) {
            @SuppressWarnings("unchecked")
            Collection<X509CertificateHolder> certs =
                    signedData.getCertificates().getMatches(signerInfo.getSID());
            for (X509CertificateHolder cert : certs) {
                var verifier = new JcaSimpleSignerInfoVerifierBuilder()
                        .setProvider("BC")
                        .build(cert);
                if (signerInfo.verify(verifier)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Generate a CMS/PKCS#7 signed license (demo only).
     *
     * @param licenseKey the license payload to sign
     * @return Base64-encoded CMS SignedData
     */
    public String signLicense(String licenseKey) throws Exception {
        if (!allowDemoSigning || licensePrivateKey == null) {
            throw new IllegalStateException("Demo license signing is disabled. Set app.license.allow-demo-signing=true for demo mode.");
        }

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(licensePrivateKey);

        generator.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()
                ).build(signer, licenseCertHolder)
        );
        generator.addCertificates(new JcaCertStore(List.of(licenseCertHolder)));

        CMSProcessableByteArray cmsData = new CMSProcessableByteArray(licenseKey.getBytes(StandardCharsets.UTF_8));
        CMSSignedData signedData = generator.generate(cmsData, true);
        return Base64.getEncoder().encodeToString(signedData.getEncoded());
    }
}
