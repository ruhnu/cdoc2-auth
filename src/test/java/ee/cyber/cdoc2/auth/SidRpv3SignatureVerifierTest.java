package ee.cyber.cdoc2.auth;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import ee.cyber.cdoc2.auth.SidRpv3SignatureVerifier.AuthTokenSignatureValidationParams;
import ee.cyber.cdoc2.auth.SidRpv3SignatureVerifier.MaskGenAlgorithm;
import ee.cyber.cdoc2.auth.SidRpv3SignatureVerifier.SessionTokenSignatureValidationParams;
import ee.cyber.cdoc2.auth.SidRpv3SignatureVerifier.SidSignature;
import ee.cyber.cdoc2.auth.SidRpv3SignatureVerifier.SidSignatureParams;
import ee.cyber.cdoc2.auth.SidRpv3SignatureVerifier.SignatureAlgorithmParameters;
import ee.cyber.cdoc2.auth.exception.VerificationException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;


class SidRpv3SignatureVerifierTest {

    private static final String SIGNATURE_ALGORITHM = "RSASSA-PSS";
    private static final String HASH_ALGORITHM = "SHA-256";
    private static final int SALT_LENGTH = 32;

    private static final String RP_NAME = "DEMO";
    private static final String SCHEME_NAME = "smart-id-demo";
    private static final String SERVER_RANDOM = "Z0RhbmRvbV9TZXJ2ZXJfQmFzZTY0X1ZhbHVl";
    private static final String RP_CHALLENGE =
        "VGhpc0lzVGhlUnBDaGFsbGVuZ2VWYWx1ZUluQmFzZTY0RW5jb2Rpbmc=";
    private static final String USER_CHALLENGE =
        "VGhpc0lzVGhlVXNlckNoYWxsZW5nZUluQmFzZTY0VXJsRm9ybWF0";
    private static final String INTERACTIONS_DIGEST =
        "olJN7OXUvfy1bUPNu712X3A7MOm1BXiWtlAmv+ubIz0=";
    private static final String INTERACTION_TYPE_USED = "confirmationMessageAndVerificationCodeChoice";
    private static final String FLOW_TYPE = "Notification";

    private static KeyPair rsaKeyPair;

    @BeforeAll
    static void setUpKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        rsaKeyPair = generator.generateKeyPair();
    }

    @Test
    void verifiesValidSignatureAuthTokenVariant() throws Exception {
        byte[] signatureBytes = signAcspV2Payload(rsaKeyPair.getPrivate());
        String signatureBase64Url = Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(signatureBytes);

        assertDoesNotThrow(() -> SidRpv3SignatureVerifier.verify(
            signatureBase64Url,
            rsaKeyPair.getPublic(),
            authTokenParams(),
            RP_NAME,
            SCHEME_NAME,
            RP_CHALLENGE
        ));
    }

    @Test
    void verifiesValidSignatureSessionTokenVariant() throws Exception {
        byte[] signatureBytes = signAcspV2Payload(rsaKeyPair.getPrivate());
        String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);

        assertDoesNotThrow(() -> SidRpv3SignatureVerifier.verify(
            rsaKeyPair.getPublic(),
            sessionTokenParams(signatureBase64)
        ));
    }

    @Test
    void throwsOnModifiedSignatureBytes() throws Exception {
        byte[] signatureBytes = signAcspV2Payload(rsaKeyPair.getPrivate());
        // Flip the first byte — keeps structural format but breaks cryptographic verification.
        signatureBytes[0] = (byte) (signatureBytes[0] ^ 0xFF);
        String tampered = Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);

        VerificationException ex = assertThrows(VerificationException.class,
            () -> SidRpv3SignatureVerifier.verify(
                tampered,
                rsaKeyPair.getPublic(),
                authTokenParams(),
                RP_NAME,
                SCHEME_NAME,
                RP_CHALLENGE
            ));
        assertEquals("SID RpV3 signature verification failure", ex.getMessage());
    }

    @Test
    void throwsOnWrongPublicKey() throws Exception {
        byte[] signatureBytes = signAcspV2Payload(rsaKeyPair.getPrivate());
        String signatureBase64Url = Base64.getUrlEncoder()
            .withoutPadding().encodeToString(signatureBytes);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        // A different RP's key — verification must not accept a signature made by someone else.
        var otherPublicKey = generator.generateKeyPair().getPublic();

        VerificationException ex = assertThrows(VerificationException.class,
            () -> SidRpv3SignatureVerifier.verify(
                signatureBase64Url,
                otherPublicKey,
                authTokenParams(),
                RP_NAME,
                SCHEME_NAME,
                RP_CHALLENGE
            ));
        assertEquals("SID RpV3 signature verification failure", ex.getMessage());
    }

    @Test
    void throwsOnWrongRpChallenge() throws Exception {
        byte[] signatureBytes = signAcspV2Payload(rsaKeyPair.getPrivate());
        String signatureBase64Url = Base64.getUrlEncoder()
            .withoutPadding().encodeToString(signatureBytes);

        // Signature was produced over RP_CHALLENGE; verify with a DIFFERENT rpChallenge → fail.
        String tamperedRpChallenge = "VGFtcGVyZWRScENoYWxsZW5nZVZhbHVl";

        VerificationException ex = assertThrows(VerificationException.class,
            () -> SidRpv3SignatureVerifier.verify(
                signatureBase64Url,
                rsaKeyPair.getPublic(),
                authTokenParams(),
                RP_NAME,
                SCHEME_NAME,
                tamperedRpChallenge
            ));
        assertEquals("SID RpV3 signature verification failure", ex.getMessage());
    }

    @Test
    void throwsOnWrongServerRandom() throws Exception {
        byte[] signatureBytes = signAcspV2Payload(rsaKeyPair.getPrivate());
        String signatureBase64Url = Base64.getUrlEncoder()
            .withoutPadding().encodeToString(signatureBytes);

        // Build params with tampered serverRandom
        AuthTokenSignatureValidationParams tamperedParams = new AuthTokenSignatureValidationParams(
            INTERACTIONS_DIGEST,
            INTERACTION_TYPE_USED,
            new SidSignatureParams(
                "VGFtcGVyZWRTZXJ2ZXJSYW5kb20=", // tampered
                USER_CHALLENGE,
                SIGNATURE_ALGORITHM,
                FLOW_TYPE,
                defaultSignatureAlgorithmParameters()
            )
        );

        VerificationException ex = assertThrows(VerificationException.class,
            () -> SidRpv3SignatureVerifier.verify(
                signatureBase64Url,
                rsaKeyPair.getPublic(),
                tamperedParams,
                RP_NAME,
                SCHEME_NAME,
                RP_CHALLENGE
            ));
        assertEquals("SID RpV3 signature verification failure", ex.getMessage());
    }

    @Test
    void throwsOnWrongInteractionsDigest() throws Exception {
        byte[] signatureBytes = signAcspV2Payload(rsaKeyPair.getPrivate());
        String signatureBase64Url = Base64.getUrlEncoder()
            .withoutPadding().encodeToString(signatureBytes);

        AuthTokenSignatureValidationParams tamperedParams = new AuthTokenSignatureValidationParams(
            "VGFtcGVyZWRJbnRlcmFjdGlvbnNEaWdlc3Q=", // tampered
            INTERACTION_TYPE_USED,
            defaultSignatureParams()
        );

        VerificationException ex = assertThrows(VerificationException.class,
            () -> SidRpv3SignatureVerifier.verify(
                signatureBase64Url,
                rsaKeyPair.getPublic(),
                tamperedParams,
                RP_NAME,
                SCHEME_NAME,
                RP_CHALLENGE
            ));
        assertEquals("SID RpV3 signature verification failure", ex.getMessage());
    }

    @Test
    void throwsOnWrongFlowType() throws Exception {
        byte[] signatureBytes = signAcspV2Payload(rsaKeyPair.getPrivate());
        String signatureBase64Url = Base64.getUrlEncoder()
            .withoutPadding().encodeToString(signatureBytes);

        AuthTokenSignatureValidationParams tamperedParams = new AuthTokenSignatureValidationParams(
            INTERACTIONS_DIGEST,
            INTERACTION_TYPE_USED,
            new SidSignatureParams(
                SERVER_RANDOM,
                USER_CHALLENGE,
                SIGNATURE_ALGORITHM,
                "DynamicLink", // tampered: original was "Notification"
                defaultSignatureAlgorithmParameters()
            )
        );

        VerificationException ex = assertThrows(VerificationException.class,
            () -> SidRpv3SignatureVerifier.verify(
                signatureBase64Url,
                rsaKeyPair.getPublic(),
                tamperedParams,
                RP_NAME,
                SCHEME_NAME,
                RP_CHALLENGE
            ));
        assertEquals("SID RpV3 signature verification failure", ex.getMessage());
    }

    private static String buildExpectedAcspV2Payload() {
        String rpNameBase64 = Base64.getEncoder()
            .encodeToString(RP_NAME.getBytes(StandardCharsets.UTF_8));
        String[] parts = {
            SCHEME_NAME,
            "ACSP_V2",
            SERVER_RANDOM,
            RP_CHALLENGE,
            USER_CHALLENGE,
            rpNameBase64,
            "", // brokeredRpNameBase64
            INTERACTIONS_DIGEST,
            INTERACTION_TYPE_USED,
            "", // initialCallbackUrl
            FLOW_TYPE
        };
        return String.join("|", parts);
    }

    private static byte[] signAcspV2Payload(PrivateKey privateKey) throws Exception {
        byte[] payloadBytes = buildExpectedAcspV2Payload().getBytes(StandardCharsets.UTF_8);

        Signature signer = Signature.getInstance(SIGNATURE_ALGORITHM);
        signer.setParameter(new PSSParameterSpec(
            HASH_ALGORITHM, "MGF1",
            new MGF1ParameterSpec(HASH_ALGORITHM),
            SALT_LENGTH, PSSParameterSpec.TRAILER_FIELD_BC
        ));
        signer.initSign(privateKey);
        signer.update(payloadBytes);
        return signer.sign();
    }

    private static SidSignatureParams defaultSignatureParams() {
        return new SidSignatureParams(
            SERVER_RANDOM,
            USER_CHALLENGE,
            SIGNATURE_ALGORITHM,
            FLOW_TYPE,
            defaultSignatureAlgorithmParameters()
        );
    }

    private static SignatureAlgorithmParameters defaultSignatureAlgorithmParameters() {
        return new SignatureAlgorithmParameters(
            HASH_ALGORITHM,
            new MaskGenAlgorithm("id-mgf1",
                new MaskGenAlgorithm.Parameters(HASH_ALGORITHM)),
            SALT_LENGTH,
            "0xbc"
        );
    }

    private static AuthTokenSignatureValidationParams authTokenParams() {
        return new AuthTokenSignatureValidationParams(
            INTERACTIONS_DIGEST,
            INTERACTION_TYPE_USED,
            defaultSignatureParams()
        );
    }

    private static SessionTokenSignatureValidationParams sessionTokenParams(String signatureBase64) {
        return new SessionTokenSignatureValidationParams(
            RP_CHALLENGE,
            INTERACTIONS_DIGEST,
            INTERACTION_TYPE_USED,
            SCHEME_NAME,
            RP_NAME,
            new SidSignature(
                signatureBase64,
                SERVER_RANDOM,
                USER_CHALLENGE,
                SIGNATURE_ALGORITHM,
                FLOW_TYPE,
                defaultSignatureAlgorithmParameters()
            )
        );
    }
}
