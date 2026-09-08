package ee.cyber.cdoc2.auth;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.text.ParseException;
import java.util.Base64;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;

import ee.cyber.cdoc2.auth.exception.VerificationException;

public final class SidRpv3SignatureVerifier {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private SidRpv3SignatureVerifier() {
        // utility class
    }

    static void verify(
        PublicKey publicKey,
        SessionTokenSignatureValidationParams params
    ) throws VerificationException {
        try {
            verify(
                Base64.getDecoder().decode(params.signature.value),
                publicKey,
                TokenSignatureValidationParams.fromSessionTokenValidationParams(params)
            );
        } catch (InvalidAlgorithmParameterException | InvalidKeyException | SignatureException
                 | NoSuchAlgorithmException e) {
            throw new VerificationException(e.getMessage());
        }
    }

    static void verify(
        String signatureValueBase64Url,
        PublicKey publicKey,
        AuthTokenSignatureValidationParams params,
        String rpName,
        String schemeName,
        String rpChallenge
    ) throws VerificationException {
        try {
            verify(Base64.getUrlDecoder().decode(signatureValueBase64Url),
                publicKey,
                TokenSignatureValidationParams.fromAuthTokenValidationParams(
                    params,
                    rpName,
                    schemeName,
                    rpChallenge
                )
            );
        } catch (InvalidAlgorithmParameterException | InvalidKeyException | SignatureException
                 | NoSuchAlgorithmException e) {
            throw new VerificationException(e.getMessage());
        }
    }

    private static void verify(
        byte[] signatureBytes,
        PublicKey publicKey,
        TokenSignatureValidationParams params
    ) throws InvalidAlgorithmParameterException, InvalidKeyException,
        SignatureException, NoSuchAlgorithmException, VerificationException {

        String separator = "|";
        String schemeName = params.schemeName;
        String signatureProtocol = "ACSP_V2";
        String relyingPartyNameBase64 = Base64.getEncoder()
            .encodeToString(params.rpName.getBytes(StandardCharsets.UTF_8));
        String brokeredRpNameBase64 = "";
        String initialCallbackUrl = "";
        String flowType = params.signatureParams.flowType;

        String[] payloadParts = {
            schemeName,
            signatureProtocol,
            params.signatureParams.serverRandom,
            params.rpChallenge,
            params.signatureParams.userChallenge,
            relyingPartyNameBase64,
            brokeredRpNameBase64,
            params.interactionsDigest,
            params.interactionTypeUsed,
            initialCallbackUrl,
            flowType
        };

        String acspV2Payload = String.join(separator, payloadParts);
        byte[] acspV2PayloadBytes = acspV2Payload.getBytes(StandardCharsets.UTF_8);

        PSSParameterSpec pssSpec = getPssParameterSpec(params);

        Signature verifier = Signature.getInstance(
            params.signatureParams.signatureAlgorithm()
        );
        verifier.setParameter(pssSpec);
        verifier.initVerify(publicKey);
        verifier.update(acspV2PayloadBytes);

        if (verifier.verify(signatureBytes)) {
            return;
        }

        throw new VerificationException("SID RpV3 signature verification failure");
    }

    private static PSSParameterSpec getPssParameterSpec(TokenSignatureValidationParams params) {
        SignatureAlgorithmParameters signatureAlgorithmParams =
            params.signatureParams.signatureAlgorithmParameters;

        String maskGenDigestAlg =
            signatureAlgorithmParams.maskGenAlgorithm()
                .parameters().hashAlgorithm();

        return new PSSParameterSpec(
            signatureAlgorithmParams.hashAlgorithm(),
            "MGF1",
            new MGF1ParameterSpec(maskGenDigestAlg),
            signatureAlgorithmParams.saltLength(),
            PSSParameterSpec.TRAILER_FIELD_BC
        );
    }

    static SessionTokenSignatureValidationParams createSessionTokenValidationParams(
        JWTClaimsSet claimsSet
    ) throws VerificationException {
        try {
            SidRpv3SignatureVerifier.SidSignature sidSignature = OBJECT_MAPPER.convertValue(
                claimsSet.getClaim("signature"),
                SidRpv3SignatureVerifier.SidSignature.class
            );

            String rpChallengeBase64 = claimsSet.getClaimAsString("rpChallenge");
            String interactionsDigestBase64 = claimsSet.getClaimAsString("interactionsDigest");
            String interactionTypeUsed = claimsSet.getClaimAsString("interactionTypeUsed");
            String schemeName = claimsSet.getClaimAsString("schemeName");
            String rpName = claimsSet.getClaimAsString("rpName");

            return new SessionTokenSignatureValidationParams(
                rpChallengeBase64,
                interactionsDigestBase64,
                interactionTypeUsed,
                schemeName,
                rpName,
                sidSignature
            );
        } catch (ParseException e) {
            throw new VerificationException(e.getMessage());
        }
    }

    static SessionTokenSignatureValidationParams createSessionTokenValidationParams(
        String signatureValidationParamsJsonBase64Url
    ) throws VerificationException {
        String signatureValidationParamsJson = new String(
            Base64.getUrlDecoder().decode(signatureValidationParamsJsonBase64Url),
            StandardCharsets.UTF_8);

        try {
            return OBJECT_MAPPER.readValue(
                signatureValidationParamsJson,
                SessionTokenSignatureValidationParams.class
            );
        } catch (JsonProcessingException e) {
            throw new VerificationException(e.getMessage());
        }
    }

    public static AuthTokenSignatureValidationParams createAuthTokenValidationParams(
        String signatureValidationParamsJsonBase64Url
    ) throws VerificationException {
        String signatureValidationParamsJson = new String(
            Base64.getUrlDecoder().decode(signatureValidationParamsJsonBase64Url),
            StandardCharsets.UTF_8);

        try {
            return OBJECT_MAPPER.readValue(
                signatureValidationParamsJson,
                AuthTokenSignatureValidationParams.class
            );
        } catch (JsonProcessingException e) {
            throw new VerificationException(e.getMessage());
        }
    }

    public record SessionTokenSignatureValidationParams(
        String rpChallenge,
        String interactionsDigest,
        String interactionTypeUsed,
        String schemeName,
        String rpName,
        SidSignature signature
    ) {
    }

    public record SidSignature(
        String value,
        String serverRandom,
        String userChallenge,
        String signatureAlgorithm,
        String flowType,
        SignatureAlgorithmParameters signatureAlgorithmParameters
    ) {
    }

    public record AuthTokenSignatureValidationParams(
        String interactionsDigest,
        String interactionTypeUsed,
        SidSignatureParams signature
    ) {
    }

    public record SidSignatureParams(
        String serverRandom,
        String userChallenge,
        String signatureAlgorithm,
        String flowType,
        SignatureAlgorithmParameters signatureAlgorithmParameters
    ) {
    }

    public record SignatureAlgorithmParameters(
        String hashAlgorithm,
        MaskGenAlgorithm maskGenAlgorithm,
        Integer saltLength,
        String trailerField
    ) {
    }

    public record MaskGenAlgorithm(
        String algorithm,
        Parameters parameters
    ) {

        public record Parameters(
            String hashAlgorithm
        ) {
        }
    }

    private record TokenSignatureValidationParams(
        String rpChallenge,
        String interactionsDigest,
        String interactionTypeUsed,
        String schemeName,
        String rpName,
        SidSignatureParams signatureParams
    ) {
        static TokenSignatureValidationParams fromSessionTokenValidationParams(
            SessionTokenSignatureValidationParams params) {
            return new TokenSignatureValidationParams(
                params.rpChallenge,
                params.interactionsDigest,
                params.interactionTypeUsed,
                params.schemeName,
                params.rpName,
                new SidSignatureParams(
                    params.signature.serverRandom,
                    params.signature.userChallenge,
                    params.signature.signatureAlgorithm,
                    params.signature.flowType,
                    params.signature.signatureAlgorithmParameters
                )
            );
        }

        static TokenSignatureValidationParams fromAuthTokenValidationParams(
            AuthTokenSignatureValidationParams params, String rpName, String schemeName,
            String rpChallenge) {
            return new TokenSignatureValidationParams(
                rpChallenge,
                params.interactionsDigest,
                params.interactionTypeUsed,
                schemeName,
                rpName,
                params.signature
            );
        }
    }
}
