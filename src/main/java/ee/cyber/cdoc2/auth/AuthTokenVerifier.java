package ee.cyber.cdoc2.auth;

import java.net.URI;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.authlete.sd.SDJWT;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import ee.cyber.cdoc2.auth.exception.VerificationException;

import static ee.cyber.cdoc2.auth.Constants.RP_V3_SIGNATURE_ALGORITHM_NAME;
import static ee.cyber.cdoc2.auth.TokenVerifierUtil.*;

public class AuthTokenVerifier {
    private static final Logger log = LoggerFactory.getLogger(AuthTokenVerifier.class);

    private final CertVerifier certVerifier;

    public AuthTokenVerifier(
        KeyStore issuersTrustStore,
        boolean enableRevocationChecks
    ) {
        this.certVerifier = new CertVerifier(issuersTrustStore, enableRevocationChecks);
    }

    /**
     * Verifies: JWT signature, using the additional provided signature parameters for SID RPv3
     * signatures, certificate chain, JWT iss match with certificate subject, correct typ, token
     * identity format.
     * Disclosed aud array must have exactly one element.
     * On successful verification returns a response object containing: a single auth nonce
     * URI, ETSI identifier parsed from the token 'iss' claim.
     *
     * @param tokenBase64Url                 session token in BASE64URL encoding
     * @param certBase64Url                  signing certificate in BASE64URL encoding
     * @param sidAuthTokenVerificationParams parameters for SID RpV3 signature verification.
     *                                       {@code null} when verifying MID signature.
     * @param rpCountersignatureParams       RP countersignature params. can be null
     *                                       for SID Rpv3-signed tokens
     * @return Response object
     * @throws VerificationException Verification exception with message
     */
    public TokenVerificationResponse verify(
        String tokenBase64Url,
        String certBase64Url,
        SidAuthTokenVerificationParams sidAuthTokenVerificationParams,
        RpHttpSignatureVerifier.RpHttpSignatureParams rpCountersignatureParams
    ) throws VerificationException {
        validateInputParams(
            tokenBase64Url,
            certBase64Url,
            sidAuthTokenVerificationParams,
            rpCountersignatureParams
        );

        X509Certificate cert = X509CertUtils.parse(Base64.getUrlDecoder().decode(certBase64Url));

        certVerifier.checkCertificate(cert);

        SDJWT sdjwt = SDJWT.parse(tokenBase64Url);
        SignedJWT signedJWT = getSignedJwt(sdjwt.getCredentialJwt());
        JWSHeader header = signedJWT.getHeader();

        if (!Constants.TYPE_AUTH_TOKEN.equals(header.getType().toString())) {
            throw new VerificationException("Unsupported \"typ\" " + header.getType());
        }

        JWTClaimsSet claimsSet = getClaimSet(signedJWT);
        String tokenIdentity = claimsSet.getIssuer();

        if (!tokenIdentity.startsWith(EtsiIdentifier.PREFIX)) {
            throw new VerificationException("Only identifiers starting with " + EtsiIdentifier.PREFIX
                + " are supported.  \"iss\" \"" + tokenIdentity + "\"");
        }

        EtsiIdentifier etsiIdentifier = verifyTokenIdentityAndReturnEtsiIdentifier(
            cert,
            tokenIdentity
        );

        if (sidAuthTokenVerificationParams != null) {
            if (!RP_V3_SIGNATURE_ALGORITHM_NAME.equals(header.getAlgorithm().getName())) {
                throw new VerificationException("Unsupported \"alg\" " + header.getAlgorithm().getName());
            }

            SidRpv3SignatureVerifier.AuthTokenSignatureValidationParams validationParams =
                SidRpv3SignatureVerifier.createAuthTokenValidationParams(
                    sidAuthTokenVerificationParams.sidSignatureParamsJsonBase64Url
                );

            SidRpv3SignatureVerifier.verify(
                signedJWT.getSignature().toString(),
                cert.getPublicKey(),
                validationParams,
                sidAuthTokenVerificationParams.rpName,
                sidAuthTokenVerificationParams.schemeName,
                createRpChallenge(signedJWT)
            );
        } else {
            if (!List.of(
                JWSAlgorithm.ES256,
                JWSAlgorithm.RS256
            ).contains(header.getAlgorithm())) {
                throw new VerificationException("Unsupported \"alg\" " + header.getAlgorithm().getName());
            }

            MidSignatureVerifier.verify(signedJWT, cert);
        }

        if (rpCountersignatureParams != null) {
            verifyRpSignedHashMatchesToken(signedJWT, rpCountersignatureParams);
            RpHttpSignatureVerifier.verify(rpCountersignatureParams);
        }

        return createResponse(claimsSet, sdjwt, etsiIdentifier);
    }

    private TokenVerificationResponse createResponse(
        JWTClaimsSet claimsSet, SDJWT sdjwt,
        EtsiIdentifier etsiIdentifier
    ) throws VerificationException {
        Map<String, Object> verifiedDecodedClaims = decodeSdJwtClaims(
            claimsSet,
            sdjwt.getDisclosures()
        );

        return new TokenVerificationResponse(
            URI.create(getSingleAudArrayElementAsString(verifiedDecodedClaims)),
            etsiIdentifier
        );
    }

    private void validateInputParams(
        String tokenBase64Url,
        String certBase64Url,
        SidAuthTokenVerificationParams sidAuthTokenVerificationParams,
        RpHttpSignatureVerifier.RpHttpSignatureParams rpCountersignatureParams
    ) throws VerificationException {
        Objects.requireNonNull(tokenBase64Url);
        Objects.requireNonNull(certBase64Url);
        if (sidAuthTokenVerificationParams == null && rpCountersignatureParams == null) {
            throw new VerificationException("One of SID RPv3 or RP countersignature verification "
                + "params must be provided");
        }
    }

    private String createRpChallenge(SignedJWT signedJWT) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] rpChallengeBytes = digest.digest(signedJWT.getSigningInput());
            return Base64.getEncoder().encodeToString(rpChallengeBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Ensures the RP counter-signature is actually about this token: the RP is expected to
     * counter-sign SHA-256 of the raw JWS signature bytes of this token (SID RPv3 or MID).
     * Without this check, any validly-signed, still-fresh RP countersignature captured from a
     * different session could be paired with this token and pass.
     */
    private void verifyRpSignedHashMatchesToken(
        SignedJWT signedJWT,
        RpHttpSignatureVerifier.RpHttpSignatureParams rpCountersignatureParams
    ) throws VerificationException {
        if (!computeSignatureHash(signedJWT).equals(rpCountersignatureParams.rpSignedHash())) {
            throw new VerificationException("RP countersignature \"x-rp-signed-hash\" does not "
                + "match this token's signature");
        }
    }

    private String computeSignatureHash(SignedJWT signedJWT) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(signedJWT.getSignature().decode());
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public record SidAuthTokenVerificationParams(
        String sidSignatureParamsJsonBase64Url,
        String rpName,
        String schemeName
    ) {
    }
}
