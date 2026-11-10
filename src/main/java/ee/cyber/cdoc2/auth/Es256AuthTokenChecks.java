package ee.cyber.cdoc2.auth;

import java.net.URI;
import java.security.interfaces.ECPublicKey;
import java.util.Map;

import com.authlete.sd.SDJWT;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import ee.cyber.cdoc2.auth.exception.VerificationException;

import static ee.cyber.cdoc2.auth.TokenVerifierUtil.decodeSdJwtClaims;
import static ee.cyber.cdoc2.auth.TokenVerifierUtil.getSignedJwt;
import static ee.cyber.cdoc2.auth.TokenVerifierUtil.getSingleAudArrayElementAsString;

/**
 * Checks shared by the verifiers of ES256 auth tokens signed by SSH keys ({@link SshPkAuthTokenVerifier},
 * {@link DidAuthTokenVerifier}).
 */
final class Es256AuthTokenChecks {

    private Es256AuthTokenChecks() {
        // utility class
    }

    /** Parse the SD-JWT */
    static SDJWT parse(String tokenBase64Url) throws VerificationException {
        if (tokenBase64Url == null || tokenBase64Url.isEmpty()) {
            throw new VerificationException("Auth token missing");
        }
        try {
            return SDJWT.parse(tokenBase64Url);
        } catch (IllegalArgumentException e) {
            throw new VerificationException("Malformed auth token: " + e.getMessage());
        }
    }

    /** Parse the credential JWT and check "typ" and that "alg" is ES256 */
    static SignedJWT es256CredentialJwt(SDJWT sdjwt) throws VerificationException {
        SignedJWT signedJWT = getSignedJwt(sdjwt.getCredentialJwt());
        JWSHeader header = signedJWT.getHeader();

        if (header.getType() == null || !Constants.TYPE_AUTH_TOKEN.equals(header.getType().toString())) {
            throw new VerificationException("Unsupported \"typ\" " + header.getType());
        }
        if (!JWSAlgorithm.ES256.equals(header.getAlgorithm())) {
            throw new VerificationException("Unsupported \"alg\" " + header.getAlgorithm());
        }
        return signedJWT;
    }

    /** Verify the JWS signature with the public key */
    static void verifySignature(SignedJWT signedJWT, ECPublicKey publicKey) throws VerificationException {
        try {
            if (!signedJWT.verify(new ECDSAVerifier(publicKey))) {
                throw new VerificationException("Auth token signature verification failed");
            }
        } catch (JOSEException e) {
            throw new VerificationException("Auth token signature verification failed: " + e.getMessage(), e);
        }
    }

    /** The single disclosed "aud" array element, the share URL with nonce */
    static URI singleAud(JWTClaimsSet claimsSet, SDJWT sdjwt) throws VerificationException {
        Map<String, Object> decoded;
        try {
            decoded = decodeSdJwtClaims(claimsSet, sdjwt.getDisclosures());
        } catch (IllegalArgumentException e) {
            throw new VerificationException("Malformed auth token disclosures: " + e.getMessage());
        }
        String aud = getSingleAudArrayElementAsString(decoded);
        try {
            return URI.create(aud);
        } catch (IllegalArgumentException e) {
            throw new VerificationException("Malformed \"aud\" " + aud);
        }
    }
}
