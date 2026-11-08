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

import ee.cyber.cdoc2.auth.exception.InvalidSshPublicKeyException;
import ee.cyber.cdoc2.auth.exception.VerificationException;

import static ee.cyber.cdoc2.auth.TokenVerifierUtil.decodeSdJwtClaims;
import static ee.cyber.cdoc2.auth.TokenVerifierUtil.getClaimSet;
import static ee.cyber.cdoc2.auth.TokenVerifierUtil.getSignedJwt;
import static ee.cyber.cdoc2.auth.TokenVerifierUtil.getSingleAudArrayElementAsString;

/**
 * Verifies auth tokens (sd-jwt) signed by an SSH public key recipient. The public key is taken from the token
 * "iss" claim ("ruhnu/pk/&lt;blob&gt;"), so no certificate or trust store is needed. Caller must check that the
 * returned identifier equals the recipient of the requested share.
 */
public class SshPkAuthTokenVerifier {

    /**
     * Verifies: "typ", "alg" is ES256, "iss" is "ruhnu/pk/" P-256 key and JWS signature verifies with that key.
     * Disclosed aud array must have exactly one element.
     * @param tokenBase64Url auth token (sd-jwt)
     * @return response with the single auth nonce URI and the verified "iss" identifier
     * @throws VerificationException if verification fails
     */
    public SshPkTokenVerificationResponse verify(String tokenBase64Url) throws VerificationException {
        if (tokenBase64Url == null || tokenBase64Url.isEmpty()) {
            throw new VerificationException("Auth token missing");
        }

        SDJWT sdjwt;
        try {
            sdjwt = SDJWT.parse(tokenBase64Url);
        } catch (IllegalArgumentException e) {
            throw new VerificationException("Malformed auth token: " + e.getMessage());
        }
        SignedJWT signedJWT = getSignedJwt(sdjwt.getCredentialJwt());
        JWSHeader header = signedJWT.getHeader();

        if (header.getType() == null || !Constants.TYPE_AUTH_TOKEN.equals(header.getType().toString())) {
            throw new VerificationException("Unsupported \"typ\" " + header.getType());
        }
        if (!JWSAlgorithm.ES256.equals(header.getAlgorithm())) {
            throw new VerificationException("Unsupported \"alg\" " + header.getAlgorithm());
        }

        JWTClaimsSet claimsSet = getClaimSet(signedJWT);
        String iss = claimsSet.getIssuer();
        if (iss == null || !iss.startsWith(SshPublicKeyParser.RECIPIENT_ID_PREFIX)) {
            throw new VerificationException("Token \"iss\" is not an SSH public key identifier");
        }

        ECPublicKey publicKey;
        try {
            publicKey = SshPublicKeyParser.fromRecipientId(iss);
        } catch (InvalidSshPublicKeyException e) {
            throw new VerificationException("Invalid SSH public key in \"iss\": " + e.getMessage(), e);
        }

        try {
            if (!signedJWT.verify(new ECDSAVerifier(publicKey))) {
                throw new VerificationException("Auth token signature verification failed");
            }
        } catch (JOSEException e) {
            throw new VerificationException("Auth token signature verification failed: " + e.getMessage(), e);
        }

        Map<String, Object> decoded;
        try {
            decoded = decodeSdJwtClaims(claimsSet, sdjwt.getDisclosures());
        } catch (IllegalArgumentException e) {
            throw new VerificationException("Malformed auth token disclosures: " + e.getMessage());
        }
        String aud = getSingleAudArrayElementAsString(decoded);
        try {
            return new SshPkTokenVerificationResponse(URI.create(aud), iss);
        } catch (IllegalArgumentException e) {
            throw new VerificationException("Malformed \"aud\" " + aud);
        }
    }
}
