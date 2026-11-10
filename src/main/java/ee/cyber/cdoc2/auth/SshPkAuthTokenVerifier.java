package ee.cyber.cdoc2.auth;

import java.security.interfaces.ECPublicKey;

import com.authlete.sd.SDJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import ee.cyber.cdoc2.auth.exception.InvalidSshPublicKeyException;
import ee.cyber.cdoc2.auth.exception.VerificationException;

import static ee.cyber.cdoc2.auth.TokenVerifierUtil.getClaimSet;

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
        SDJWT sdjwt = Es256AuthTokenChecks.parse(tokenBase64Url);
        SignedJWT signedJWT = Es256AuthTokenChecks.es256CredentialJwt(sdjwt);

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

        Es256AuthTokenChecks.verifySignature(signedJWT, publicKey);
        return new SshPkTokenVerificationResponse(Es256AuthTokenChecks.singleAud(claimsSet, sdjwt), iss);
    }
}
