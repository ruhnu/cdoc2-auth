package ee.cyber.cdoc2.auth;

import java.security.interfaces.ECPublicKey;

import com.authlete.sd.SDJWT;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import ee.cyber.cdoc2.auth.exception.InvalidDidRecipientException;
import ee.cyber.cdoc2.auth.exception.InvalidSshPublicKeyException;
import ee.cyber.cdoc2.auth.exception.VerificationException;

import static ee.cyber.cdoc2.auth.TokenVerifierUtil.getClaimSet;

/**
 * Verifies auth tokens (sd-jwt) of "ruhnu/did/&lt;did&gt;/hash/&lt;fingerprint&gt;" DID recipients. The identifier
 * holds only the fingerprint of the SSH key, so the token carries the public key in its JWS "jwk" header, and the
 * key's fingerprint must equal the one in "iss". This verifier does not contact the DID host: the caller must check
 * that the returned identifier equals the recipient of the requested share, and then that the DID document still
 * lists the key ({@link DidWebResolver}).
 */
public class DidAuthTokenVerifier {

    /**
     * Verifies: "typ", "alg" is ES256, "iss" is a valid "ruhnu/did/" identifier, the "jwk" header is a public
     * P-256 key whose fingerprint equals the one in "iss", and the JWS signature verifies with that key.
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
        if (!DidRecipientId.isDidRecipientId(iss)) {
            throw new VerificationException("Token \"iss\" is not a DID recipient identifier");
        }
        DidRecipientId recipientId;
        try {
            recipientId = DidRecipientId.parse(iss);
        } catch (InvalidDidRecipientException e) {
            throw new VerificationException("Invalid DID recipient identifier in \"iss\": " + e.getMessage(), e);
        }

        ECPublicKey publicKey = headerKey(signedJWT.getHeader().getJWK());
        byte[] blob;
        try {
            blob = SshPublicKeyParser.blobFromPublicKey(publicKey);
        } catch (InvalidSshPublicKeyException e) {
            throw new VerificationException("Invalid \"jwk\" header key: " + e.getMessage(), e);
        }
        if (!recipientId.matches(blob)) {
            throw new VerificationException("\"jwk\" header key does not match the fingerprint in \"iss\"");
        }

        Es256AuthTokenChecks.verifySignature(signedJWT, publicKey);
        return new SshPkTokenVerificationResponse(Es256AuthTokenChecks.singleAud(claimsSet, sdjwt), iss);
    }

    private static ECPublicKey headerKey(JWK jwk) throws VerificationException {
        if (jwk == null) {
            throw new VerificationException("Auth token has no \"jwk\" header");
        }
        if (jwk.isPrivate()) {
            throw new VerificationException("\"jwk\" header must not contain a private key");
        }
        if (!(jwk instanceof ECKey ecKey) || !Curve.P_256.equals(ecKey.getCurve())) {
            throw new VerificationException("\"jwk\" header is not an EC P-256 key");
        }
        try {
            return ecKey.toECPublicKey();
        } catch (JOSEException e) {
            throw new VerificationException("Invalid \"jwk\" header key: " + e.getMessage(), e);
        }
    }
}
