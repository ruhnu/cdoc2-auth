package ee.cyber.cdoc2.auth;

import java.net.URI;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.authlete.sd.SDJWT;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import ee.cyber.cdoc2.auth.SidRpv3SignatureVerifier.SessionTokenSignatureValidationParams;
import ee.cyber.cdoc2.auth.exception.VerificationException;

import static ee.cyber.cdoc2.auth.SidRpv3SignatureVerifier.createSessionTokenValidationParams;
import static ee.cyber.cdoc2.auth.TokenVerifierUtil.*;

public class SessionTokenVerifier {
    private static final Logger log = LoggerFactory.getLogger(SessionTokenVerifier.class);

    private final CertVerifier certVerifier;
    private final Clock clock;

    public SessionTokenVerifier(
        KeyStore issuersTrustStore,
        boolean enableRevocationChecks,
        Clock clock
    ) {
        this.certVerifier = new CertVerifier(issuersTrustStore, enableRevocationChecks);
        this.clock = clock;
    }

    /**
     * Verifies: JWT signature with provided jwk, certificate chain, JWT sub match with
     * certificate subject, issuance time not in the future, expiry time not in the past, correct
     * typ, SID signature (if included with token).
     * Disclosed aud array must have exactly one element.
     * On successful verification returns a response object containing: a single session nonce
     * URI, ETSI identifier parsed from the token 'sub' claim.
     *
     * @param tokenBase64Url session token in BASE64URL encoding
     * @param certBase64Url  signing certificate in BASE64URL encoding
     * @param jwtPublicKeys  List of JWK public keys that will be filtered for match with kid in
     *                       the JWT header
     * @return Response object.
     */
    public TokenVerificationResponse verify(
        String tokenBase64Url,
        String certBase64Url,
        List<JWK> jwtPublicKeys
    ) throws VerificationException {
        Objects.requireNonNull(tokenBase64Url);
        Objects.requireNonNull(certBase64Url);
        Objects.requireNonNull(jwtPublicKeys);

        X509Certificate cert = X509CertUtils.parse(Base64.getUrlDecoder().decode(certBase64Url));

        if (cert == null) {
            throw new VerificationException("Malformed certificate in x-cdoc2-session-x5c");
        }

        certVerifier.checkCertificate(cert);

        SDJWT sdjwt;
        try {
            sdjwt = SDJWT.parse(tokenBase64Url);
        } catch (IllegalArgumentException e) {
            throw new VerificationException("Malformed session token in x-cdoc2-session-token");
        }

        SignedJWT signedJWT = getSignedJwt(sdjwt.getCredentialJwt());

        JWSHeader header = signedJWT.getHeader();

        if (!Constants.TYPE_SESSION_TOKEN.equals(header.getType().toString())) {
            throw new VerificationException("Unsupported \"typ\" " + header.getType());
        }

        String kid = header.getKeyID();

        JWK jwk = jwtPublicKeys.stream().filter(key -> key.getKeyID().equals(kid))
            .findFirst().orElseThrow(() -> new VerificationException("No key found matching kid "
                + "in JWT header"));

        if (!isValidJwtSignature(signedJWT, jwk)) {
            throw new VerificationException("Invalid JWT signature");
        }

        JWTClaimsSet claimsSet = getClaimSet(signedJWT);

        validateIssuanceAndExpiry(claimsSet);
        String tokenIdentity = claimsSet.getSubject();

        EtsiIdentifier etsiIdentifier = verifyTokenIdentityAndReturnEtsiIdentifier(
            cert,
            tokenIdentity
        );

        if (isSidToken(claimsSet)) {
            SessionTokenSignatureValidationParams validationParams =
                createSessionTokenValidationParams(claimsSet);
            PublicKey certPublicKey = cert.getPublicKey();

            SidRpv3SignatureVerifier.verify(certPublicKey, validationParams);
        }

        Map<String, Object> verifiedDecodedClaims = decodeSdJwtClaims(
            claimsSet,
            sdjwt.getDisclosures()
        );

        return new TokenVerificationResponse(
            URI.create(getSingleAudArrayElementAsString(verifiedDecodedClaims)),
            etsiIdentifier
        );
    }

    private boolean isValidJwtSignature(SignedJWT signedJWT, JWK jwk) throws VerificationException {
        JWSVerifier jwsVerifier = createJwsVerifierForJwk(jwk);

        try {
            return signedJWT.verify(jwsVerifier);
        } catch (JOSEException e) {
            throw new VerificationException("JWS could not be verified");
        }
    }

    private void validateIssuanceAndExpiry(JWTClaimsSet claimsSet) throws VerificationException {
        Date expiresAt = claimsSet.getExpirationTime();
        Date issuedAt = claimsSet.getIssueTime();
        if (clock.instant().isAfter(expiresAt.toInstant())) {
            throw new VerificationException("Token has expired");
        }
        if (clock.instant().isBefore(issuedAt.toInstant())) {
            throw new VerificationException("Invalid token issuance time");
        }
    }

    private JWSVerifier createJwsVerifierForJwk(JWK jwk) throws VerificationException {
        try {
            if (KeyType.RSA == jwk.getKeyType()) {
                RSAKey rsaKey = (RSAKey) jwk;
                RSAPublicKey publicKey = rsaKey.toRSAPublicKey();
                return new RSASSAVerifier(publicKey);
            }
            if (KeyType.EC == jwk.getKeyType()) {
                ECKey ecKey = (ECKey) jwk;
                ECPublicKey publicKey = ecKey.toECPublicKey();
                return new ECDSAVerifier(publicKey);
            }
        } catch (JOSEException e) {
            throw new VerificationException("Error creating JWS verifier");
        }

        throw new VerificationException("Unsupported JWK type");
    }

    private boolean isSidToken(JWTClaimsSet claimsSet) {
        return claimsSet.getClaim("signature") != null;
    }
}
