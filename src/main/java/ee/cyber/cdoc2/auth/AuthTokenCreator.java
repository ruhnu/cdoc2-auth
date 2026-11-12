package ee.cyber.cdoc2.auth;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.authlete.sd.SDObjectBuilder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import ee.cyber.cdoc2.auth.exception.MalformedAuthUrlException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Create cdoc2 auth-token (sd-jwt)
 */
public final class AuthTokenCreator {
    private static final Logger log = LoggerFactory.getLogger(AuthTokenCreator.class);

    private static final Logger tokens_log = LoggerFactory.getLogger("tokens");

    private final String issuer;

    private final ShareAccessData[] shareAccessData;

    // public key put into the JWS "jwk" header, null for no "jwk" header
    private final JWK headerJwk;

    private final List<Disclosure> audDisclosureArray;

    private final Disclosure disclosedShareAccessData;

    private SignedJWT signedJWT = null; // initialized by sign()

    private AuthTokenCreator(String issuer, ShareAccessData[] sharesData, JWK headerJwk) {
        this.issuer = issuer;
        this.shareAccessData = sharesData;
        this.headerJwk = headerJwk;

        this.audDisclosureArray = initDisclosureArray();  //generate salts
        this.disclosedShareAccessData = genDisclosedAudience(); //generate salt
    }

    /**
     * Convert shareAccessData claims to array of Disclosure objects. Each value is array of ["generated_salt", {}]
     */
    private List<Disclosure> initDisclosureArray() {

        return Arrays.stream(shareAccessData)
            .map(audValue -> {
                    try {
                        return new Disclosure(audValue.toURL());
                    } catch (MalformedURLException e) {
                        throw new MalformedAuthUrlException(e);
                    }
                } // generated salt, claimValue
            )
            .toList();
    }

    /**
     * Creates array of disclosure digests from keyShareAccessData
     * <p>
     * <code>
     * [
     *     "k-4EaZpAg-17QnMfOwMbOw",
     *     "aud",
     *     [
     *         {
     *             "...": "EEs_5efYCyYSch0ze2JgUlWEiIXsq6bsZ8QqAvyjeuM"
     *         },
     *         {
     *             "...": "F_-6nsDCOCoJcNKfa87VgAMTTs87KF3zYysmJgC1wrE"
     *         }
     *     ]
     * ]
     * </code>
     * @return Disclosure for "aud" list
     */
    private Disclosure genDisclosedAudience() {
        return new Disclosure("aud",
            audDisclosureArray.stream()
                .map(Disclosure::toArrayElement
                ).toList()
        );
    }

    private Disclosure getDisclosedAudience() {
        return this.disclosedShareAccessData;
    }

    /**
     * Create payload for JWT
     * <p>
     * <code>
     *     {"iss":"etsi/PNOEE-48010010101","_sd":["1STjFlBH6jmF270Ify2StXnMzZ2TDrIKJX5By65gv-4"],"_sd_alg":"sha-256"}
     * </code>
     *
     * @return JWTClaimsSet, where "aud" list has been replaced with digests of Disclosures
     * @throws ParseException if JWT claims parse has failed
     */
    private JWTClaimsSet createPayload() throws ParseException {
        // Create an SDObjectBuilder instance to prepare the payload part of
        // a credential JWT. "sha-256" is used as a hash algorithm to compute
        // digest values of Disclosures.
        SDObjectBuilder builder = new SDObjectBuilder();

        // Put the digest value of the Disclosure.
        // will create claim  "_sd": ["y7ePxU9QuqYLz8ITcxcDAA4T43VDzF9_x2Z3z0-xxls"] that is calculated from
        // disclosed "aud" array, see getDisclosedShareAccessData()

        log.debug("disclosedShareAccessData: {}", getDisclosedAudience().getJson());
        builder.putSDClaim(getDisclosedAudience());

        // Create a Map instance that represents the payload part of a
        // credential JWT. The 'claims' map contains the "_sd" array.
        // The size of the array is 1.
        Map<String, Object> claims = builder.build(true);

        JWTClaimsSet regularClaims = new JWTClaimsSet.Builder()
            .issuer(Objects.requireNonNull(issuer, "issuer not set"))//iss
            .build();

        claims.putAll(regularClaims.toJSONObject());

        // Prepare the payload part of a credential JWT.
        return JWTClaimsSet.parse(claims);
    }

    /**
     * Create payload part of JWT and sign it with JWSSigner and JWK private key.
     * Currently, RSASigner and ECDSASigner are supported.
     * @param signer jwsSigner jwsSigner.supportedJWSAlgorithms() must return exactly 1 algorithm
     * @throws JOSEException if JWT signing has failed
     * @throws ParseException if JWT claims parse has failed
     */
    public void sign(JWSSigner signer)
        throws ParseException, JOSEException {

        Objects.requireNonNull(signer);

        if (signer.supportedJWSAlgorithms().size() != 1) {
            throw new JOSEException("Expecting signer with exactly 1 supported JWS algorithm: "
                + signer.supportedJWSAlgorithms());
        }
        JWSAlgorithm jwsAlgorithm = signer.supportedJWSAlgorithms().iterator().next();
        sign(signer, jwsAlgorithm);
    }

    /**
     * Create payload part of JWT and sign it with JWSSigner and JWK private key.
     * Currently, RSASigner and ECDSASigner are supported.
     * @param signer jwsSigner
     * @param jwsAlgorithm jws algorithm that will be used for signing. Must be supported by signer
     * @throws JOSEException if JWT signing has failed
     * @throws ParseException if JWT claims parse has failed
     */
    public void sign(JWSSigner signer, JWSAlgorithm jwsAlgorithm)
        throws JOSEException, ParseException {
        //for SID certificate is available after successful authentication
        //(that is actually signing with different key - PIN1)
        //for SID use jwk (RSA), for MID jwk (ECDSA)

        JWSHeader.Builder headerBuilder =
            new JWSHeader.Builder(jwsAlgorithm)
                // signature padding is supported
                .type(new JOSEObjectType(Constants.TYPE_AUTH_TOKEN));
        if (headerJwk != null) {
            headerBuilder.jwk(headerJwk);
        }
        JWSHeader header = headerBuilder.build();

        // Create a credential JWT. (not signed yet)
        SignedJWT jwt = new SignedJWT(header, createPayload());

        // Let the signer sign the credential JWT.
        jwt.sign(signer);

        this.signedJWT = jwt;
    }

    /**
     * Create token (sdjwt)
     * @param index shareAccessData element index from signed shareAccessData
     * @return token as SDJWT
     */
    public String createToken(int index) {
        if (this.signedJWT == null) {
            throw new IllegalStateException("jwt not signed, can't create tokent (did you call sign()?)");
        }

        if ((index < 0) || (index > audDisclosureArray.size())) {
            throw new IllegalArgumentException("Invalid index " + index);
        }

        SDJWT sdjwt = new SDJWT(this.signedJWT.serialize(),
            List.of(getDisclosedAudience(), audDisclosureArray.get(index)));

        if (tokens_log.isDebugEnabled()) {
            try {
                tokens_log.debug("Claims: {}", signedJWT.getJWTClaimsSet());
            } catch (ParseException e) {
                throw new IllegalStateException("Should not happen as jwt is not parsed");
            }
            tokens_log.debug("Disclosures: {}",
                sdjwt.getDisclosures().stream().map(d -> d.digest() + ": " + d.getJson()).toList());
        }

        return sdjwt.toString();
    }

    /**
     * Create token (sdjwt) for share id
     * @param shareId shareId from signed shareAccessData
     * @return token as SDJWT
     * @throws IllegalArgumentException if shareId was not part signed payload
     */
    public String createTokenForShareId(String shareId) {
        Objects.requireNonNull(shareId);

        for (int i = 0; i < shareAccessData.length; i++) {
            if (shareId.equals(shareAccessData[i].getShareId())) {
                return createToken(i);
            }
        }

        throw new IllegalArgumentException(shareId + "not found");
    }

    public static class Builder {
        EtsiIdentifier etsiIdentifier;
        // used instead of etsiIdentifier for non-ETSI issuers, see withIssuer()
        String issuer;
        Collection<ShareAccessData> keyShares = new LinkedList<>();
        JWK headerJwk;

        public Builder withEtsiIdentifier(EtsiIdentifier identifier) {
            this.etsiIdentifier = identifier;
            this.issuer = null;
            return this;
        }

        /**
         * Set token issuer ("iss") for recipients that are not identified by ETSI identifier,
         * for example "ruhnu/pk/&lt;blob&gt;" SSH public key recipients. Replaces value set by
         * {@link #withEtsiIdentifier(EtsiIdentifier)}.
         * @param recipientId recipient identifier, used as "iss" value
         * @return this builder
         */
        public Builder withIssuer(String recipientId) {
            this.issuer = Objects.requireNonNull(recipientId);
            this.etsiIdentifier = null;
            return this;
        }

        /**
         * Put the signing key's public key into the JWS "jwk" header (RFC 7515 section 4.1.3), as needed for
         * "ruhnu/did/" recipients, whose identifier holds only the key's fingerprint. Only the public members are
         * used, so a private JWK can be given.
         * @param signingKey JWK of the signing key
         * @return this builder
         */
        public Builder withHeaderJwk(JWK signingKey) {
            this.headerJwk = Objects.requireNonNull(signingKey).toPublicJWK();
            return this;
        }

        /**
         * Add share access data
         * @param share to add to data to be signed
         * @return
         */
        public Builder withShareAccessData(ShareAccessData share) {
            this.keyShares.add(share);
            return this;
        }

        public Builder withSharesAccessData(List<ShareAccessData> audList) {

            this.keyShares.addAll(audList);
            return this;
        }

        public AuthTokenCreator build() {
            String iss = (this.issuer != null) ? this.issuer
                : (this.etsiIdentifier != null) ? this.etsiIdentifier.toString() : null;
            return new AuthTokenCreator(iss, keyShares.toArray(new ShareAccessData[0]), headerJwk);
        }
    }

    public static Builder builder() {
        return new Builder();
    }
}
