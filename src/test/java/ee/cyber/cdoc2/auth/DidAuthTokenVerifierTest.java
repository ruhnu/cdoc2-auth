package ee.cyber.cdoc2.auth;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.authlete.sd.SDObjectBuilder;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import ee.cyber.cdoc2.auth.exception.VerificationException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DidAuthTokenVerifierTest {

    private static final String DID = "did:web:example.org:p:alice";
    private static final String SHARE_ID_1 = "9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3";
    private static final String SHARE_ID_2 = "5BAE4603-C33C-4425-B301-125F2ACF9B1E";
    private static final ShareAccessData SHARE_1 =
        new ShareAccessData("https://localhost:8443", SHARE_ID_1, "59b314d4815f21f73a0b9168cecbd5773cc694b6");
    private static final ShareAccessData SHARE_2 =
        new ShareAccessData("https://localhost:8442", SHARE_ID_2, "9d23660840b427f405009d970d269770417bc769");

    private static KeyPair keyPair;
    private static KeyPair otherKeyPair;
    private static String recipientId;
    private static String otherRecipientId;

    private final DidAuthTokenVerifier verifier = new DidAuthTokenVerifier();

    @BeforeAll
    static void init() throws Exception {
        keyPair = SshPkAuthTokenVerifierTest.generateP256KeyPair();
        otherKeyPair = SshPkAuthTokenVerifierTest.generateP256KeyPair();
        recipientId = didRecipientId(keyPair);
        otherRecipientId = didRecipientId(otherKeyPair);
    }

    @Test
    void shouldVerifyValidToken() throws Exception {
        AuthTokenCreator creator = creator(recipientId, jwk(keyPair), keyPair, SHARE_1, SHARE_2);

        SshPkTokenVerificationResponse response = verifier.verify(creator.createTokenForShareId(SHARE_ID_2));

        assertEquals(recipientId, response.identifier());
        assertEquals(URI.create(SHARE_2.toURL().toString()), response.nonceUri());
    }

    @Test
    void shouldRejectTokenWithoutJwkHeader() throws Exception {
        String token = SshPkAuthTokenVerifierTest.signedCreator(recipientId, keyPair, SHARE_1).createToken(0);

        assertVerificationFails(token, "no \"jwk\" header");
    }

    @Test
    void shouldRejectNonP256HeaderKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair p384 = generator.generateKeyPair();
        JWK p384Jwk = new ECKey.Builder(Curve.P_384, (ECPublicKey) p384.getPublic()).build();
        assertVerificationFails(creator(recipientId, p384Jwk, keyPair, SHARE_1).createToken(0),
            "not an EC P-256 key");

        RSAKey rsaJwk = new RSAKeyGenerator(2048).generate().toPublicJWK();
        assertVerificationFails(creator(recipientId, rsaJwk, keyPair, SHARE_1).createToken(0),
            "not an EC P-256 key");
    }

    @Test
    void shouldRejectHeaderWithPrivateKey() throws Exception {
        ECKey privateJwk = new ECKey.Builder(Curve.P_256, (ECPublicKey) keyPair.getPublic())
            .privateKey((ECPrivateKey) keyPair.getPrivate())
            .build();
        String token = creator(recipientId, jwk(keyPair), keyPair, SHARE_1).createToken(0);
        // re-sign the token with a header that carries the private key too (nimbus refuses to build one)
        SDJWT sdjwt = SDJWT.parse(token);
        String payload = sdjwt.getCredentialJwt().split("\\.")[1];
        String headerJson = "{\"jwk\":" + privateJwk.toJSONString() + ",\"typ\":\"" + Constants.TYPE_AUTH_TOKEN
            + "\",\"alg\":\"ES256\"}";
        String header = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        Base64URL signature = new ECDSASigner(privateJwk).sign(new JWSHeader(JWSAlgorithm.ES256),
            (header + "." + payload).getBytes(StandardCharsets.US_ASCII));
        String forged = new SDJWT(header + "." + payload + "." + signature, sdjwt.getDisclosures()).toString();

        assertThrows(VerificationException.class, () -> verifier.verify(forged));
    }

    @Test
    void shouldRejectHeaderKeyThatDoesNotMatchFingerprint() throws Exception {
        // signed by the key in the header, but "iss" pins another key
        String token = creator(otherRecipientId, jwk(keyPair), keyPair, SHARE_1).createToken(0);

        assertVerificationFails(token, "does not match the fingerprint in \"iss\"");
    }

    @Test
    void shouldRejectTokenSignedByDifferentKey() throws Exception {
        // header key matches "iss", but the signature was made with another private key
        String token = creator(recipientId, jwk(keyPair), otherKeyPair, SHARE_1).createToken(0);

        assertVerificationFails(token, "signature verification failed");
    }

    @Test
    void shouldRejectIssThatIsNotADidIdentifier() throws Exception {
        String pkId = SshPkAuthTokenVerifierTest.recipientId((ECPublicKey) keyPair.getPublic());
        assertVerificationFails(creator(pkId, jwk(keyPair), keyPair, SHARE_1).createToken(0),
            "not a DID recipient identifier");

        String fingerprint = recipientId.substring(recipientId.lastIndexOf('/') + 1);
        String didKeyId = "ruhnu/did/did:key:zDnaeXyz/hash/" + fingerprint;
        assertVerificationFails(creator(didKeyId, jwk(keyPair), keyPair, SHARE_1).createToken(0),
            "Invalid DID recipient identifier");
    }

    @Test
    void shouldRejectOtherAlgorithmsAndTyp() throws Exception {
        String token = creator(recipientId, jwk(keyPair), keyPair, SHARE_1).createToken(0);
        SdJwtWrapper wrapper = new SdJwtWrapper(token);

        assertVerificationFails(wrapper.replaceValue("alg", "RS256"), "Unsupported \"alg\"");
        assertVerificationFails(wrapper.replaceValue("alg", "ES384"), "Unsupported \"alg\"");
        assertThrows(VerificationException.class, () -> verifier.verify(wrapper.replaceValue("alg", "none")));
        assertVerificationFails(wrapper.replaceValue("typ", "JWT"), "Unsupported \"typ\"");
    }

    @Test
    void shouldRejectTamperedPayload() throws Exception {
        String token = creator(recipientId, jwk(keyPair), keyPair, SHARE_1).createToken(0);

        assertVerificationFails(new SdJwtWrapper(token).replaceValue("_sd_alg", "sha-512"),
            "signature verification failed");
    }

    @Test
    void shouldRequireExactlyOneAudElement() throws Exception {
        AuthTokenCreator creator = creator(recipientId, jwk(keyPair), keyPair, SHARE_1, SHARE_2);
        SDJWT token1 = SDJWT.parse(creator.createToken(0));
        SDJWT token2 = SDJWT.parse(creator.createToken(1));

        Disclosure audOnly = token1.getDisclosures().stream()
            .filter(d -> "aud".equals(d.getClaimName()))
            .findFirst().orElseThrow();
        assertVerificationFails(new SDJWT(token1.getCredentialJwt(), List.of(audOnly)).toString(),
            "aud array is empty");

        List<Disclosure> both = new ArrayList<>(token1.getDisclosures());
        token2.getDisclosures().stream().filter(d -> d.getClaimName() == null).forEach(both::add);
        assertVerificationFails(new SDJWT(token1.getCredentialJwt(), both).toString(), "More than one element");
    }

    @Test
    void shouldRejectAudElementThatIsNotAString() throws Exception {
        assertVerificationFails(tokenWithAud(recipientId, jwk(keyPair), keyPair, Collections.singletonList(null)),
            "not a string");
        assertVerificationFails(tokenWithAud(recipientId, jwk(keyPair), keyPair, List.of(Map.of("a", "b"))),
            "not a string");
    }

    @Test
    void shouldRejectMissingOrGarbageToken() {
        assertThrows(VerificationException.class, () -> verifier.verify(null));
        assertThrows(VerificationException.class, () -> verifier.verify(""));
        assertThrows(VerificationException.class, () -> verifier.verify("garbage"));
    }

    /** "ruhnu/did/" identifier for the key pair's public key */
    static String didRecipientId(KeyPair keys) {
        return DidRecipientId.of(DID, SshPublicKeyParser.blobFromPublicKey((ECPublicKey) keys.getPublic()))
            .toString();
    }

    static ECKey jwk(KeyPair keys) {
        return new ECKey.Builder(Curve.P_256, (ECPublicKey) keys.getPublic()).build();
    }

    static AuthTokenCreator creator(String issuer, JWK headerJwk, KeyPair signingKey, ShareAccessData... shares)
        throws Exception {
        AuthTokenCreator creator = AuthTokenCreator.builder()
            .withIssuer(issuer)
            .withHeaderJwk(headerJwk)
            .withSharesAccessData(List.of(shares))
            .build();
        creator.sign(new ECDSASigner((ECPrivateKey) signingKey.getPrivate()));
        return creator;
    }

    /**
     * Token signed by the key pair whose "aud" disclosure holds the given elements as they are, not as array element
     * disclosures: AuthTokenCreator cannot create such a token.
     */
    static String tokenWithAud(String issuer, JWK headerJwk, KeyPair signingKey, List<?> aud) throws Exception {
        Disclosure audDisclosure = new Disclosure("aud", aud);
        SDObjectBuilder builder = new SDObjectBuilder();
        builder.putSDClaim(audDisclosure);
        Map<String, Object> claims = builder.build(true);
        claims.put("iss", issuer);
        JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(new JOSEObjectType(Constants.TYPE_AUTH_TOKEN));
        if (headerJwk != null) {
            header.jwk(headerJwk);
        }
        SignedJWT jwt = new SignedJWT(header.build(), JWTClaimsSet.parse(claims));
        jwt.sign(new ECDSASigner((ECPrivateKey) signingKey.getPrivate()));
        return new SDJWT(jwt.serialize(), List.of(audDisclosure)).toString();
    }

    private void assertVerificationFails(String token, String expectedMessagePart) {
        VerificationException ex = assertThrows(VerificationException.class, () -> verifier.verify(token));
        assertTrue(ex.getMessage().contains(expectedMessagePart), "Actual message: " + ex.getMessage());
    }
}
