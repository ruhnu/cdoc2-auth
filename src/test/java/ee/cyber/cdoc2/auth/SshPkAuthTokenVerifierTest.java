package ee.cyber.cdoc2.auth;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.BigIntegerUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import ee.cyber.cdoc2.auth.exception.VerificationException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SshPkAuthTokenVerifierTest {

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

    private final SshPkAuthTokenVerifier verifier = new SshPkAuthTokenVerifier();

    @BeforeAll
    static void init() throws Exception {
        keyPair = generateP256KeyPair();
        otherKeyPair = generateP256KeyPair();
        recipientId = recipientId((ECPublicKey) keyPair.getPublic());
        otherRecipientId = recipientId((ECPublicKey) otherKeyPair.getPublic());
    }

    @Test
    void shouldVerifyValidToken() throws Exception {
        AuthTokenCreator creator = signedCreator(recipientId, keyPair, SHARE_1, SHARE_2);

        SshPkTokenVerificationResponse response = verifier.verify(creator.createTokenForShareId(SHARE_ID_2));

        assertEquals(recipientId, response.identifier());
        assertEquals(URI.create(SHARE_2.toURL().toString()), response.nonceUri());
    }

    /**
     * Token signed through a real ssh-agent (SSH "string r, string s" signature re-encoded to JWS r||s).
     * Produced by cdoc2-ssh/jws_probe: python3 ssh_jws.py --iss-from-key --aud '&lt;url&gt;'
     */
    @Test
    void shouldVerifySshAgentSignedToken() throws Exception {
        String token = readResource("ssh-agent-token.sdjwt");
        String publicKeyLine = readResource("ssh-agent-token-key.pub");

        SshPkTokenVerificationResponse response = verifier.verify(token);

        assertEquals(SshPublicKeyParser.recipientIdFromOpenSshLine(publicKeyLine), response.identifier());
        assertEquals(URI.create("https://localhost:8443/key-shares/9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3"
            + "?nonce=59b314d4815f21f73a0b9168cecbd5773cc694b6"), response.nonceUri());
        ShareAccessData accessData = ShareAccessData.fromURL(response.nonceUri().toURL());
        assertEquals(SHARE_ID_1, accessData.getShareId());

        // and the signature really is bound to the key
        assertVerificationFails(new SdJwtWrapper(token).replaceValue("iss", recipientId),
            "signature verification failed");
    }

    @Test
    void shouldRejectTokenSignedByDifferentKey() throws Exception {
        String token = signedCreator(recipientId, otherKeyPair, SHARE_1).createToken(0);

        assertVerificationFails(token, "signature verification failed");
    }

    @Test
    void shouldRejectIssWithoutPrefix() throws Exception {
        String etsiToken = signedCreator("etsi/PNOEE-48010010101", keyPair, SHARE_1).createToken(0);
        assertVerificationFails(etsiToken, "not an SSH public key identifier");

        String privateToken = signedCreator(recipientId.replace("ruhnu/pk/", "private/pk/"), keyPair, SHARE_1)
            .createToken(0);
        assertVerificationFails(privateToken, "not an SSH public key identifier");
    }

    @Test
    void shouldRejectOtherAlgorithms() throws Exception {
        String token = signedCreator(recipientId, keyPair, SHARE_1).createToken(0);
        SdJwtWrapper wrapper = new SdJwtWrapper(token);

        assertVerificationFails(wrapper.replaceValue("alg", "RS256"), "Unsupported \"alg\"");
        assertVerificationFails(wrapper.replaceValue("alg", "EdDSA"), "Unsupported \"alg\"");
        assertVerificationFails(wrapper.replaceValue("alg", "ES384"), "Unsupported \"alg\"");
        // alg "none" is not a JWS header for nimbus, rejected when parsing
        assertThrows(VerificationException.class, () -> verifier.verify(wrapper.replaceValue("alg", "none")));
    }

    @Test
    void shouldRejectWrongTyp() throws Exception {
        String token = signedCreator(recipientId, keyPair, SHARE_1).createToken(0);

        assertVerificationFails(new SdJwtWrapper(token).replaceValue("typ", "JWT"), "Unsupported \"typ\"");
    }

    @Test
    void shouldRejectNonP256KeyInIss() throws Exception {
        String ed25519Id = "ruhnu/pk/" + SshPublicKeyParserTest.ED25519_LINE.split(" ")[1];
        String token = signedCreator(ed25519Id, keyPair, SHARE_1).createToken(0);

        assertVerificationFails(token, "ssh-ed25519");
    }

    @Test
    void shouldRejectTamperedPayload() throws Exception {
        String token = signedCreator(recipientId, keyPair, SHARE_1).createToken(0);
        SdJwtWrapper wrapper = new SdJwtWrapper(token);

        // claim to be another key holder
        assertVerificationFails(wrapper.replaceValue("iss", otherRecipientId), "signature verification failed");
        assertVerificationFails(wrapper.replaceValue("_sd_alg", "sha-512"), "signature verification failed");
    }

    @Test
    void shouldIgnoreDisclosureNotCoveredBySignature() throws Exception {
        String token = signedCreator(recipientId, keyPair, SHARE_1).createToken(0);
        SDJWT original = SDJWT.parse(token);
        // replace aud disclosures with unsigned ones pointing to another share
        Disclosure element = new Disclosure(SHARE_2.toURL().toString());
        Disclosure aud = new Disclosure("aud", List.of(element.toArrayElement()));
        String forged = new SDJWT(original.getCredentialJwt(), List.of(aud, element)).toString();

        assertVerificationFails(forged, "aud claim missing");
    }

    @Test
    void shouldRejectZeroAudElements() throws Exception {
        String token = signedCreator(recipientId, keyPair, SHARE_1).createToken(0);
        SDJWT original = SDJWT.parse(token);
        // keep only "aud" array disclosure, drop array element disclosure
        Disclosure audOnly = original.getDisclosures().stream()
            .filter(d -> "aud".equals(d.getClaimName()))
            .findFirst().orElseThrow();
        String noElements = new SDJWT(original.getCredentialJwt(), List.of(audOnly)).toString();

        assertVerificationFails(noElements, "aud array is empty");
    }

    @Test
    void shouldRejectTwoAudElements() throws Exception {
        AuthTokenCreator creator = signedCreator(recipientId, keyPair, SHARE_1, SHARE_2);
        SDJWT token1 = SDJWT.parse(creator.createToken(0));
        SDJWT token2 = SDJWT.parse(creator.createToken(1));

        List<Disclosure> disclosures = new ArrayList<>(token1.getDisclosures());
        token2.getDisclosures().stream()
            .filter(d -> d.getClaimName() == null)
            .forEach(disclosures::add);
        String both = new SDJWT(token1.getCredentialJwt(), disclosures).toString();

        assertVerificationFails(both, "More than one element");
    }

    @Test
    void shouldRejectMissingOrGarbageToken() {
        assertThrows(VerificationException.class, () -> verifier.verify(null));
        assertThrows(VerificationException.class, () -> verifier.verify(""));
        assertThrows(VerificationException.class, () -> verifier.verify("garbage"));
        assertThrows(VerificationException.class, () -> verifier.verify("a.b.c~"));
    }

    private static String readResource(String name) throws Exception {
        try (var in = SshPkAuthTokenVerifierTest.class.getClassLoader().getResourceAsStream(name)) {
            if (in == null) {
                throw new IllegalStateException("Test resource not found: " + name);
            }
            return new String(in.readAllBytes(), StandardCharsets.US_ASCII).strip();
        }
    }

    private void assertVerificationFails(String token, String expectedMessagePart) {
        VerificationException ex = assertThrows(VerificationException.class, () -> verifier.verify(token));
        assertTrue(ex.getMessage().contains(expectedMessagePart), "Actual message: " + ex.getMessage());
    }

    static AuthTokenCreator signedCreator(String issuer, KeyPair signingKey, ShareAccessData... shares)
        throws Exception {
        AuthTokenCreator creator = AuthTokenCreator.builder()
            .withIssuer(issuer)
            .withSharesAccessData(List.of(shares))
            .build();
        JWSSigner signer = new ECDSASigner((ECPrivateKey) signingKey.getPrivate());
        creator.sign(signer);
        return creator;
    }

    static KeyPair generateP256KeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    /** "ruhnu/pk/" identifier for EC P-256 public key, OpenSSH wire format */
    static String recipientId(ECPublicKey publicKey) {
        byte[] q = new byte[65];
        q[0] = 0x04;
        byte[] x = BigIntegerUtils.toBytesUnsigned(publicKey.getW().getAffineX());
        byte[] y = BigIntegerUtils.toBytesUnsigned(publicKey.getW().getAffineY());
        // left-pad coordinates to 32 bytes
        System.arraycopy(x, 0, q, 1 + 32 - x.length, x.length);
        System.arraycopy(y, 0, q, 33 + 32 - y.length, y.length);
        byte[] blob = SshPublicKeyParserTest.sshBlob(
            "ecdsa-sha2-nistp256".getBytes(StandardCharsets.US_ASCII),
            "nistp256".getBytes(StandardCharsets.US_ASCII),
            q);
        return SshPublicKeyParser.recipientIdFromBlob(blob);
    }
}
