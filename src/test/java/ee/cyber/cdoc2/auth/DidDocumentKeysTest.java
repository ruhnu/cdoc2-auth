package ee.cyber.cdoc2.auth;

import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DidDocumentKeysTest {

    private static final String DID = "did:web:example.org:p:alice";

    // P-256 key of SshPublicKeyParserTest.P256_BLOB, whose ssh-keygen -l fingerprint is
    // SHA256:ILaep1/NfsYICEypSkuVoSj0tD6P+nvxnABaRhsg+uc
    private static final ECPublicKey P256_KEY = SshPublicKeyParser.fromRecipientId(
        SshPublicKeyParserTest.P256_RECIPIENT_ID);
    private static final String P256_FINGERPRINT = "ILaep1_NfsYICEypSkuVoSj0tD6P-nvxnABaRhsg-uc";

    private static final String ED25519_JWK =
        "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"tZwRQY3W6qoMejnrXWBnDfS3etTTlD1jrOo63wIx8PI\"}";

    @Test
    void shouldListKeyReferencedFromAuthentication() throws Exception {
        String doc = document(
            "[" + method(DID + "#key-1", DID, jwk(P256_KEY)) + "]",
            "[\"" + DID + "#key-1\"]");

        DidDocumentKeys keys = extract(doc);

        assertEquals(1, keys.keys().size());
        DidDocumentKeys.ListedKey key = keys.keys().get(0);
        assertEquals(DID + "#key-1", key.id());
        assertEquals(P256_FINGERPRINT, key.fingerprint());
        assertEquals("SHA256:ILaep1/NfsYICEypSkuVoSj0tD6P+nvxnABaRhsg+uc", key.openSshFingerprint());
        assertEquals(P256_KEY.getW(), key.publicKey().getW());
        assertTrue(keys.find(P256_FINGERPRINT).isPresent());
        assertTrue(keys.skipped().isEmpty());
    }

    @Test
    void shouldResolveRelativeReferences() throws Exception {
        String relativeRef = document("[" + method(DID + "#key-1", DID, jwk(P256_KEY)) + "]", "[\"#key-1\"]");
        assertEquals(DID + "#key-1", extract(relativeRef).keys().get(0).id());

        String relativeId = document("[" + method("#key-1", DID, jwk(P256_KEY)) + "]", "[\"" + DID + "#key-1\"]");
        assertEquals(P256_FINGERPRINT, extract(relativeId).keys().get(0).fingerprint());
    }

    @Test
    void shouldListKeyEmbeddedInAuthentication() throws Exception {
        String doc = document("[]", "[" + method(DID + "#key-1", DID, jwk(P256_KEY)) + "]");

        assertEquals(List.of(P256_FINGERPRINT), fingerprints(extract(doc)));
    }

    @Test
    void shouldNotListKeyNotUsedForAuthentication() throws Exception {
        String onlyVerificationMethod = document("[" + method(DID + "#key-1", DID, jwk(P256_KEY)) + "]", "[]");
        assertTrue(extract(onlyVerificationMethod).keys().isEmpty());

        String assertionMethod = "{\"id\":\"" + DID + "\",\"verificationMethod\":["
            + method(DID + "#key-1", DID, jwk(P256_KEY)) + "],\"assertionMethod\":[\"#key-1\"]}";
        assertTrue(extract(assertionMethod).keys().isEmpty());

        String noAuthentication = "{\"id\":\"" + DID + "\"}";
        assertTrue(extract(noAuthentication).keys().isEmpty());
    }

    @Test
    void shouldNotListKeyControlledByAnotherDid() throws Exception {
        String doc = document("[]", "[" + method(DID + "#key-1", "did:web:example.org:p:bob", jwk(P256_KEY)) + "]");

        DidDocumentKeys keys = extract(doc);

        assertTrue(keys.keys().isEmpty());
        assertSkipped(keys, "controlled by another DID");
    }

    @Test
    void shouldIgnoreUnsupportedKeyTypes() throws Exception {
        String doc = document(
            "[" + method(DID + "#ed", DID, ED25519_JWK) + "," + method(DID + "#p256", DID, jwk(P256_KEY)) + ","
                + method(DID + "#p384", DID, jwk(p384Key())) + "]",
            "[\"#ed\",\"#p256\",\"#p384\"]");

        DidDocumentKeys keys = extract(doc);

        assertEquals(List.of(P256_FINGERPRINT), fingerprints(keys));
        assertSkipped(keys, DID + "#ed: unsupported key type OKP Ed25519");
        assertSkipped(keys, DID + "#p384: unsupported key type EC P-384");
    }

    @Test
    void shouldIgnoreJwkWithPrivateKey() throws Exception {
        String privateJwk = jwk(P256_KEY).replace("}", ",\"d\":\"" + "A".repeat(43) + "\"}");
        String doc = document("[]", "[" + method(DID + "#key-1", DID, privateJwk) + "]");

        DidDocumentKeys keys = extract(doc);

        assertTrue(keys.keys().isEmpty());
        assertSkipped(keys, "private key");
    }

    @Test
    void shouldReportOtherKeyFormatsAndMissingReferences() throws Exception {
        String multibase = "{\"id\":\"" + DID + "#mb\",\"type\":\"Multikey\",\"controller\":\"" + DID + "\","
            + "\"publicKeyMultibase\":\"zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169\"}";
        String doc = document("[" + multibase + "]", "[\"#mb\",\"#missing\"]");

        DidDocumentKeys keys = extract(doc);

        assertTrue(keys.keys().isEmpty());
        assertSkipped(keys, DID + "#mb: unsupported key format");
        assertSkipped(keys, DID + "#missing: referenced verification method not found");
    }

    @Test
    void shouldListKeyOnce() throws Exception {
        String doc = document(
            "[" + method(DID + "#key-1", DID, jwk(P256_KEY)) + "]",
            "[\"#key-1\",\"" + DID + "#key-1\"," + method(DID + "#copy", DID, jwk(P256_KEY)) + "]");

        assertEquals(List.of(P256_FINGERPRINT), fingerprints(extract(doc)));
    }

    @Test
    void shouldIgnoreMalformedEntries() throws Exception {
        String doc = "{\"id\":\"" + DID + "\",\"verificationMethod\":\"not a list\",\"authentication\":[1,null,"
            + method(DID + "#key-1", DID, "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"AAAA\",\"y\":\"AAAA\"}") + "]}";

        DidDocumentKeys keys = extract(doc);

        assertTrue(keys.keys().isEmpty());
        assertSkipped(keys, DID + "#key-1: invalid");
    }

    @Test
    void shouldEscapeDocumentTextInSkippedEntries() throws Exception {
        // JSON escapes: a line break that would start a forged log line, an ANSI sequence that hides terminal output
        String forged = "did:web:evil\\n2026-11-11 INFO forged\\u001b[8m";
        String doc = document("[]", "[\"#a\\nb\"," + method(DID + "#key-1", forged, jwk(P256_KEY)) + "]");

        DidDocumentKeys keys = extract(doc);

        assertEquals(2, keys.skipped().size(), keys.skipped().toString());
        for (String entry : keys.skipped()) {
            assertTrue(entry.chars().noneMatch(Character::isISOControl), entry);
        }
        assertSkipped(keys, DID + "#a\\u000ab: referenced verification method not found");
        assertSkipped(keys, "controlled by another DID (did:web:evil\\u000a2026-11-11 INFO forged\\u001b[8m)");
    }

    @Test
    void shouldShortenLongDocumentTextInSkippedEntries() throws Exception {
        String doc = document("[]", "[\"#" + "k".repeat(1000) + "\"]");

        String entry = extract(doc).skipped().get(0);

        assertTrue(entry.startsWith((DID + "#" + "k".repeat(UntrustedText.MAX_SHOWN)).substring(0,
            UntrustedText.MAX_SHOWN) + "...: referenced"), entry);
    }

    static String document(String verificationMethods, String authentication) {
        return "{\"@context\":[\"https://www.w3.org/ns/did/v1\"],\"id\":\"" + DID + "\","
            + "\"verificationMethod\":" + verificationMethods + ",\"authentication\":" + authentication + "}";
    }

    static String method(String id, String controller, String jwk) {
        return "{\"id\":\"" + id + "\",\"type\":\"JsonWebKey2020\",\"controller\":\"" + controller + "\","
            + "\"publicKeyJwk\":" + jwk + "}";
    }

    static String jwk(ECPublicKey key) {
        Curve curve = Curve.forECParameterSpec(key.getParams());
        return new ECKey.Builder(curve, key).build().toJSONString();
    }

    private static ECPublicKey p384Key() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        return (ECPublicKey) generator.generateKeyPair().getPublic();
    }

    private static DidDocumentKeys extract(String json) throws Exception {
        Map<String, Object> document = JSONObjectUtils.parse(json);
        return DidDocumentKeys.extract(DID, document);
    }

    private static List<String> fingerprints(DidDocumentKeys keys) {
        return keys.keys().stream().map(DidDocumentKeys.ListedKey::fingerprint).toList();
    }

    private static void assertSkipped(DidDocumentKeys keys, String expectedPart) {
        assertTrue(keys.skipped().stream().anyMatch(s -> s.contains(expectedPart)),
            "expected skipped entry containing \"" + expectedPart + "\", got " + keys.skipped());
    }
}
