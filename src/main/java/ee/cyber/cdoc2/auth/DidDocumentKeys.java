package ee.cyber.cdoc2.auth;

import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;

import ee.cyber.cdoc2.auth.exception.InvalidSshPublicKeyException;

import static ee.cyber.cdoc2.auth.UntrustedText.printable;

/**
 * The SSH keys a DID document lists for authentication. A document lists a key if and only if its
 * "authentication" contains a verification method, embedded or as a reference to an entry in "verificationMethod",
 * whose "controller" equals the DID and whose "publicKeyJwk" is an EC P-256 public key. Other verification methods
 * are not listed; those that look like keys are reported in {@link #skipped()}.
 */
public final class DidDocumentKeys {

    private static final String AUTHENTICATION = "authentication";
    private static final String VERIFICATION_METHOD = "verificationMethod";
    private static final String ID = "id";
    private static final String CONTROLLER = "controller";
    private static final String PUBLIC_KEY_JWK = "publicKeyJwk";

    private final List<ListedKey> keys;
    private final List<String> skipped;

    /**
     * A key the DID document lists.
     *
     * @param id          verification method id, as an absolute DID URL
     * @param publicKey   P-256 public key
     * @param fingerprint {@link SshPublicKeyParser#fingerprintBase64Url(byte[])} of the key's OpenSSH blob
     */
    public record ListedKey(String id, ECPublicKey publicKey, String fingerprint) {

        /**
         * @return OpenSSH public key wire blob of the key
         */
        public byte[] blob() {
            return SshPublicKeyParser.blobFromPublicKey(publicKey);
        }

        /**
         * @return fingerprint as OpenSSH shows it, "SHA256:..."
         */
        public String openSshFingerprint() {
            return SshPublicKeyParser.openSshFingerprint(blob());
        }
    }

    private DidDocumentKeys(List<ListedKey> keys, List<String> skipped) {
        this.keys = List.copyOf(keys);
        this.skipped = List.copyOf(skipped);
    }

    /**
     * Extract the listed keys from a parsed DID document. Does not check the document "id"; see
     * {@link DidWebResolver}.
     * @param did      the DID the document belongs to
     * @param document DID document as a JSON object
     * @return listed and skipped keys
     */
    public static DidDocumentKeys extract(String did, Map<String, Object> document) {
        Objects.requireNonNull(did);
        Objects.requireNonNull(document);

        Map<String, Map<String, Object>> methodsById = new HashMap<>();
        for (Object method : asList(document.get(VERIFICATION_METHOD))) {
            Map<String, Object> methodMap = asMap(method);
            if (methodMap != null && methodMap.get(ID) instanceof String id) {
                methodsById.putIfAbsent(absolute(did, id), methodMap);
            }
        }

        Map<String, ListedKey> listed = new LinkedHashMap<>(); // by fingerprint, keeps document order
        List<String> skipped = new ArrayList<>();
        for (Object entry : asList(document.get(AUTHENTICATION))) {
            Map<String, Object> method;
            String id;
            if (entry instanceof String reference) {
                id = absolute(did, reference);
                method = methodsById.get(id);
                if (method == null) {
                    skipped.add(printable(id) + ": referenced verification method not found");
                    continue;
                }
            } else {
                method = asMap(entry);
                if (method == null) {
                    continue;
                }
                id = (method.get(ID) instanceof String methodId) ? absolute(did, methodId) : "(embedded method)";
            }

            String problem = checkMethod(did, method);
            if (problem != null) {
                // problem can quote the document too: controller, crv, JWK parse errors
                skipped.add(printable(id) + ": " + printable(problem));
                continue;
            }
            ECPublicKey publicKey = toP256PublicKey(asMap(method.get(PUBLIC_KEY_JWK)));
            String fingerprint =
                SshPublicKeyParser.fingerprintBase64Url(SshPublicKeyParser.blobFromPublicKey(publicKey));
            listed.putIfAbsent(fingerprint, new ListedKey(id, publicKey, fingerprint));
        }
        return new DidDocumentKeys(new ArrayList<>(listed.values()), skipped);
    }

    /**
     * @return listed keys, in document order, without duplicates
     */
    public List<ListedKey> keys() {
        return keys;
    }

    /**
     * @return one description per verification method in "authentication" that is not listed, for example
     *     "did:web:example.org#key-2: unsupported key type OKP Ed25519"; text from the document is shortened and
     *     its control characters escaped, so an entry can be logged or printed as is
     */
    public List<String> skipped() {
        return skipped;
    }

    /**
     * @param fingerprint fingerprint as in a "ruhnu/did/" recipient identifier
     * @return the listed key with this fingerprint, if any
     */
    public Optional<ListedKey> find(String fingerprint) {
        return keys.stream().filter(k -> k.fingerprint().equals(fingerprint)).findFirst();
    }

    /** @return null if the method is a listed key, otherwise why it is not */
    private static String checkMethod(String did, Map<String, Object> method) {
        if (!did.equals(method.get(CONTROLLER))) {
            return "controlled by another DID (" + method.get(CONTROLLER) + ")";
        }
        Map<String, Object> jwkMap = asMap(method.get(PUBLIC_KEY_JWK));
        if (jwkMap == null) {
            return "unsupported key format, only publicKeyJwk is supported";
        }
        JWK jwk;
        try {
            jwk = JWK.parse(jwkMap);
        } catch (ParseException e) {
            return "invalid publicKeyJwk (" + e.getMessage() + ")";
        }
        if (jwk.isPrivate()) {
            return "publicKeyJwk contains a private key, ignored";
        }
        if (!(jwk instanceof ECKey ecKey) || !Curve.P_256.equals(ecKey.getCurve())) {
            Object crv = jwkMap.get("crv");
            return "unsupported key type " + jwk.getKeyType() + ((crv != null) ? " " + crv : "")
                + ", only EC P-256 is supported";
        }
        try {
            SshPublicKeyParser.blobFromPublicKey(ecKey.toECPublicKey());
        } catch (JOSEException | InvalidSshPublicKeyException e) {
            return "invalid P-256 key (" + e.getMessage() + ")";
        }
        return null;
    }

    private static ECPublicKey toP256PublicKey(Map<String, Object> jwkMap) {
        try {
            return ((ECKey) JWK.parse(jwkMap)).toECPublicKey();
        } catch (ParseException | JOSEException e) {
            throw new IllegalStateException("Key was checked before", e);
        }
    }

    /** Resolve a relative DID URL ("#key-1") against the DID */
    private static String absolute(String did, String id) {
        return id.startsWith("#") ? did + id : id;
    }

    private static List<?> asList(Object value) {
        return (value instanceof List<?> list) ? list : List.of();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        return (value instanceof Map<?, ?>) ? (Map<String, Object>) value : null;
    }
}
