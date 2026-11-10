package ee.cyber.cdoc2.auth;

import java.util.Objects;

/**
 * Result of resolving a did:web DID with {@link DidWebResolver}.
 */
public sealed interface DidResolution permits DidResolution.Found, DidResolution.NotFound, DidResolution.Unavailable {

    /**
     * The DID document was retrieved and belongs to the DID.
     * @param keys keys the document lists
     */
    record Found(DidDocumentKeys keys) implements DidResolution {
        public Found {
            Objects.requireNonNull(keys);
        }
    }

    /**
     * The DID is not found: the host answered, but not with a DID document for this DID (404, 410, any other
     * 4xx or 3xx, a body that is not a JSON object, a document for another DID, a body that is too large), or the
     * host is not allowed. Retrying will not help.
     * @param reason human-readable reason
     */
    record NotFound(String reason) implements DidResolution {
        public NotFound {
            Objects.requireNonNull(reason);
        }
    }

    /**
     * The DID host is unavailable: connection failure, timeout, TLS failure, or a 5xx or 429 response. Retrying
     * later may help.
     * @param reason human-readable reason
     */
    record Unavailable(String reason) implements DidResolution {
        public Unavailable {
            Objects.requireNonNull(reason);
        }
    }
}
