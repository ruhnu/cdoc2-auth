package ee.cyber.cdoc2.auth;

import java.net.URI;

/**
 * Result of successful {@link SshPkAuthTokenVerifier#verify(String)} and {@link DidAuthTokenVerifier#verify(String)}.
 * @param nonceUri single disclosed "aud" element (share URL with nonce)
 * @param identifier verified token issuer: a "ruhnu/pk/&lt;blob&gt;" or
 *     "ruhnu/did/&lt;did&gt;/hash/&lt;fingerprint&gt;" recipient identifier
 */
public record SshPkTokenVerificationResponse(
    URI nonceUri,
    String identifier
) {
}
