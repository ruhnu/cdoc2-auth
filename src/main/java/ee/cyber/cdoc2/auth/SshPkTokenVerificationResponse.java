package ee.cyber.cdoc2.auth;

import java.net.URI;

/**
 * Result of successful {@link SshPkAuthTokenVerifier#verify(String)}.
 * @param nonceUri single disclosed "aud" element (share URL with nonce)
 * @param identifier verified token issuer, "ruhnu/pk/&lt;blob&gt;" recipient identifier
 */
public record SshPkTokenVerificationResponse(
    URI nonceUri,
    String identifier
) {
}
