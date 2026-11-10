package ee.cyber.cdoc2.auth;

import java.net.URI;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

import ee.cyber.cdoc2.auth.exception.InvalidDidRecipientException;
import ee.cyber.cdoc2.auth.exception.InvalidDidRecipientException.Reason;

/**
 * A parsed did:web DID, for example "did:web:example.org:p:alice" or "did:web:example.org%3A8443:p:alice".
 * The host must be a domain name (the did:web method does not allow IP addresses), an optional port is given
 * percent-encoded as "%3A&lt;port&gt;", and path segments are separated by ":".
 *
 * @param did          the DID string, exactly as given
 * @param host         host name, as written in the DID
 * @param port         port, 443 when the DID has none
 * @param pathSegments path segments, empty for a DID without a path
 */
public record DidWeb(String did, String host, int port, List<String> pathSegments) {

    /** did:web DID prefix */
    public static final String PREFIX = "did:web:";

    /** Default HTTPS port */
    public static final int DEFAULT_PORT = 443;

    /**
     * Longest DID that still fits into a "ruhnu/did/&lt;did&gt;/hash/&lt;43 character fingerprint&gt;" recipient
     * identifier of at most {@link DidRecipientId#MAX_LENGTH} characters.
     */
    public static final int MAX_LENGTH = DidRecipientId.MAX_LENGTH - DidRecipientId.PREFIX.length()
        - DidRecipientId.HASH_SEPARATOR.length() - DidRecipientId.FINGERPRINT_LENGTH;

    private static final String DID_SCHEME = "did:";
    private static final String ENCODED_PORT_SEPARATOR = "%3A";
    private static final int MAX_PORT = 65535;
    private static final int MAX_HOST_LENGTH = 253;

    private static final Pattern DNS_LABEL = Pattern.compile("[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?");
    private static final Pattern NUMERIC = Pattern.compile("[0-9]+");
    private static final Pattern PORT = Pattern.compile("[0-9]{1,5}");
    // DID syntax idchar: ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
    private static final Pattern SEGMENT = Pattern.compile("([A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+");

    public DidWeb {
        Objects.requireNonNull(did);
        Objects.requireNonNull(host);
        pathSegments = List.copyOf(pathSegments);
    }

    /**
     * Parse a did:web DID.
     * @param did DID string
     * @return parsed DID
     * @throws InvalidDidRecipientException if the string is not a did:web DID ({@link Reason#UNSUPPORTED_METHOD}
     *     for another DID method, {@link Reason#TOO_LONG} if longer than {@link #MAX_LENGTH},
     *     {@link Reason#INVALID_DID} otherwise)
     */
    public static DidWeb parse(String did) {
        Objects.requireNonNull(did);
        if (!did.startsWith(PREFIX)) {
            if (did.startsWith(DID_SCHEME) && did.indexOf(':', DID_SCHEME.length()) > 0) {
                throw new InvalidDidRecipientException(Reason.UNSUPPORTED_METHOD,
                    "Only did:web DIDs are supported, got " + abbreviate(did));
            }
            throw new InvalidDidRecipientException(Reason.INVALID_DID, abbreviate(did) + " is not a did:web DID");
        }
        if (did.length() > MAX_LENGTH) {
            throw new InvalidDidRecipientException(Reason.TOO_LONG,
                "DID is too long: " + did.length() + " characters, at most " + MAX_LENGTH + " are supported");
        }

        String[] parts = did.substring(PREFIX.length()).split(":", -1);
        String hostAndPort = parts[0];
        String host = hostAndPort;
        int port = DEFAULT_PORT;
        int portSeparator = hostAndPort.indexOf(ENCODED_PORT_SEPARATOR);
        if (portSeparator >= 0) {
            host = hostAndPort.substring(0, portSeparator);
            port = parsePort(did, hostAndPort.substring(portSeparator + ENCODED_PORT_SEPARATOR.length()));
        }
        checkHost(did, host);

        List<String> segments = List.of(parts).subList(1, parts.length);
        for (String segment : segments) {
            if (!SEGMENT.matcher(segment).matches()) {
                throw invalid(did, "path segment \"" + segment + "\" is empty or has characters not allowed in a DID");
            }
        }
        return new DidWeb(did, host, port, segments);
    }

    /**
     * URL of the DID document, as defined by the did:web method:
     * "https://&lt;host&gt;[:&lt;port&gt;]/&lt;path&gt;/did.json", or
     * "https://&lt;host&gt;[:&lt;port&gt;]/.well-known/did.json" for a DID without a path.
     * @return DID document URL
     */
    public URI documentUri() {
        StringBuilder url = new StringBuilder("https://").append(host);
        if (port != DEFAULT_PORT) {
            url.append(':').append(port);
        }
        if (pathSegments.isEmpty()) {
            url.append("/.well-known");
        } else {
            for (String segment : pathSegments) {
                url.append('/').append(segment);
            }
        }
        return URI.create(url.append("/did.json").toString());
    }

    @Override
    public String toString() {
        return did;
    }

    private static int parsePort(String did, String port) {
        if (!PORT.matcher(port).matches()) {
            throw invalid(did, "port \"" + port + "\" is not a number");
        }
        int value = Integer.parseInt(port);
        if (value < 1 || value > MAX_PORT) {
            throw invalid(did, "port " + value + " is out of range");
        }
        return value;
    }

    private static void checkHost(String did, String host) {
        if (host.isEmpty() || host.length() > MAX_HOST_LENGTH) {
            throw invalid(did, "host name is missing or too long");
        }
        String[] labels = host.split("\\.", -1);
        for (String label : labels) {
            if (!DNS_LABEL.matcher(label).matches()) {
                throw invalid(did, "host must be a domain name, not \"" + host + "\"");
            }
        }
        // top-level domains are never numeric, so this rejects IPv4 addresses such as 192.0.2.1
        if (NUMERIC.matcher(labels[labels.length - 1]).matches()) {
            throw invalid(did, "host must be a domain name, not an IP address");
        }
    }

    private static InvalidDidRecipientException invalid(String did, String detail) {
        return new InvalidDidRecipientException(Reason.INVALID_DID,
            abbreviate(did) + " is not a valid did:web DID: " + detail);
    }

    private static String abbreviate(String value) {
        final int maxShown = 80;
        return (value.length() <= maxShown) ? value : value.substring(0, maxShown) + "...";
    }
}
