package ee.cyber.cdoc2.auth;

import java.net.URI;
import java.util.List;

import org.junit.jupiter.api.Test;

import ee.cyber.cdoc2.auth.exception.InvalidDidRecipientException;
import ee.cyber.cdoc2.auth.exception.InvalidDidRecipientException.Reason;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DidWebTest {

    @Test
    void shouldMapDidWithPath() {
        DidWeb did = DidWeb.parse("did:web:example.org:p:alice");

        assertEquals("example.org", did.host());
        assertEquals(443, did.port());
        assertEquals(List.of("p", "alice"), did.pathSegments());
        assertEquals(URI.create("https://example.org/p/alice/did.json"), did.documentUri());
        assertEquals("did:web:example.org:p:alice", did.toString());
    }

    @Test
    void shouldMapDidWithoutPath() {
        DidWeb did = DidWeb.parse("did:web:example.org");

        assertEquals(URI.create("https://example.org/.well-known/did.json"), did.documentUri());
    }

    @Test
    void shouldMapDidWithPort() {
        DidWeb did = DidWeb.parse("did:web:example.org%3A8443:p:alice");

        assertEquals("example.org", did.host());
        assertEquals(8443, did.port());
        assertEquals(URI.create("https://example.org:8443/p/alice/did.json"), did.documentUri());
    }

    @Test
    void shouldKeepPercentEncodedPathSegments() {
        DidWeb did = DidWeb.parse("did:web:example.org:u:j%C3%BCri");

        assertEquals(URI.create("https://example.org/u/j%C3%BCri/did.json"), did.documentUri());
    }

    @Test
    void shouldAcceptSingleLabelHost() {
        assertEquals("localhost", DidWeb.parse("did:web:localhost%3A8444:p:alice").host());
    }

    @Test
    void shouldRejectOtherDidMethods() {
        var ex = assertThrows(InvalidDidRecipientException.class, () -> DidWeb.parse("did:key:zDnaeXyz"));

        assertEquals(Reason.UNSUPPORTED_METHOD, ex.getReason());
        assertTrue(ex.getMessage().contains("Only did:web DIDs are supported"), ex.getMessage());
    }

    @Test
    void shouldRejectIpAddresses() {
        var ex = assertThrows(InvalidDidRecipientException.class, () -> DidWeb.parse("did:web:192.0.2.1"));
        assertEquals(Reason.INVALID_DID, ex.getReason());
        assertTrue(ex.getMessage().contains("is not a valid did:web DID"), ex.getMessage());
        assertTrue(ex.getMessage().contains("IP address"), ex.getMessage());

        assertInvalid("did:web:192.0.2.1%3A8443:p:alice");
        assertInvalid("did:web:[::1]");
        assertInvalid("did:web:%5B%3A%3A1%5D");
    }

    @Test
    void shouldRejectMalformedDids() {
        assertInvalid("example.org");
        assertInvalid("did:web:");
        assertInvalid("did:web:example.org::alice");
        assertInvalid("did:web:example.org:p:");
        assertInvalid("did:web:example.org:p:al ice");
        assertInvalid("did:web:example.org:p/alice");
        assertInvalid("did:web:exa_mple.org");
        assertInvalid("did:web:-example.org");
        assertInvalid("did:web:example..org");
        assertInvalid("did:web:example.org%3A");
        assertInvalid("did:web:example.org%3Aabc");
        assertInvalid("did:web:example.org%3A0");
        assertInvalid("did:web:example.org%3A70000");
        assertInvalid("did:web:example.org:p:%zz");
    }

    @Test
    void shouldRejectTooLongDid() {
        String prefix = "did:web:example.org:p:";
        String longest = prefix + "a".repeat(DidWeb.MAX_LENGTH - prefix.length());
        assertEquals(196, longest.length());
        DidWeb.parse(longest);

        var ex = assertThrows(InvalidDidRecipientException.class, () -> DidWeb.parse(longest + "a"));
        assertEquals(Reason.TOO_LONG, ex.getReason());
        assertTrue(ex.getMessage().contains("DID is too long"), ex.getMessage());
    }

    private static void assertInvalid(String did) {
        var ex = assertThrows(InvalidDidRecipientException.class, () -> DidWeb.parse(did), did);
        assertEquals(Reason.INVALID_DID, ex.getReason(), did);
    }
}
