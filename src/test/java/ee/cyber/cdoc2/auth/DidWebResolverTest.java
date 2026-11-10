package ee.cyber.cdoc2.auth;

import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ee.cyber.cdoc2.auth.exception.InvalidDidRecipientException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DidWebResolverTest {

    private static final Duration DEADLINE = Duration.ofMillis(1500);
    private static final String DOC_PATH = "/p/alice/did.json";
    private static final String P256_FINGERPRINT = "ILaep1_NfsYICEypSkuVoSj0tD6P-nvxnABaRhsg-uc";

    private TestHttpsServer host;
    private String did;
    private DidWebResolver resolver;

    @BeforeEach
    void startHost() throws Exception {
        host = new TestHttpsServer();
        did = "did:web:localhost%3A" + host.port() + ":p:alice";
        resolver = resolver(64 * 1024, DidHostPolicy.ALLOW_ALL);
    }

    @AfterEach
    void stopHost() {
        host.close();
    }

    @Test
    void shouldResolveDidWithPath() {
        host.onJson(DOC_PATH, documentFor(did));

        DidResolution.Found found = assertInstanceOf(DidResolution.Found.class, resolver.resolve(did));

        assertEquals(P256_FINGERPRINT, found.keys().keys().get(0).fingerprint());
        assertEquals(1, host.requestCount(DOC_PATH));
    }

    @Test
    void shouldResolveDidWithoutPath() {
        String rootDid = "did:web:localhost%3A" + host.port();
        host.onJson("/.well-known/did.json", documentFor(rootDid));

        assertInstanceOf(DidResolution.Found.class, resolver.resolve(rootDid));
    }

    @Test
    void missingDocumentIsNotFound() {
        assertNotFound(resolver.resolve(did), "HTTP 404");

        host.on(DOC_PATH, exchange -> TestHttpsServer.send(exchange, 410, ""));
        assertNotFound(resolver.resolve(did), "HTTP 410");

        host.on(DOC_PATH, exchange -> TestHttpsServer.send(exchange, 403, ""));
        assertNotFound(resolver.resolve(did), "HTTP 403");
    }

    @Test
    void redirectIsNotFollowed() {
        host.onJson("/elsewhere/did.json", documentFor(did));
        host.on(DOC_PATH, exchange -> {
            exchange.getResponseHeaders().add("Location", "https://localhost:" + host.port() + "/elsewhere/did.json");
            TestHttpsServer.send(exchange, 301, "");
        });

        assertNotFound(resolver.resolve(did), "HTTP 301");
        assertEquals(0, host.requestCount("/elsewhere/did.json"));
    }

    @Test
    void documentForAnotherDidIsNotFound() {
        host.onJson(DOC_PATH, documentFor("did:web:localhost%3A" + host.port() + ":p:bob"));

        assertNotFound(resolver.resolve(did), "another DID");
    }

    @Test
    void bodyThatIsNotAJsonObjectIsNotFound() {
        host.onJson(DOC_PATH, "<html>not json</html>");
        assertNotFound(resolver.resolve(did), "not a JSON object");

        host.onJson(DOC_PATH, "[1, 2]");
        assertNotFound(resolver.resolve(did), "not a JSON object");
    }

    @Test
    void oversizedBodyIsNotFound() {
        DidWebResolver small = resolver(1024, DidHostPolicy.ALLOW_ALL);
        String padded = documentFor(did).replace("{\"@context\"",
            "{\"padding\":\"" + "x".repeat(2000) + "\",\"@context\"");
        host.onJson(DOC_PATH, padded);

        assertNotFound(small.resolve(did), "larger than 1024 bytes");
        assertInstanceOf(DidResolution.Found.class, resolver.resolve(did));
    }

    @Test
    void serverErrorsAreUnavailable() {
        for (int status : new int[] {500, 502, 503, 429}) {
            host.on(DOC_PATH, exchange -> TestHttpsServer.send(exchange, status, ""));

            assertUnavailable(resolver.resolve(did), "HTTP " + status);
        }
    }

    @Test
    void hostThatDoesNotAnswerIsUnavailable() {
        host.on(DOC_PATH, exchange -> Thread.sleep(5000));

        long start = System.nanoTime();
        DidResolution result = resolver.resolve(did);

        assertUnavailable(result, "");
        assertTrue(Duration.ofNanos(System.nanoTime() - start).compareTo(Duration.ofSeconds(3)) < 0,
            "deadline not enforced");
    }

    @Test
    void bodyThatArrivesTooSlowlyIsUnavailable() {
        host.on(DOC_PATH, exchange -> {
            byte[] body = documentFor(did).getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            OutputStream out = exchange.getResponseBody();
            out.write(body, 0, 10);
            out.flush();
            Thread.sleep(5000);
            out.write(body, 10, body.length - 10);
        });

        long start = System.nanoTime();
        DidResolution result = resolver.resolve(did);

        assertUnavailable(result, "did not answer within 1500 ms");
        assertTrue(Duration.ofNanos(System.nanoTime() - start).compareTo(Duration.ofSeconds(3)) < 0,
            "deadline not enforced for the body");
    }

    @Test
    void refusedConnectionIsUnavailable() throws Exception {
        int closedPort;
        try (ServerSocket socket = new ServerSocket(0)) {
            closedPort = socket.getLocalPort();
        }

        assertUnavailable(resolver.resolve("did:web:localhost%3A" + closedPort + ":p:alice"), "could not be reached");
    }

    @Test
    void untrustedCertificateIsUnavailable() {
        host.onJson(DOC_PATH, documentFor(did));
        HttpClient defaultTrust = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
        DidWebResolver strict = new DidWebResolver(defaultTrust, DEADLINE, 1024, DidHostPolicy.ALLOW_ALL);

        assertUnavailable(strict.resolve(did), "SSL");
    }

    @Test
    void hostNotAllowedByPolicyIsNotContacted() {
        host.onJson(DOC_PATH, documentFor(did));
        int port = host.port();
        DidWebResolver otherPortOnly = resolver(1024, (h, p) -> "localhost".equals(h) && p != port);

        assertNotFound(otherPortOnly.resolve(did), "not allowed");
        assertEquals(0, host.totalRequests());
    }

    @Test
    void shouldRejectInvalidDids() {
        assertThrows(InvalidDidRecipientException.class, () -> resolver.resolve("did:key:zDnaeXyz"));
        assertThrows(InvalidDidRecipientException.class, () -> resolver.resolve("did:web:127.0.0.1"));
        assertEquals(0, host.totalRequests());
    }

    @Test
    void shouldRequireClientWithoutRedirects() {
        HttpClient following = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build();

        assertThrows(IllegalArgumentException.class,
            () -> new DidWebResolver(following, DEADLINE, 1024, DidHostPolicy.ALLOW_ALL));
        assertEquals(HttpClient.Redirect.NEVER,
            DidWebResolver.createHttpClient(Duration.ofSeconds(1)).followRedirects());
    }

    private DidWebResolver resolver(int maxBytes, DidHostPolicy policy) {
        HttpClient client = HttpClient.newBuilder()
            .sslContext(host.clientSslContext())
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(1))
            .build();
        return new DidWebResolver(client, DEADLINE, maxBytes, policy);
    }

    private static String documentFor(String forDid) {
        return "{\"@context\":[\"https://www.w3.org/ns/did/v1\"],\"id\":\"" + forDid + "\","
            + "\"verificationMethod\":[" + DidDocumentKeysTest.method(forDid + "#key-1", forDid,
                DidDocumentKeysTest.jwk(SshPublicKeyParser.fromRecipientId(SshPublicKeyParserTest.P256_RECIPIENT_ID)))
            + "],\"authentication\":[\"#key-1\"]}";
    }

    private static void assertNotFound(DidResolution result, String reasonPart) {
        DidResolution.NotFound notFound = assertInstanceOf(DidResolution.NotFound.class, result);
        assertTrue(notFound.reason().contains(reasonPart), notFound.reason());
    }

    private static void assertUnavailable(DidResolution result, String reasonPart) {
        DidResolution.Unavailable unavailable = assertInstanceOf(DidResolution.Unavailable.class, result);
        assertTrue(unavailable.reason().contains(reasonPart), unavailable.reason());
    }
}
