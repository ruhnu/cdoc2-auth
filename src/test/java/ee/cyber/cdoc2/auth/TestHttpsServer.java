package ee.cyber.cdoc2.auth;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * HTTPS server on localhost with a self-signed "localhost" certificate, for DID host tests. Responses are
 * registered per path; every request is counted per path.
 */
final class TestHttpsServer implements AutoCloseable {

    private static final char[] PASSWORD = "test".toCharArray();

    /** Writes a response */
    @FunctionalInterface
    interface Responder {
        void respond(HttpExchange exchange) throws IOException, InterruptedException;
    }

    private final HttpsServer server;
    private final ExecutorService executor = Executors.newCachedThreadPool();
    private final SSLContext clientSslContext;
    private final Map<String, Responder> responders = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> requests = new ConcurrentHashMap<>();

    TestHttpsServer() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = generator.generateKeyPair();
        X509Certificate cert = selfSignedLocalhost(keyPair);

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("server", keyPair.getPrivate(), PASSWORD, new Certificate[] {cert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, PASSWORD);
        SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(kmf.getKeyManagers(), null, null);

        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("server", cert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        clientSslContext = SSLContext.getInstance("TLS");
        clientSslContext.init(null, tmf.getTrustManagers(), null);

        server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(serverContext));
        server.setExecutor(executor);
        server.createContext("/", this::handle);
        server.start();
    }

    /** @return SSL context that trusts this server's certificate */
    SSLContext clientSslContext() {
        return clientSslContext;
    }

    int port() {
        return server.getAddress().getPort();
    }

    void on(String path, Responder responder) {
        responders.put(path, responder);
    }

    void onJson(String path, String json) {
        on(path, exchange -> send(exchange, 200, json));
    }

    int requestCount(String path) {
        AtomicInteger count = requests.get(path);
        return (count == null) ? 0 : count.get();
    }

    int totalRequests() {
        return requests.values().stream().mapToInt(AtomicInteger::get).sum();
    }

    static void send(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/did+json");
        exchange.sendResponseHeaders(status, (bytes.length == 0) ? -1 : bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }

    private void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        requests.computeIfAbsent(path, p -> new AtomicInteger()).incrementAndGet();
        Responder responder = responders.get(path);
        try {
            if (responder == null) {
                send(exchange, 404, "");
            } else {
                responder.respond(exchange);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            exchange.close();
        }
    }

    private static X509Certificate selfSignedLocalhost(KeyPair keyPair) throws Exception {
        X500Name name = new X500Name("CN=localhost");
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name,
            BigInteger.valueOf(now.toEpochMilli()), Date.from(now.minus(Duration.ofDays(1))),
            Date.from(now.plus(Duration.ofDays(1))), name, keyPair.getPublic());
        builder.addExtension(Extension.subjectAlternativeName, false,
            new GeneralNames(new GeneralName(GeneralName.dNSName, "localhost")));
        return new JcaX509CertificateConverter().getCertificate(
            builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate())));
    }
}
