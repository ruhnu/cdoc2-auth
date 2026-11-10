package ee.cyber.cdoc2.auth;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.nimbusds.jose.util.JSONObjectUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resolves did:web DIDs: one HTTPS GET of the URL the did:web method defines ({@link DidWeb#documentUri()}),
 * without following redirects, within an overall deadline that covers connecting, the response headers and the
 * body, and with a cap on the body size. TLS is validated with the trust material of the {@link HttpClient},
 * by default the runtime's default trusted CAs. Each response is classified as {@link DidResolution.Found},
 * {@link DidResolution.NotFound} or {@link DidResolution.Unavailable}, the same way on clients and servers.
 * Nothing is cached.
 */
public final class DidWebResolver {

    private static final Logger log = LoggerFactory.getLogger(DidWebResolver.class);

    /** Default connect timeout */
    public static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(2);

    /** Default overall deadline for one resolution */
    public static final Duration DEFAULT_DEADLINE = Duration.ofSeconds(3);

    /** Default limit for the DID document size */
    public static final int DEFAULT_MAX_DOCUMENT_BYTES = 64 * 1024;

    private static final int HTTP_OK = 200;
    private static final int HTTP_TOO_MANY_REQUESTS = 429;
    private static final int HTTP_SERVER_ERROR_MIN = 500;
    private static final int HTTP_SERVER_ERROR_MAX = 599;

    private final HttpClient httpClient;
    private final Duration deadline;
    private final int maxDocumentBytes;
    private final DidHostPolicy hostPolicy;

    /**
     * @param httpClient       HTTP client; must not follow redirects, see {@link #createHttpClient(Duration)}
     * @param deadline         overall deadline for one resolution
     * @param maxDocumentBytes largest DID document accepted
     * @param hostPolicy       hosts that may be contacted
     */
    public DidWebResolver(HttpClient httpClient, Duration deadline, int maxDocumentBytes, DidHostPolicy hostPolicy) {
        this.httpClient = Objects.requireNonNull(httpClient);
        this.deadline = Objects.requireNonNull(deadline);
        this.maxDocumentBytes = maxDocumentBytes;
        this.hostPolicy = Objects.requireNonNull(hostPolicy);
        if (httpClient.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalArgumentException("DID resolution must not follow redirects");
        }
    }

    /**
     * Resolver with an {@link #createHttpClient(Duration) HTTP client} that uses the default trusted CAs.
     * @param connectTimeout connect timeout
     * @param deadline       overall deadline for one resolution
     * @param hostPolicy     hosts that may be contacted
     * @return resolver
     */
    public static DidWebResolver createDefault(Duration connectTimeout, Duration deadline, DidHostPolicy hostPolicy) {
        return new DidWebResolver(createHttpClient(connectTimeout), deadline, DEFAULT_MAX_DOCUMENT_BYTES, hostPolicy);
    }

    /**
     * HTTP client for DID resolution: no redirects, the default proxy selector (so the standard
     * {@code https.proxyHost} and {@code http.nonProxyHosts} settings apply) and the default SSL context.
     * @param connectTimeout connect timeout
     * @return HTTP client
     */
    public static HttpClient createHttpClient(Duration connectTimeout) {
        HttpClient.Builder builder = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(connectTimeout);
        ProxySelector proxySelector = ProxySelector.getDefault();
        if (proxySelector != null) {
            builder.proxy(proxySelector);
        }
        return builder.build();
    }

    /**
     * Resolve a DID.
     * @param did did:web DID
     * @return resolution result
     * @throws ee.cyber.cdoc2.auth.exception.InvalidDidRecipientException if {@code did} is not a valid did:web DID
     */
    public DidResolution resolve(String did) {
        return resolve(DidWeb.parse(did));
    }

    /**
     * Resolve a DID.
     * @param did did:web DID
     * @return resolution result
     */
    public DidResolution resolve(DidWeb did) {
        Objects.requireNonNull(did);
        if (!hostPolicy.allows(did.host(), did.port())) {
            return new DidResolution.NotFound("DID host " + did.host() + ":" + did.port() + " is not allowed");
        }

        HttpRequest request = HttpRequest.newBuilder(did.documentUri())
            .GET()
            .timeout(deadline)
            .header("Accept", "application/did+json, application/json")
            .build();

        CompletableFuture<HttpResponse<byte[]>> pending =
            httpClient.sendAsync(request, info -> bodySubscriber(info, maxDocumentBytes));
        HttpResponse<byte[]> response;
        try {
            response = pending.get(deadline.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            pending.cancel(true);
            return unavailable(did, "DID host did not answer within " + deadline.toMillis() + " ms");
        } catch (InterruptedException e) {
            pending.cancel(true);
            Thread.currentThread().interrupt();
            return unavailable(did, "interrupted");
        } catch (ExecutionException e) {
            Throwable cause = (e.getCause() != null) ? e.getCause() : e;
            if (hasCause(cause, DocumentTooLargeException.class)) {
                return notFound(did, "DID document is larger than " + maxDocumentBytes + " bytes");
            }
            return unavailable(did, "DID host could not be reached: " + describe(cause));
        }

        int status = response.statusCode();
        if (status == HTTP_TOO_MANY_REQUESTS || (status >= HTTP_SERVER_ERROR_MIN && status <= HTTP_SERVER_ERROR_MAX)) {
            return unavailable(did, "DID host responded HTTP " + status);
        }
        if (status != HTTP_OK) {
            return notFound(did, "DID host responded HTTP " + status);
        }
        return parseDocument(did, response.body());
    }

    private static DidResolution parseDocument(DidWeb did, byte[] body) {
        Map<String, Object> document;
        try {
            document = JSONObjectUtils.parse(new String(body, StandardCharsets.UTF_8));
        } catch (ParseException e) {
            return notFound(did, "DID document is not a JSON object");
        }
        if (!did.did().equals(document.get("id"))) {
            return notFound(did, "DID document is for another DID (" + document.get("id") + ")");
        }
        return new DidResolution.Found(DidDocumentKeys.extract(did.did(), document));
    }

    private static HttpResponse.BodySubscriber<byte[]> bodySubscriber(HttpResponse.ResponseInfo info, int maxBytes) {
        if (info.statusCode() != HTTP_OK) {
            return HttpResponse.BodySubscribers.replacing(new byte[0]);
        }
        return new LimitedBodySubscriber(maxBytes);
    }

    private static DidResolution notFound(DidWeb did, String reason) {
        log.info("DID {} not found: {}", did, reason);
        return new DidResolution.NotFound(reason);
    }

    private static DidResolution unavailable(DidWeb did, String reason) {
        log.info("DID {} unavailable: {}", did, reason);
        return new DidResolution.Unavailable(reason);
    }

    private static boolean hasCause(Throwable t, Class<? extends Throwable> type) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (type.isInstance(c)) {
                return true;
            }
        }
        return false;
    }

    private static String describe(Throwable t) {
        return t.getClass().getSimpleName() + ((t.getMessage() != null) ? " " + t.getMessage() : "");
    }

    /** Body larger than the limit */
    private static final class DocumentTooLargeException extends IOException {
        private static final long serialVersionUID = 1L;

        DocumentTooLargeException() {
            super("DID document too large");
        }
    }

    /** Collects the body, failing as soon as it exceeds the limit */
    private static final class LimitedBodySubscriber implements HttpResponse.BodySubscriber<byte[]> {
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private final ByteArrayOutputStream body = new ByteArrayOutputStream();
        private final int maxBytes;
        private Flow.Subscription subscription;

        LimitedBodySubscriber(int maxBytes) {
            this.maxBytes = maxBytes;
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return result;
        }

        @Override
        public void onSubscribe(Flow.Subscription newSubscription) {
            this.subscription = newSubscription;
            newSubscription.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(List<ByteBuffer> buffers) {
            if (result.isDone()) {
                return;
            }
            for (ByteBuffer buffer : buffers) {
                if (body.size() + buffer.remaining() > maxBytes) {
                    subscription.cancel();
                    result.completeExceptionally(new DocumentTooLargeException());
                    return;
                }
                byte[] chunk = new byte[buffer.remaining()];
                buffer.get(chunk);
                body.writeBytes(chunk);
            }
        }

        @Override
        public void onError(Throwable throwable) {
            result.completeExceptionally(throwable);
        }

        @Override
        public void onComplete() {
            result.complete(body.toByteArray());
        }
    }
}
