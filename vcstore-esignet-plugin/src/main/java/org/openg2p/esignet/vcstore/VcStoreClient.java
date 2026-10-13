package org.openg2p.esignet.vcstore;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collections;
import java.util.Map;

/** Calls the vc-store service's internal OTP endpoints. */
final class VcStoreClient {

    /** HTTP status and the parsed JSON body (empty when the body was not a JSON object). */
    static final class Reply {
        final int status;
        final Map<String, Object> body;

        Reply(int status, Map<String, Object> body) {
            this.status = status;
            this.body = body;
        }

        String string(String key) {
            Object v = body.get(key);
            return v instanceof String ? (String) v : null;
        }

        boolean bool(String key) {
            return Boolean.TRUE.equals(body.get(key));
        }
    }

    /** The vc-store service could not be reached or did not answer in time. */
    static final class VcStoreException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        VcStoreException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private final HttpClient http;
    private final String baseUrl;
    private final String internalKey;
    private final Duration readTimeout;

    VcStoreClient(String baseUrl, String internalKey, int connectTimeoutMs, int readTimeoutMs) {
        if (baseUrl == null || baseUrl.isBlank()) {
            throw new IllegalStateException("mosip.esignet.vcstore.base-url is required (e.g. http://vc-store-service/v1/vault)");
        }
        if (internalKey == null || internalKey.length() < 16) {
            throw new IllegalStateException(
                    "mosip.esignet.vcstore.internal-api-key is required (at least 16 characters, "
                            + "the same value as VAULT_INTERNAL_API_KEY on the vc-store service)");
        }
        this.baseUrl = baseUrl.trim().replaceAll("/+$", "");
        URI uri = URI.create(this.baseUrl);
        if (uri.getScheme() == null || !(uri.getScheme().equals("http") || uri.getScheme().equals("https"))) {
            throw new IllegalStateException("mosip.esignet.vcstore.base-url must start with http:// or https://");
        }
        this.internalKey = internalKey;
        this.readTimeout = Duration.ofMillis(readTimeoutMs);
        this.http = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofMillis(connectTimeoutMs))
                .followRedirects(HttpClient.Redirect.NEVER) // never forward the internal key to another host
                .build();
    }

    Reply post(String path, String jsonBody) {
        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .timeout(readTimeout)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("X-Internal-Key", internalKey)
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8))
                .build();
        try {
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return new Reply(response.statusCode(), parseQuietly(response.body()));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new VcStoreException("interrupted while calling the vc-store service", e);
        } catch (IOException e) {
            throw new VcStoreException("vc-store service not reachable: " + e.getClass().getSimpleName(), e);
        }
    }

    private static Map<String, Object> parseQuietly(String body) {
        if (body == null || body.isBlank()) {
            return Collections.emptyMap();
        }
        try {
            return MiniJson.parseObject(body);
        } catch (IllegalArgumentException e) {
            return Collections.emptyMap();
        }
    }
}
