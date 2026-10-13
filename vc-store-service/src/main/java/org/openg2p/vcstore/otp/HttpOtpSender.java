package org.openg2p.vcstore.otp;

import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

/**
 * Generic webhook sender: POST {"to": "<phone>", "message": "<text>"} to the configured URL
 * (optionally with a bearer token). Adapt the body here to your SMS gateway's API.
 */
public class HttpOtpSender implements OtpSender {
    private final RestClient client = RestClient.create();
    private final String url;
    private final String authToken;

    public HttpOtpSender(String url, String authToken) {
        if (url == null || url.isBlank()) {
            throw new IllegalStateException("vault.otp.sender.url is required when sender.type=http");
        }
        this.url = url;
        this.authToken = authToken;
    }

    @Override
    public void send(String phoneE164, String message) {
        client.post()
                .uri(url)
                .contentType(MediaType.APPLICATION_JSON)
                .headers(h -> {
                    if (authToken != null && !authToken.isBlank()) {
                        h.setBearerAuth(authToken);
                    }
                })
                .body(Map.of("to", phoneE164, "message", message))
                .retrieve()
                .toBodilessEntity();
    }
}
