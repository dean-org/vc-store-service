package org.openg2p.vcstore.config;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "vault")
public record VaultProperties(
        String publicBaseUrl,
        String encryptionKey,
        String internalApiKey,
        Oidc oidc,
        Otp otp,
        Credential credential,
        Metadata metadata) {

    public record Oidc(String issuerUri, String jwkSetUri, List<String> allowedAudiences) {}

    public record Otp(
            int length,
            int ttlSeconds,
            int maxAttempts,
            int resendAfterSeconds,
            int maxSendsPerHour,
            String hashPepper,
            String messageTemplate,
            Sender sender,
            Email email) {}

    public record Sender(String type, boolean logOtp, String url, String authToken) {}

    /** Email channel: used when the credential has a registered email; SMS (Sender) otherwise. */
    public record Email(String type, boolean logOtp, String from, String subject, String bodyTemplate, Smtp smtp) {}

    public record Smtp(String host, int port, String username, String password, boolean auth, boolean starttls, boolean ssl) {}

    public record Credential(int maxDownloads) {}

    public record Metadata(String templatePath) {}
}
