package org.openg2p.vcstore.config;

import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.crypto.spec.SecretKeySpec;
import org.openg2p.vcstore.crypto.VaultCrypto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {
    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    VaultCrypto vaultCrypto(VaultProperties props) {
        VaultCrypto crypto = new VaultCrypto(props.encryptionKey());
        if (!crypto.enabled()) {
            log.warn("vault.encryption-key is empty: stored values are read as clear text (dev only)");
        }
        return crypto;
    }

    /**
     * Normal operation: validates eSignet access tokens (signature via JWKS, issuer, audience).
     *
     * LOCAL TESTING ONLY: if VAULT_DEV_HMAC_SECRET is set, tokens signed with that shared secret (HS256) are
     * accepted instead. Anyone who knows the secret can mint a token for any claim code and download that
     * credential without an OTP, so it must never be set on a shared or production environment. The service
     * refuses to start with it when a "prod"/"production" Spring profile is active.
     */
    @Bean
    JwtDecoder jwtDecoder(VaultProperties props, Environment env,
                          @Value("${vault.dev-hmac-secret:}") String devHmacSecret) {
        if (devHmacSecret != null && !devHmacSecret.isBlank()) {
            if (env.acceptsProfiles(Profiles.of("prod", "production"))) {
                throw new IllegalStateException("VAULT_DEV_HMAC_SECRET must not be set when the prod profile is active");
            }
            byte[] key = devHmacSecret.getBytes(StandardCharsets.UTF_8);
            if (key.length < 32) {
                throw new IllegalStateException("VAULT_DEV_HMAC_SECRET must be at least 32 bytes for HS256");
            }
            log.warn("*** DEV MODE: accepting HS256 tokens signed with VAULT_DEV_HMAC_SECRET instead of eSignet tokens. "
                    + "Anyone with that secret can download any credential without an OTP. Never use this outside your own machine. ***");
            return NimbusJwtDecoder.withSecretKey(new SecretKeySpec(key, "HmacSHA256"))
                    .macAlgorithm(MacAlgorithm.HS256)
                    .build();
        }
        return eSignetDecoder(props.oidc());
    }

    private static JwtDecoder eSignetDecoder(VaultProperties.Oidc oidc) {
        if (isBlank(oidc.issuerUri()) || isBlank(oidc.jwkSetUri()) || oidc.allowedAudiences() == null
                || oidc.allowedAudiences().isEmpty()) {
            throw new IllegalStateException(
                    "vault.oidc.issuer-uri, jwk-set-uri and allowed-audiences must be configured "
                            + "(or set VAULT_DEV_HMAC_SECRET for local testing)");
        }
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(oidc.jwkSetUri())
                .jwsAlgorithms(a -> {
                    a.add(SignatureAlgorithm.RS256);
                    a.add(SignatureAlgorithm.PS256);
                })
                .build();
        List<String> allowed = oidc.allowedAudiences();
        OAuth2TokenValidator<Jwt> audience = token -> {
            List<String> aud = token.getAudience();
            return aud != null && aud.stream().anyMatch(allowed::contains)
                    ? OAuth2TokenValidatorResult.success()
                    : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Audience not allowed", null));
        };
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(oidc.issuerUri()), audience));
        return decoder;
    }

    @Bean
    SecurityFilterChain chain(HttpSecurity http, VaultProperties props) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/actuator/health/**", "/actuator/health", "/.well-known/**").permitAll()
                        // Spring Boot forwards failures to /error; without this an error body is replaced by a 401.
                        .requestMatchers("/error").permitAll()
                        .requestMatchers("/internal/**").permitAll() // guarded by InternalKeyFilter below
                        .requestMatchers("/credential").authenticated()
                        .anyRequest().denyAll())
                .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))
                .addFilterBefore(new InternalKeyFilter(props.internalApiKey()), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}