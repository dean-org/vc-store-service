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

    private static final Logger log =
            LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    VaultCrypto vaultCrypto(VaultProperties props) {
        VaultCrypto crypto = new VaultCrypto(props.encryptionKey());

        if (!crypto.enabled()) {
            log.warn(
                    "vault.encryption-key is empty: stored values are read as clear text (dev only)"
            );
        }

        return crypto;
    }

    /**
     * Normal operation: validates eSignet access tokens using JWKS,
     * issuer, and audience.
     *
     * LOCAL TESTING ONLY:
     * If VAULT_DEV_HMAC_SECRET is set, HS256 tokens signed with that
     * shared secret are accepted instead.
     *
     * Never use this override in a shared or production environment.
     */
    @Bean
    JwtDecoder jwtDecoder(
            VaultProperties props,
            Environment env,
            @Value("${vault.dev-hmac-secret:}") String devHmacSecret) {

        if (devHmacSecret != null && !devHmacSecret.isBlank()) {

            if (env.acceptsProfiles(
                    Profiles.of("prod", "production"))) {
                throw new IllegalStateException(
                        "VAULT_DEV_HMAC_SECRET must not be set when "
                                + "the prod profile is active"
                );
            }

            byte[] key =
                    devHmacSecret.getBytes(StandardCharsets.UTF_8);

            if (key.length < 32) {
                throw new IllegalStateException(
                        "VAULT_DEV_HMAC_SECRET must be at least "
                                + "32 bytes for HS256"
                );
            }

            log.warn(
                    "*** DEV MODE: accepting HS256 tokens signed with "
                            + "VAULT_DEV_HMAC_SECRET instead of eSignet tokens. "
                            + "Anyone with that secret can mint tokens. "
                            + "Never use this outside your own machine. ***"
            );

            return NimbusJwtDecoder
                    .withSecretKey(
                            new SecretKeySpec(key, "HmacSHA256"))
                    .macAlgorithm(MacAlgorithm.HS256)
                    .build();
        }

        return eSignetDecoder(props.oidc());
    }

    private static JwtDecoder eSignetDecoder(
            VaultProperties.Oidc oidc) {

        if (isBlank(oidc.issuerUri())
                || isBlank(oidc.jwkSetUri())
                || oidc.allowedAudiences() == null
                || oidc.allowedAudiences().isEmpty()) {

            throw new IllegalStateException(
                    "vault.oidc.issuer-uri, jwk-set-uri and "
                            + "allowed-audiences must be configured "
                            + "(or set VAULT_DEV_HMAC_SECRET for local testing)"
            );
        }

        NimbusJwtDecoder decoder =
                NimbusJwtDecoder
                        .withJwkSetUri(oidc.jwkSetUri())
                        .jwsAlgorithms(algorithms -> {
                            algorithms.add(SignatureAlgorithm.RS256);
                            algorithms.add(SignatureAlgorithm.PS256);
                        })
                        .build();

        List<String> allowed = oidc.allowedAudiences();

        OAuth2TokenValidator<Jwt> audience = token -> {
            List<String> aud = token.getAudience();

            return aud != null
                    && aud.stream().anyMatch(allowed::contains)
                    ? OAuth2TokenValidatorResult.success()
                    : OAuth2TokenValidatorResult.failure(
                    new OAuth2Error(
                            "invalid_token",
                            "Audience not allowed",
                            null
                    )
            );
        };

        decoder.setJwtValidator(
                new DelegatingOAuth2TokenValidator<>(
                        JwtValidators.createDefaultWithIssuer(
                                oidc.issuerUri()),
                        audience
                )
        );

        return decoder;
    }

    @Bean
    SecurityFilterChain chain(
            HttpSecurity http,
            VaultProperties props,
            Environment env,
            @Value("${vault.internal-auth-enabled:true}") boolean internalAuthEnabled) throws Exception {

        if (!internalAuthEnabled) {
            if (env.acceptsProfiles(Profiles.of("prod", "production"))) {
                throw new IllegalStateException(
                        "vault.internal-auth-enabled=false is not allowed when the prod profile is active");
            }
            log.warn("*** LOCAL TESTING ONLY: /internal/** is OPEN without X-Internal-Key "
                    + "(vault.internal-auth-enabled=false). Anyone who can reach this service can trigger OTPs. "
                    + "Never use this outside your own machine. ***");
        }

        http
                .csrf(AbstractHttpConfigurer::disable)

                .sessionManagement(session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS
                        )
                )

                .authorizeHttpRequests(auth -> auth

                        // Public health endpoints
                        .requestMatchers(
                                "/actuator/health",
                                "/actuator/health/**"
                        ).permitAll()

                        // Public well-known endpoints
                        .requestMatchers(
                                "/.well-known/**"
                        ).permitAll()

                        // Allow Spring Boot error handling
                        .requestMatchers(
                                "/error"
                        ).permitAll()

                        // Allow Swagger UI
                        .requestMatchers(
                                "/swagger-ui.html",
                                "/swagger-ui/**"
                        ).permitAll()

                        // Allow OpenAPI specification
                        .requestMatchers(
                                "/v3/api-docs",
                                "/v3/api-docs/**"
                        ).permitAll()

                        // Internal endpoints are guarded by InternalKeyFilter
                        .requestMatchers(
                                "/internal/**"
                        ).permitAll()

                        // Credential endpoint still requires a valid JWT
                        .requestMatchers(
                                "/credential"
                        ).authenticated()

                        // Deny every other endpoint by default
                        .anyRequest().denyAll()
                )

                // JWT authentication for protected endpoints
                .oauth2ResourceServer(oauth2 ->
                        oauth2.jwt(Customizer.withDefaults())
                );

        // Internal API-key validation (skipped only when explicitly disabled for local testing)
        if (internalAuthEnabled) {
            http.addFilterBefore(
                    new InternalKeyFilter(props.internalApiKey()),
                    UsernamePasswordAuthenticationFilter.class);
        }

        return http.build();
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}