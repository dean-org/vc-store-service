package org.openg2p.vcstore.otp;

import org.openg2p.vcstore.config.VaultProperties;
import org.openg2p.vcstore.repo.CredentialIds;
import org.openg2p.vcstore.repo.CredentialRepository;
import org.openg2p.vcstore.repo.StoredCredential;
import org.openg2p.vcstore.web.VaultException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class OtpService {
    private static final Logger log = LoggerFactory.getLogger(OtpService.class);

    public record SendResult(String channel, String destinationMasked, int expiresInSeconds, int resendAfterSeconds) {}

    public record VerifyResult(boolean valid, String reason, String psut) {}

    private final JdbcTemplate jdbc;
    private final CredentialRepository credentials;
    private final OtpSender smsSender;
    private final EmailSender emailSender;
    private final VaultProperties.Otp cfg;

    public OtpService(JdbcTemplate jdbc, CredentialRepository credentials, OtpSender smsSender,
            EmailSender emailSender, VaultProperties props) {
        this.jdbc = jdbc;
        this.credentials = credentials;
        this.smsSender = smsSender;
        this.emailSender = emailSender;
        this.cfg = props.otp();
        if (cfg.hashPepper() == null || cfg.hashPepper().length() < 16) {
            throw new IllegalStateException("vault.otp.hash-pepper (VAULT_OTP_PEPPER) must be set, at least 16 characters");
        }
    }

    public SendResult send(String rawCredentialId) {
        String id = CredentialIds.normalize(rawCredentialId);
        StoredCredential c = usable(id);
        // Email if the credential has one, otherwise SMS to the registered phone.
        OtpDestinations.Destination destination = OtpDestinations.choose(c);
        if (destination == null) {
            throw new VaultException(HttpStatus.UNPROCESSABLE_ENTITY, "no_registered_contact",
                    "No registered email or phone number for this credential");
        }

        Integer recent = jdbc.queryForObject(
                "SELECT count(*) FROM vc_vault.otp WHERE credential_id = ? AND created_at > now() - (? * interval '1 second')",
                Integer.class, id, cfg.resendAfterSeconds());
        if (recent != null && recent > 0) {
            throw new VaultException(HttpStatus.TOO_MANY_REQUESTS, "otp_recently_sent",
                    "An OTP was just sent. Please wait before requesting another.");
        }
        Integer hourly = jdbc.queryForObject(
                "SELECT count(*) FROM vc_vault.otp WHERE credential_id = ? AND created_at > now() - interval '1 hour'",
                Integer.class, id);
        if (hourly != null && hourly >= cfg.maxSendsPerHour()) {
            throw new VaultException(HttpStatus.TOO_MANY_REQUESTS, "otp_limit_reached",
                    "Too many OTP requests for this credential. Try again later.");
        }

        String otp = OtpCodec.generate(cfg.length());
        Long otpId = jdbc.queryForObject(
                "INSERT INTO vc_vault.otp (credential_id, otp_hash, expires_at) "
                        + "VALUES (?, ?, now() + (? * interval '1 second')) RETURNING otp_id",
                Long.class, id, OtpCodec.hash(cfg.hashPepper(), id, otp), cfg.ttlSeconds());

        int minutes = Math.max(1, cfg.ttlSeconds() / 60);
        try {
            if (destination.channel() == OtpDestinations.Channel.EMAIL) {
                emailSender.send(destination.address(), cfg.email().subject(),
                        String.format(cfg.email().bodyTemplate(), otp, minutes));
            } else {
                smsSender.send(destination.address(), String.format(cfg.messageTemplate(), otp, minutes));
            }
        } catch (RuntimeException e) {
            jdbc.update("DELETE FROM vc_vault.otp WHERE otp_id = ?", otpId);
            log.error("OTP delivery by {} failed for credential {}: {}", destination.channel(), id, e.toString());
            throw new VaultException(HttpStatus.BAD_GATEWAY, "otp_delivery_failed", "Could not deliver the OTP");
        }
        log.info("OTP sent for credential {} by {} to {}", id, destination.channel(), destination.masked());
        return new SendResult(destination.channel().name(), destination.masked(), cfg.ttlSeconds(), cfg.resendAfterSeconds());
    }

    public VerifyResult verify(String rawCredentialId, String otp) {
        String id = CredentialIds.normalize(rawCredentialId);
        usable(id);

        var latest = jdbc.queryForList(
                "SELECT otp_id FROM vc_vault.otp WHERE credential_id = ? AND consumed = false "
                        + "AND expires_at > now() ORDER BY created_at DESC LIMIT 1",
                Long.class, id);
        if (latest.isEmpty()) {
            return new VerifyResult(false, "otp_expired_or_not_requested", null);
        }
        long otpId = latest.get(0);

        // Count the attempt first (atomically), then compare: concurrent guesses cannot exceed the limit.
        var hashes = jdbc.query(
                "UPDATE vc_vault.otp SET attempts = attempts + 1 "
                        + "WHERE otp_id = ? AND consumed = false AND attempts < ? RETURNING otp_hash",
                (rs, i) -> rs.getString(1), otpId, cfg.maxAttempts());
        if (hashes.isEmpty()) {
            return new VerifyResult(false, "too_many_attempts", null);
        }
        if (otp == null || !OtpCodec.matches(hashes.get(0), cfg.hashPepper(), id, otp.trim())) {
            return new VerifyResult(false, "otp_mismatch", null);
        }
        int consumed = jdbc.update("UPDATE vc_vault.otp SET consumed = true WHERE otp_id = ? AND consumed = false", otpId);
        if (consumed != 1) {
            return new VerifyResult(false, "otp_already_used", null);
        }
        log.info("OTP verified for credential {}", id);
        return new VerifyResult(true, null, id); // psut = credential id => `sub` in the eSignet access token
    }

    private StoredCredential usable(String id) {
        StoredCredential c = credentials.findById(id)
                .orElseThrow(() -> new VaultException(HttpStatus.NOT_FOUND, "invalid_credential_id", "Unknown credential id"));
        if (!"ACTIVE".equals(c.status())) {
            throw new VaultException(HttpStatus.GONE, "credential_not_active", "This credential is " + c.status());
        }
        if (c.expired()) {
            throw new VaultException(HttpStatus.GONE, "credential_expired", "This credential has expired");
        }
        return c;
    }
}
