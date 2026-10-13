package org.openg2p.esignet.vcstore;

import io.mosip.esignet.api.dto.AuthChallenge;
import io.mosip.esignet.api.dto.KycAuthDto;
import io.mosip.esignet.api.dto.KycAuthResult;
import io.mosip.esignet.api.dto.KycExchangeDto;
import io.mosip.esignet.api.dto.KycExchangeResult;
import io.mosip.esignet.api.dto.KycSigningCertificateData;
import io.mosip.esignet.api.dto.SendOtpDto;
import io.mosip.esignet.api.dto.SendOtpResult;
import io.mosip.esignet.api.exception.KycAuthException;
import io.mosip.esignet.api.exception.KycExchangeException;
import io.mosip.esignet.api.exception.KycSigningCertificateException;
import io.mosip.esignet.api.exception.SendOtpException;
import io.mosip.esignet.api.spi.Authenticator;
import io.mosip.esignet.api.util.ErrorConstants;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * eSignet authenticator backed by the credential vault.
 *
 * The farmer enters the claim code printed on the credential card (K7QM-2XPD-9TVR) as the "individual id" and
 * the OTP they receive (by email if the credential has an email, otherwise by SMS). The vc-store service owns
 * the OTPs and the vault; this class only forwards the calls. On success the claim code is returned as the
 * partner-specific user token, which eSignet puts into the access token's `sub`, so the credential endpoint
 * knows which stored credential to hand over.
 *
 * Enable with:  mosip.esignet.integration.authenticator=VcStoreAuthenticationService
 */
@ConditionalOnProperty(value = "mosip.esignet.integration.authenticator", havingValue = "VcStoreAuthenticationService")
@Component
public class VcStoreAuthenticationService implements Authenticator {

    private static final Logger log = LoggerFactory.getLogger(VcStoreAuthenticationService.class);

    private final VcStoreClient client;
    private final String otpFactor;
    private final Set<String> supportedChannels;

    public VcStoreAuthenticationService(
            @Value("${mosip.esignet.vcstore.base-url}") String baseUrl,
            @Value("${mosip.esignet.vcstore.internal-api-key}") String internalApiKey,
            @Value("${mosip.esignet.vcstore.connect-timeout-ms:3000}") int connectTimeoutMs,
            @Value("${mosip.esignet.vcstore.read-timeout-ms:10000}") int readTimeoutMs,
            @Value("${mosip.esignet.vcstore.otp-auth-factor:OTP}") String otpAuthFactor,
            @Value("${mosip.esignet.vcstore.supported-otp-channels:email,phone}") String supportedOtpChannels) {
        this.client = new VcStoreClient(baseUrl, internalApiKey, connectTimeoutMs, readTimeoutMs);
        this.otpFactor = otpAuthFactor.trim();
        this.supportedChannels = Arrays.stream(supportedOtpChannels.split(","))
                .map(s -> s.trim().toLowerCase(Locale.ROOT))
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toCollection(HashSet::new));
    }

    @Override
    public SendOtpResult sendOtp(String relyingPartyId, String clientId, SendOtpDto sendOtpDto) throws SendOtpException {
        String claimCode = sendOtpDto == null ? null : sendOtpDto.getIndividualId();
        if (claimCode == null || claimCode.isBlank()) {
            throw new SendOtpException(ErrorConstants.SEND_OTP_FAILED);
        }
        VcStoreClient.Reply reply;
        try {
            reply = client.post("/internal/otp/send", MiniJson.object("credentialId", claimCode.trim()));
        } catch (VcStoreClient.VcStoreException e) {
            log.error("OTP request for transaction {} failed: {}", sendOtpDto.getTransactionId(), e.getMessage());
            throw new SendOtpException(ErrorConstants.SEND_OTP_FAILED);
        }
        String channel = reply.string("channel");
        String masked = reply.string("destinationMasked");
        if (reply.status != 200 || channel == null || masked == null) {
            // One generic error for every cause (unknown code, revoked, no contact, throttled, delivery failed):
            // a more specific one would let anyone probe which claim codes exist.
            log.warn("vc-store did not send an OTP for transaction {}: status={} error={}",
                    sendOtpDto.getTransactionId(), reply.status, reply.string("error"));
            throw new SendOtpException(ErrorConstants.SEND_OTP_FAILED);
        }
        boolean email = "EMAIL".equalsIgnoreCase(channel);
        boolean sms = "SMS".equalsIgnoreCase(channel);
        if (!email && !sms) {
            log.error("vc-store returned an unknown OTP channel '{}'", channel);
            throw new SendOtpException(ErrorConstants.SEND_OTP_FAILED);
        }
        log.info("OTP sent for transaction {} by {}", sendOtpDto.getTransactionId(), channel);
        return new SendOtpResult(sendOtpDto.getTransactionId(), email ? masked : null, sms ? masked : null);
    }

    @Override
    public KycAuthResult doKycAuth(String relyingPartyId, String clientId, KycAuthDto kycAuthDto) throws KycAuthException {
        if (kycAuthDto == null || kycAuthDto.getIndividualId() == null || kycAuthDto.getIndividualId().isBlank()) {
            throw new KycAuthException(ErrorConstants.AUTH_FAILED);
        }
        AuthChallenge otp = null;
        List<AuthChallenge> challenges = kycAuthDto.getChallengeList();
        if (challenges != null) {
            for (AuthChallenge challenge : challenges) {
                if (challenge != null && otpFactor.equalsIgnoreCase(challenge.getAuthFactorType())) {
                    otp = challenge;
                    break;
                }
            }
        }
        if (otp == null) {
            throw new KycAuthException(ErrorConstants.INVALID_AUTH_FACTOR_TYPE);
        }
        if (otp.getChallenge() == null || otp.getChallenge().isBlank()) {
            throw new KycAuthException(ErrorConstants.INVALID_CHALLENGE);
        }

        VcStoreClient.Reply reply;
        try {
            reply = client.post("/internal/otp/verify",
                    MiniJson.object("credentialId", kycAuthDto.getIndividualId().trim(), "otp", otp.getChallenge()));
        } catch (VcStoreClient.VcStoreException e) {
            log.error("OTP verification for transaction {} failed: {}", kycAuthDto.getTransactionId(), e.getMessage());
            throw new KycAuthException(ErrorConstants.AUTH_FAILED);
        }
        if (reply.status != 200 || !reply.bool("valid")) {
            log.warn("OTP rejected for transaction {}: status={} reason={}",
                    kycAuthDto.getTransactionId(), reply.status, reply.string("reason"));
            throw new KycAuthException(ErrorConstants.AUTH_FAILED);
        }
        // The service returns the canonical claim code (it normalises what was typed). It becomes `sub`.
        String psut = reply.string("psut");
        if (psut == null || psut.isBlank()) {
            log.error("vc-store accepted the OTP but returned no subject for transaction {}", kycAuthDto.getTransactionId());
            throw new KycAuthException(ErrorConstants.AUTH_FAILED);
        }
        log.info("OTP verified for transaction {}", kycAuthDto.getTransactionId());
        return new KycAuthResult(UUID.randomUUID().toString(), psut);
    }

    /** Wallets download the credential from the vc-store service; no user claims are served by this plugin. */
    @Override
    public KycExchangeResult doKycExchange(String relyingPartyId, String clientId, KycExchangeDto kycExchangeDto)
            throws KycExchangeException {
        throw new KycExchangeException(ErrorConstants.NOT_IMPLEMENTED, "userinfo is not supported by the vc-store authenticator");
    }

    @Override
    public boolean isSupportedOtpChannel(String channel) {
        return channel != null && supportedChannels.contains(channel.trim().toLowerCase(Locale.ROOT));
    }

    @Override
    public List<KycSigningCertificateData> getAllKycSigningCertificates() throws KycSigningCertificateException {
        return Collections.emptyList();
    }
}
