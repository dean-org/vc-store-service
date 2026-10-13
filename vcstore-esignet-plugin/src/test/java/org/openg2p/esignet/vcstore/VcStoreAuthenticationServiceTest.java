package org.openg2p.esignet.vcstore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.mosip.esignet.api.dto.AuthChallenge;
import io.mosip.esignet.api.dto.KycAuthDto;
import io.mosip.esignet.api.dto.KycAuthResult;
import io.mosip.esignet.api.dto.SendOtpDto;
import io.mosip.esignet.api.dto.SendOtpResult;
import io.mosip.esignet.api.exception.KycAuthException;
import io.mosip.esignet.api.exception.KycExchangeException;
import io.mosip.esignet.api.exception.SendOtpException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Runs the plugin against a real local HTTP server that behaves like the vc-store service. */
class VcStoreAuthenticationServiceTest {

    static final String KEY = "test-internal-key-0123456789";
    static HttpServer server;
    static String baseUrl;
    static volatile String lastKeyHeader;
    static volatile String lastContentType;
    static volatile String lastPath;
    static volatile String lastBody;

    @BeforeAll
    static void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(Executors.newFixedThreadPool(4));
        server.createContext("/v1/vault/internal/otp/send", ex -> handle(ex, true));
        server.createContext("/v1/vault/internal/otp/verify", ex -> handle(ex, false));
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/v1/vault";
    }

    @AfterAll
    static void stop() {
        server.stop(0);
    }

    @BeforeEach
    void reset() {
        lastKeyHeader = null;
        lastContentType = null;
        lastPath = null;
        lastBody = null;
    }

    // ---- the fake vc-store service ------------------------------------------------------------------------
    static void handle(HttpExchange ex, boolean send) throws IOException {
        byte[] raw = ex.getRequestBody().readAllBytes();
        lastBody = new String(raw, StandardCharsets.UTF_8);
        lastPath = ex.getRequestURI().getPath();
        lastKeyHeader = ex.getRequestHeaders().getFirst("X-Internal-Key");
        lastContentType = ex.getRequestHeaders().getFirst("Content-Type");
        if (!KEY.equals(lastKeyHeader)) {
            reply(ex, 401, "{\"error\":\"unauthorized\"}");
            return;
        }
        Map<String, Object> req = MiniJson.parseObject(lastBody);
        String id = String.valueOf(req.get("credentialId"));
        String otp = String.valueOf(req.get("otp"));
        if (send) {
            switch (id) {
                case "EMAIL-1": reply(ex, 200, "{\"channel\":\"EMAIL\",\"destinationMasked\":\"r***@example.com\",\"expiresInSeconds\":300,\"resendAfterSeconds\":30}"); break;
                case "SMS-1": reply(ex, 200, "{\"channel\":\"SMS\",\"destinationMasked\":\"+251******795\",\"expiresInSeconds\":300,\"resendAfterSeconds\":30}"); break;
                case "NOPE-1": reply(ex, 404, "{\"error\":\"invalid_credential_id\",\"error_description\":\"Unknown credential id\"}"); break;
                case "REVOKED-1": reply(ex, 410, "{\"error\":\"credential_not_active\"}"); break;
                case "NOCONTACT-1": reply(ex, 422, "{\"error\":\"no_registered_contact\"}"); break;
                case "WAIT-1": reply(ex, 429, "{\"error\":\"otp_recently_sent\"}"); break;
                case "SMTP-DOWN": reply(ex, 502, "{\"error\":\"otp_delivery_failed\"}"); break;
                case "BADJSON": reply(ex, 200, "this is not json"); break;
                case "NOCHANNEL": reply(ex, 200, "{}"); break;
                case "PIGEON": reply(ex, 200, "{\"channel\":\"PIGEON\",\"destinationMasked\":\"x\"}"); break;
                case "SLOW-1":
                    try { Thread.sleep(1500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                    reply(ex, 200, "{\"channel\":\"SMS\",\"destinationMasked\":\"+251******795\"}");
                    break;
                default: reply(ex, 404, "{\"error\":\"invalid_credential_id\"}");
            }
            return;
        }
        switch (id) {
            case "EMAIL-1": case "SMS-1": case "k7qm 2xpd 9tvr": // the real service normalises the typed code
                if ("123456".equals(otp)) {
                    reply(ex, 200, "{\"valid\":true,\"psut\":\"K7QM-2XPD-9TVR\"}"); // canonical code, not what was typed
                } else {
                    reply(ex, 200, "{\"valid\":false,\"reason\":\"otp_mismatch\"}");
                }
                break;
            case "NOPSUT": reply(ex, 200, "{\"valid\":true}"); break;
            case "NOPE-1": reply(ex, 404, "{\"error\":\"invalid_credential_id\"}"); break;
            case "ESC-1": reply(ex, 200, "{\"valid\":true,\"psut\":\"" + MiniJson.escape(otp) + "\"}"); break; // echoes what it received
            default: reply(ex, 200, "{\"valid\":false,\"reason\":\"otp_expired_or_not_requested\"}");
        }
    }

    static void reply(HttpExchange ex, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length);
        ex.getResponseBody().write(bytes);
        ex.close();
    }

    // ---- helpers ------------------------------------------------------------------------------------------
    static VcStoreAuthenticationService svc() {
        return new VcStoreAuthenticationService(baseUrl, KEY, 1000, 3000, "OTP", "email,phone");
    }

    static SendOtpDto otpRequest(String id) {
        SendOtpDto d = new SendOtpDto();
        d.setTransactionId("tx-1");
        d.setIndividualId(id);
        d.setOtpChannels(Arrays.asList("email", "phone"));
        return d;
    }

    static KycAuthDto authRequest(String id, String type, String challenge) {
        AuthChallenge c = new AuthChallenge();
        c.setAuthFactorType(type);
        c.setChallenge(challenge);
        c.setFormat("alpha-numeric");
        return new KycAuthDto("tx-1", id, new ArrayList<>(Collections.singletonList(c)));
    }

    // ---- sendOtp ------------------------------------------------------------------------------------------
    @Test
    void emailCredentialReportsAMaskedEmail() throws Exception {
        SendOtpResult r = svc().sendOtp("rp", "client", otpRequest("EMAIL-1"));
        assertEquals("tx-1", r.getTransactionId());
        assertEquals("r***@example.com", r.getMaskedEmail());
        assertNull(r.getMaskedMobile());
    }

    @Test
    void smsCredentialReportsAMaskedMobile() throws Exception {
        SendOtpResult r = svc().sendOtp("rp", "client", otpRequest("SMS-1"));
        assertEquals("+251******795", r.getMaskedMobile());
        assertNull(r.getMaskedEmail());
    }

    @Test
    void sendsTheClaimCodeWithTheInternalKeyAsJson() throws Exception {
        svc().sendOtp("rp", "client", otpRequest("  EMAIL-1 "));
        assertEquals("/v1/vault/internal/otp/send", lastPath);
        assertEquals(KEY, lastKeyHeader);
        assertEquals("application/json", lastContentType);
        assertEquals("EMAIL-1", MiniJson.parseObject(lastBody).get("credentialId"));
    }

    @Test
    void everyRefusalIsTheSameGenericError() {
        for (String id : new String[] {"NOPE-1", "REVOKED-1", "NOCONTACT-1", "WAIT-1", "SMTP-DOWN", "BADJSON", "NOCHANNEL", "PIGEON", "unknown-id"}) {
            SendOtpException e = assertThrows(SendOtpException.class, () -> svc().sendOtp("rp", "client", otpRequest(id)), id);
            assertEquals("send_otp_failed", e.getErrorCode(), id);
        }
    }

    @Test
    void blankOrMissingCodeIsRejectedWithoutCallingTheService() {
        assertThrows(SendOtpException.class, () -> svc().sendOtp("rp", "client", otpRequest("  ")));
        assertThrows(SendOtpException.class, () -> svc().sendOtp("rp", "client", otpRequest(null)));
        assertThrows(SendOtpException.class, () -> svc().sendOtp("rp", "client", null));
        assertNull(lastPath);
    }

    @Test
    void wrongInternalKeyIsRefusedAndNeverLeaks() {
        VcStoreAuthenticationService wrong = new VcStoreAuthenticationService(baseUrl, "another-internal-key-0123456789", 1000, 3000, "OTP", "email,phone");
        SendOtpException e = assertThrows(SendOtpException.class, () -> wrong.sendOtp("rp", "client", otpRequest("EMAIL-1")));
        assertEquals("send_otp_failed", e.getErrorCode());
        assertFalse(String.valueOf(e.getMessage()).contains("internal-key"));
    }

    @Test
    void unreachableServiceFailsFastAndGenerically() {
        VcStoreAuthenticationService down = new VcStoreAuthenticationService("http://127.0.0.1:1/v1/vault", KEY, 500, 1000, "OTP", "email,phone");
        assertEquals("send_otp_failed", assertThrows(SendOtpException.class, () -> down.sendOtp("rp", "client", otpRequest("EMAIL-1"))).getErrorCode());
        assertEquals("auth_failed", assertThrows(KycAuthException.class, () -> down.doKycAuth("rp", "client", authRequest("EMAIL-1", "OTP", "123456"))).getErrorCode());
    }

    @Test
    void slowServiceTimesOutInsteadOfHangingTheLogin() {
        VcStoreAuthenticationService quick = new VcStoreAuthenticationService(baseUrl, KEY, 500, 400, "OTP", "email,phone");
        long start = System.nanoTime();
        assertEquals("send_otp_failed", assertThrows(SendOtpException.class, () -> quick.sendOtp("rp", "client", otpRequest("SLOW-1"))).getErrorCode());
        long ms = (System.nanoTime() - start) / 1_000_000;
        assertTrue(ms < 1300, "gave up after " + ms + " ms");
    }

    // ---- doKycAuth ----------------------------------------------------------------------------------------
    @Test
    void correctOtpReturnsTheCanonicalCodeAsTheSubject() throws Exception {
        KycAuthResult r = svc().doKycAuth("rp", "client", authRequest("k7qm 2xpd 9tvr", "OTP", "123456"));
        assertEquals("K7QM-2XPD-9TVR", r.getPartnerSpecificUserToken()); // what the service says, not what was typed
        assertNotNull(r.getKycToken());
        assertEquals("/v1/vault/internal/otp/verify", lastPath);
        Map<String, Object> sent = MiniJson.parseObject(lastBody);
        assertEquals("k7qm 2xpd 9tvr", sent.get("credentialId"));
        assertEquals("123456", sent.get("otp"));
    }

    @Test
    void eachSuccessfulLoginGetsItsOwnKycToken() throws Exception {
        KycAuthResult a = svc().doKycAuth("rp", "client", authRequest("EMAIL-1", "OTP", "123456"));
        KycAuthResult b = svc().doKycAuth("rp", "client", authRequest("EMAIL-1", "OTP", "123456"));
        assertNotEquals(a.getKycToken(), b.getKycToken());
    }

    @Test
    void factorTypeMatchesIgnoringCaseAndSkipsOtherFactors() throws Exception {
        KycAuthDto dto = authRequest("EMAIL-1", "PIN", "9999");
        AuthChallenge otp = new AuthChallenge();
        otp.setAuthFactorType("otp");
        otp.setChallenge("123456");
        dto.getChallengeList().add(otp);
        assertEquals("K7QM-2XPD-9TVR", svc().doKycAuth("rp", "client", dto).getPartnerSpecificUserToken());
    }

    @Test
    void theDefaultFourArgumentOverloadDelegatesToTheSamePlugin() throws Exception {
        assertEquals("K7QM-2XPD-9TVR", svc().doKycAuth("rp", "client", false, authRequest("SMS-1", "OTP", "123456")).getPartnerSpecificUserToken());
    }

    @Test
    void wrongOtpUnknownCodeAndMissingSubjectAreAllAuthFailed() {
        for (Object[] c : new Object[][] {{"EMAIL-1", "000000"}, {"NOPE-1", "123456"}, {"NOPSUT", "123456"}, {"never-requested", "123456"}}) {
            KycAuthException e = assertThrows(KycAuthException.class,
                    () -> svc().doKycAuth("rp", "client", authRequest((String) c[0], "OTP", (String) c[1])), String.valueOf(c[0]));
            assertEquals("auth_failed", e.getErrorCode(), String.valueOf(c[0]));
        }
    }

    @Test
    void malformedRequestsNeverReachTheService() {
        assertEquals("invalid_auth_factor_type", assertThrows(KycAuthException.class, () -> svc().doKycAuth("rp", "client", authRequest("EMAIL-1", "PIN", "123456"))).getErrorCode());
        assertEquals("invalid_challenge", assertThrows(KycAuthException.class, () -> svc().doKycAuth("rp", "client", authRequest("EMAIL-1", "OTP", " "))).getErrorCode());
        assertEquals("auth_failed", assertThrows(KycAuthException.class, () -> svc().doKycAuth("rp", "client", authRequest(" ", "OTP", "123456"))).getErrorCode());
        KycAuthDto noList = new KycAuthDto("tx", "EMAIL-1", null);
        assertEquals("invalid_auth_factor_type", assertThrows(KycAuthException.class, () -> svc().doKycAuth("rp", "client", noList)).getErrorCode());
        assertEquals("auth_failed", assertThrows(KycAuthException.class, () -> svc().doKycAuth("rp", "client", null)).getErrorCode());
        assertNull(lastPath);
    }

    @Test
    void awkwardCharactersInTheOtpSurviveTheRoundTrip() throws Exception {
        String nasty = "a\"b\\c\n\t\u00fc \uD83D\uDE00 }{";
        // the fake service echoes the OTP it received back as the subject
        assertEquals(nasty, svc().doKycAuth("rp", "client", authRequest("ESC-1", "OTP", nasty)).getPartnerSpecificUserToken());
    }

    // ---- the rest of the SPI ------------------------------------------------------------------------------
    @Test
    void otpChannelsAreEmailAndPhoneByDefault() {
        VcStoreAuthenticationService s = svc();
        assertTrue(s.isSupportedOtpChannel("email"));
        assertTrue(s.isSupportedOtpChannel("PHONE"));
        assertTrue(s.isSupportedOtpChannel(" Email "));
        assertFalse(s.isSupportedOtpChannel("whatsapp"));
        assertFalse(s.isSupportedOtpChannel(null));
        assertTrue(new VcStoreAuthenticationService(baseUrl, KEY, 1000, 3000, "OTP", "sms").isSupportedOtpChannel("sms"));
    }

    @Test
    void userinfoIsNotSupportedAndNoKycCertificatesAreServed() throws Exception {
        assertEquals("not_implemented", assertThrows(KycExchangeException.class, () -> svc().doKycExchange("rp", "client", null)).getErrorCode());
        assertTrue(svc().getAllKycSigningCertificates().isEmpty());
    }

    // ---- configuration ------------------------------------------------------------------------------------
    @Test
    void badConfigurationStopsEsignetFromStarting() {
        assertThrows(IllegalStateException.class, () -> new VcStoreAuthenticationService("", KEY, 1000, 3000, "OTP", "email"));
        assertThrows(IllegalStateException.class, () -> new VcStoreAuthenticationService(null, KEY, 1000, 3000, "OTP", "email"));
        assertThrows(IllegalStateException.class, () -> new VcStoreAuthenticationService(baseUrl, "short", 1000, 3000, "OTP", "email"));
        assertThrows(IllegalStateException.class, () -> new VcStoreAuthenticationService(baseUrl, null, 1000, 3000, "OTP", "email"));
        assertThrows(IllegalStateException.class, () -> new VcStoreAuthenticationService("ftp://host/x", KEY, 1000, 3000, "OTP", "email"));
        assertThrows(IllegalStateException.class, () -> new VcStoreAuthenticationService("host-without-scheme", KEY, 1000, 3000, "OTP", "email"));
    }

    @Test
    void trailingSlashesOnTheBaseUrlAreHarmless() throws Exception {
        VcStoreAuthenticationService s = new VcStoreAuthenticationService(baseUrl + "///", KEY, 1000, 3000, "OTP", "email,phone");
        assertEquals("r***@example.com", s.sendOtp("rp", "client", otpRequest("EMAIL-1")).getMaskedEmail());
        assertEquals("/v1/vault/internal/otp/send", lastPath);
    }
}
