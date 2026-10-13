package org.openg2p.vcstore.otp;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** OTP generation and hashing. Only an HMAC of the OTP is ever stored. JDK-only. */
public final class OtpCodec {
    private static final SecureRandom RANDOM = new SecureRandom();

    private OtpCodec() {}

    public static String generate(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(RANDOM.nextInt(10));
        }
        return sb.toString();
    }

    /** HMAC-SHA256(pepper, credentialId + ":" + otp). Binding the id stops reuse across credentials. */
    public static String hash(String pepper, String credentialId, String otp) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(pepper.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal((credentialId + ":" + otp).getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static boolean matches(String expectedHash, String pepper, String credentialId, String otp) {
        return MessageDigest.isEqual(
                expectedHash.getBytes(StandardCharsets.UTF_8),
                hash(pepper, credentialId, otp).getBytes(StandardCharsets.UTF_8));
    }
}
