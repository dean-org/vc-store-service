package org.openg2p.vcstore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.openg2p.vcstore.crypto.VaultCrypto;
import org.openg2p.vcstore.otp.OtpCodec;
import org.openg2p.vcstore.repo.CredentialIds;

class CoreLogicTest {
    private static final String KEY = Base64.getEncoder().encodeToString(new byte[32]);

    @Test
    void cryptoRoundTripBindsCredentialId() {
        VaultCrypto c = new VaultCrypto(KEY);
        String ct = c.encrypt("{\"a\":1}", "K7QM-2XPD-9TVR");
        assertEquals("{\"a\":1}", c.decrypt(ct, "K7QM-2XPD-9TVR"));
        assertThrows(IllegalStateException.class, () -> c.decrypt(ct, "AAAA-BBBB-CCCC"));
    }

    @Test
    void otpIsBoundToCredentialAndPepper() {
        String h = OtpCodec.hash("pepper-0123456789abc", "K7QM-2XPD-9TVR", "123456");
        assertTrue(OtpCodec.matches(h, "pepper-0123456789abc", "K7QM-2XPD-9TVR", "123456"));
        assertFalse(OtpCodec.matches(h, "pepper-0123456789abc", "K7QM-2XPD-9TVR", "000000"));
        assertFalse(OtpCodec.matches(h, "pepper-0123456789abc", "ZZZZ-ZZZZ-ZZZZ", "123456"));
        assertFalse(OtpCodec.matches(h, "another-pepper-0123", "K7QM-2XPD-9TVR", "123456"));
    }

    @Test
    void idsAreNormalised() {
        String id = "K7QM-2XPD-9TVR";
        assertEquals(id, CredentialIds.normalize(id));
        assertEquals(id, CredentialIds.normalize(" k7qm2xpd9tvr "));
        assertEquals(id, CredentialIds.normalize("k7qm 2xpd 9tvr"));
        assertEquals(id, CredentialIds.normalize("urn:openg2p:credential:K7QM-2XPD-9TVR"));
    }
}
