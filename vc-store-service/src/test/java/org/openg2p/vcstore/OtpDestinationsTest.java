package org.openg2p.vcstore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.time.OffsetDateTime;
import org.junit.jupiter.api.Test;
import org.openg2p.vcstore.otp.OtpDestinations;
import org.openg2p.vcstore.otp.OtpDestinations.Channel;
import org.openg2p.vcstore.repo.StoredCredential;

class OtpDestinationsTest {
    private static StoredCredential cred(String email, String phone) {
        return new StoredCredential("K7QM-2XPD-9TVR", "FR-1", "Cfg", "A,B", "ldp_vc", "{}", phone,
                phone == null ? null : "+251******795", email, email == null ? null : "r***@example.com",
                "ACTIVE", OffsetDateTime.now().plusDays(1), 0);
    }

    @Test
    void emailWinsWhenPresent() {
        var d = OtpDestinations.choose(cred("ronald@example.com", "+251959031795"));
        assertEquals(Channel.EMAIL, d.channel());
        assertEquals("ronald@example.com", d.address());
        assertEquals("r***@example.com", d.masked());
    }

    @Test
    void smsWhenNoEmail() {
        assertEquals(Channel.SMS, OtpDestinations.choose(cred(null, "+251959031795")).channel());
        assertEquals(Channel.SMS, OtpDestinations.choose(cred("  ", "+251959031795")).channel());
    }

    @Test
    void noneWhenNoContact() {
        assertNull(OtpDestinations.choose(cred(null, null)));
    }
}
