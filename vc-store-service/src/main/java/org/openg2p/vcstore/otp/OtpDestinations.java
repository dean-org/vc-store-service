package org.openg2p.vcstore.otp;

import org.openg2p.vcstore.repo.StoredCredential;

/** Decides where an OTP goes: the registered email if there is one, otherwise the registered phone (SMS). */
public final class OtpDestinations {

    public enum Channel { EMAIL, SMS }

    public record Destination(Channel channel, String address, String masked) {}

    private OtpDestinations() {}

    /** @return the destination, or null when the credential has neither an email nor a phone. */
    public static Destination choose(StoredCredential c) {
        if (c.email() != null && !c.email().isBlank()) {
            return new Destination(Channel.EMAIL, c.email().trim(), c.emailMasked());
        }
        if (c.phone() != null && !c.phone().isBlank()) {
            return new Destination(Channel.SMS, c.phone().trim(), c.phoneMasked());
        }
        return null;
    }
}
