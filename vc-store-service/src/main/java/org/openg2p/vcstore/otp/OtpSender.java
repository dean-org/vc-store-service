package org.openg2p.vcstore.otp;

/** Delivery channel for the OTP. Throw a RuntimeException if the message could not be handed off. */
public interface OtpSender {
    void send(String phoneE164, String message);
}
