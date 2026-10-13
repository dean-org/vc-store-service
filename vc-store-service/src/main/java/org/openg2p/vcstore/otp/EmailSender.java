package org.openg2p.vcstore.otp;

/** Email delivery of the OTP. Throw a RuntimeException if the message could not be handed to the mail server. */
public interface EmailSender {
    void send(String toEmail, String subject, String body);
}
