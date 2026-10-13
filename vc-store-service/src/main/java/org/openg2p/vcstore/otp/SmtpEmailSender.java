package org.openg2p.vcstore.otp;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

/** Sends the OTP as a plain-text email through the configured SMTP server. */
public class SmtpEmailSender implements EmailSender {
    private final JavaMailSender mail;
    private final String from;

    public SmtpEmailSender(JavaMailSender mail, String from) {
        if (from == null || from.isBlank()) {
            throw new IllegalStateException("vault.otp.email.from (VAULT_MAIL_FROM) is required when email type is smtp");
        }
        this.mail = mail;
        this.from = from;
    }

    @Override
    public void send(String toEmail, String subject, String body) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(toEmail);
        message.setSubject(subject);
        message.setText(body);
        mail.send(message);
    }
}
