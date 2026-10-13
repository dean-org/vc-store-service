package org.openg2p.vcstore.config;

import java.util.Properties;
import org.openg2p.vcstore.otp.EmailSender;
import org.openg2p.vcstore.otp.HttpOtpSender;
import org.openg2p.vcstore.otp.LogEmailSender;
import org.openg2p.vcstore.otp.LogOtpSender;
import org.openg2p.vcstore.otp.OtpSender;
import org.openg2p.vcstore.otp.SmtpEmailSender;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSenderImpl;

/** The two OTP channels: email (SMTP) when the credential has an email, SMS otherwise. */
@Configuration
public class DeliveryConfig {

    @Bean
    OtpSender smsSender(VaultProperties props) {
        VaultProperties.Sender s = props.otp().sender();
        return "http".equalsIgnoreCase(s.type())
                ? new HttpOtpSender(s.url(), s.authToken())
                : new LogOtpSender(s.logOtp());
    }

    @Bean
    EmailSender emailSender(VaultProperties props) {
        VaultProperties.Email email = props.otp().email();
        if (!"smtp".equalsIgnoreCase(email.type())) {
            return new LogEmailSender(email.logOtp());
        }
        VaultProperties.Smtp smtp = email.smtp();
        if (smtp.host() == null || smtp.host().isBlank()) {
            throw new IllegalStateException(
                    "vault.otp.email.type=smtp needs an SMTP server: set VAULT_SMTP_HOST (and port / credentials)");
        }
        JavaMailSenderImpl mail = new JavaMailSenderImpl();
        mail.setHost(smtp.host());
        mail.setPort(smtp.port());
        if (smtp.username() != null && !smtp.username().isBlank()) {
            mail.setUsername(smtp.username());
            mail.setPassword(smtp.password());
        }
        Properties p = mail.getJavaMailProperties();
        p.put("mail.smtp.auth", String.valueOf(smtp.auth()));
        p.put("mail.smtp.starttls.enable", String.valueOf(smtp.starttls()));
        p.put("mail.smtp.ssl.enable", String.valueOf(smtp.ssl()));
        p.put("mail.smtp.connectiontimeout", "5000");
        p.put("mail.smtp.timeout", "10000");
        p.put("mail.smtp.writetimeout", "10000");
        return new SmtpEmailSender(mail, email.from());
    }
}
