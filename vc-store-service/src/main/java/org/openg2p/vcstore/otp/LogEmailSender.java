package org.openg2p.vcstore.otp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Development email sender: nothing is delivered. The body (with the OTP) is logged only when log-otp=true. */
public class LogEmailSender implements EmailSender {
    private static final Logger log = LoggerFactory.getLogger(LogEmailSender.class);
    private final boolean logOtp;

    public LogEmailSender(boolean logOtp) {
        this.logOtp = logOtp;
        log.warn("LogEmailSender is active: OTP emails are NOT delivered. Configure vault.otp.email.type=smtp.");
    }

    @Override
    public void send(String toEmail, String subject, String body) {
        int at = toEmail.indexOf('@');
        String masked = at > 0 ? toEmail.charAt(0) + "***" + toEmail.substring(at) : "***";
        if (logOtp) {
            log.info("[DEV OTP EMAIL] to={} subject={} body={}", masked, subject, body);
        } else {
            log.info("[DEV OTP EMAIL] would send an OTP email to {} (set vault.otp.email.log-otp=true to print it)", masked);
        }
    }
}
