package org.openg2p.vcstore.otp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Development sender: nothing is delivered. The OTP is logged only when log-otp=true. */
public class LogOtpSender implements OtpSender {
    private static final Logger log = LoggerFactory.getLogger(LogOtpSender.class);
    private final boolean logOtp;

    public LogOtpSender(boolean logOtp) {
        this.logOtp = logOtp;
        log.warn("LogOtpSender is active: OTPs are NOT delivered to phones. Configure vault.otp.sender.type=http.");
    }

    @Override
    public void send(String phoneE164, String message) {
        String masked = phoneE164.length() > 7
                ? phoneE164.substring(0, 4) + "*".repeat(phoneE164.length() - 7) + phoneE164.substring(phoneE164.length() - 3)
                : "***";
        if (logOtp) {
            log.info("[DEV OTP] to={} message={}", masked, message);
        } else {
            log.info("[DEV OTP] would send an OTP to {} (set vault.otp.sender.log-otp=true to print it)", masked);
        }
    }
}
