package org.openg2p.vcstore.web;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.openg2p.vcstore.otp.OtpService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Called only by the eSignet authenticator plugin (X-Internal-Key). Never expose /internal/** through
 * the public ingress.
 */
@RestController
@RequestMapping("/internal/otp")
public class InternalOtpController {

    public record SendRequest(@NotBlank String credentialId) {}

    public record VerifyRequest(@NotBlank String credentialId, @NotBlank String otp) {}

    private final OtpService otp;

    public InternalOtpController(OtpService otp) {
        this.otp = otp;
    }

    @PostMapping("/send")
    public OtpService.SendResult send(@Valid @RequestBody SendRequest req) {
        return otp.send(req.credentialId());
    }

    @PostMapping("/verify")
    public OtpService.VerifyResult verify(@Valid @RequestBody VerifyRequest req) {
        return otp.verify(req.credentialId(), req.otp());
    }
}
