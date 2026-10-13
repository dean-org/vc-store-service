package org.openg2p.vcstore.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.HashSet;
import java.util.Set;
import org.openg2p.vcstore.config.VaultProperties;
import org.openg2p.vcstore.repo.CredentialRepository;
import org.openg2p.vcstore.repo.StoredCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * OID4VCI credential endpoint that SIGNS NOTHING: it returns the credential already stored in the vault.
 * The eSignet access token's `sub` is the vault credential id (set by the eSignet plugin after OTP login).
 */
@RestController
@RequestMapping("/credential")
public class CredentialController {
    private static final Logger log = LoggerFactory.getLogger(CredentialController.class);

    private final CredentialRepository credentials;
    private final ObjectMapper mapper;
    private final int maxDownloads;

    public CredentialController(CredentialRepository credentials, ObjectMapper mapper, VaultProperties props) {
        this.credentials = credentials;
        this.mapper = mapper;
        this.maxDownloads = props.credential().maxDownloads();
    }

    @PostMapping
    public ObjectNode credential(@AuthenticationPrincipal Jwt jwt, @RequestBody(required = false) JsonNode body) {
        String credentialId = jwt.getSubject();
        StoredCredential c = credentials.findById(credentialId)
                .orElseThrow(() -> new VaultException(HttpStatus.BAD_REQUEST, "invalid_credential_request", "No credential for this token"));
        if (!"ACTIVE".equals(c.status()) || c.expired()) {
            throw new VaultException(HttpStatus.BAD_REQUEST, "invalid_credential_request", "Credential is not available");
        }

        // The wallet asked for a credential type: it must be the one that is stored under this id.
        Set<String> requested = requestedTypes(body);
        if (!requested.isEmpty() && !c.typeSet().containsAll(requested)) {
            throw new VaultException(HttpStatus.BAD_REQUEST, "unsupported_credential_type",
                    "Requested credential type does not match the stored credential");
        }

        if (!credentials.claimDownload(credentialId, maxDownloads)) {
            throw new VaultException(HttpStatus.BAD_REQUEST, "invalid_credential_request", "Download limit reached");
        }

        try {
            ObjectNode response = mapper.createObjectNode();
            response.put("format", c.format());
            String vc = c.vcJson().trim();
            if (vc.startsWith("{")) {
                response.set("credential", mapper.readTree(vc)); // ldp_vc: a JSON object
            } else {
                response.put("credential", vc); // e.g. SD-JWT: a compact string
            }
            log.info("Served stored credential {} (client={})", credentialId, jwt.getClaimAsString("client_id"));
            return response;
        } catch (Exception e) {
            log.error("Stored credential {} is not valid JSON", credentialId, e);
            throw new VaultException(HttpStatus.INTERNAL_SERVER_ERROR, "server_error", "Stored credential is unreadable");
        }
    }

    private static Set<String> requestedTypes(JsonNode body) {
        Set<String> types = new HashSet<>();
        if (body == null) {
            return types;
        }
        JsonNode def = body.has("credential_definition") ? body.get("credential_definition") : body.get("credentialDefinition");
        if (def != null && def.has("type") && def.get("type").isArray()) {
            def.get("type").forEach(t -> types.add(t.asText()));
        }
        return types;
    }
}
