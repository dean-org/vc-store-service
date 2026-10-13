package org.openg2p.vcstore.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.File;
import java.io.IOException;
import org.openg2p.vcstore.config.VaultProperties;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Serves /.well-known/openid-credential-issuer. The credential configurations (display, claims, format)
 * come from a copy of Certify's own metadata; only the issuer, credential endpoint and authorization
 * server are rewritten to point at this service and eSignet.
 */
@RestController
@RequestMapping("/.well-known")
public class IssuerMetadataController {

    private final ObjectMapper mapper;
    private final VaultProperties props;
    private volatile ObjectNode cached;

    public IssuerMetadataController(ObjectMapper mapper, VaultProperties props) {
        this.mapper = mapper;
        this.props = props;
    }

    @GetMapping("/openid-credential-issuer")
    public ObjectNode metadata() {
        if (cached == null) {
            synchronized (this) {
                if (cached == null) {
                    cached = load();
                }
            }
        }
        return cached;
    }

    private ObjectNode load() {
        File file = new File(props.metadata().templatePath());
        try {
            ObjectNode node = (ObjectNode) mapper.readTree(file);
            String base = props.publicBaseUrl().replaceAll("/+$", "");
            node.put("credential_issuer", base);
            node.put("credential_endpoint", base + "/credential");
            ArrayNode servers = mapper.createArrayNode();
            servers.add(props.oidc().issuerUri());
            node.set("authorization_servers", servers);
            return node;
        } catch (IOException | ClassCastException e) {
            throw new VaultException(HttpStatus.INTERNAL_SERVER_ERROR, "server_error",
                    "Issuer metadata template is missing or invalid: " + file);
        }
    }
}
