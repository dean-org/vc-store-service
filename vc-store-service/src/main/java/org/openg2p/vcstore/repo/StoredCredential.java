package org.openg2p.vcstore.repo;

import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/** A vault row with the VC and phone already decrypted. Never log this object's fields. */
public record StoredCredential(
        String credentialId,
        String functionalRecordId,
        String configId,
        String credentialTypes,
        String format,
        String vcJson,
        String phone,
        String phoneMasked,
        String email,
        String emailMasked,
        String status,
        OffsetDateTime expiresAt,
        int downloadCount) {

    public Set<String> typeSet() {
        return Arrays.stream(credentialTypes.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());
    }

    public boolean expired() {
        return expiresAt != null && expiresAt.isBefore(OffsetDateTime.now());
    }

    @Override
    public String toString() {
        return "StoredCredential[" + credentialId + ", " + configId + ", " + status + "]";
    }
}
