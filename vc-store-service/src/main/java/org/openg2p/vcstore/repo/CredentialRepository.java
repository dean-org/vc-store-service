package org.openg2p.vcstore.repo;

import java.time.OffsetDateTime;
import java.util.Optional;
import org.openg2p.vcstore.crypto.VaultCrypto;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class CredentialRepository {

    private final JdbcTemplate jdbc;
    private final VaultCrypto crypto;

    public CredentialRepository(JdbcTemplate jdbc, VaultCrypto crypto) {
        this.jdbc = jdbc;
        this.crypto = crypto;
    }

    public Optional<StoredCredential> findById(String credentialId) {
        return jdbc
                .query(
                        """
                        SELECT credential_id, functional_record_id, config_id, credential_types, format,
                               vc_payload, encrypted, phone_payload, phone_masked, email_payload, email_masked,
                               status, expires_at,
                               download_count
                          FROM vc_vault.credential WHERE credential_id = ?
                        """,
                        (rs, i) -> {
                            String id = rs.getString("credential_id");
                            boolean encrypted = rs.getBoolean("encrypted");
                            String phonePayload = rs.getString("phone_payload");
                            String emailPayload = rs.getString("email_payload");
                            return new StoredCredential(
                                    id,
                                    rs.getString("functional_record_id"),
                                    rs.getString("config_id"),
                                    rs.getString("credential_types"),
                                    rs.getString("format"),
                                    encrypted ? crypto.decrypt(rs.getString("vc_payload"), id) : rs.getString("vc_payload"),
                                    phonePayload == null ? null : (encrypted ? crypto.decrypt(phonePayload, id) : phonePayload),
                                    rs.getString("phone_masked"),
                            emailPayload == null ? null : (encrypted ? crypto.decrypt(emailPayload, id) : emailPayload),
                            rs.getString("email_masked"),
                                    rs.getString("status"),
                                    rs.getObject("expires_at", OffsetDateTime.class),
                                    rs.getInt("download_count"));
                        },
                        credentialId)
                .stream()
                .findFirst();
    }

    /**
     * Atomically counts one download. Returns false when the credential is no longer ACTIVE or the
     * per-credential download limit (maxDownloads > 0) has been reached.
     */
    public boolean claimDownload(String credentialId, int maxDownloads) {
        return jdbc.update(
                        """
                        UPDATE vc_vault.credential
                           SET download_count = download_count + 1, last_downloaded_at = now()
                         WHERE credential_id = ? AND status = 'ACTIVE'
                           AND (? <= 0 OR download_count < ?)
                        """,
                        credentialId,
                        maxDownloads,
                        maxDownloads)
                == 1;
    }
}
