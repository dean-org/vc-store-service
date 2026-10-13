# openg2p-vc-store

Lets a farmer download a credential that has **already been signed and stored**, instead of triggering a new
issuance, after an eSignet login with a claim code and an OTP.

| Module | What it is | Runs in | Java |
|---|---|---|---|
| `vc-store-service` | Spring Boot service: sends/verifies OTPs (email or SMS) and serves the stored credential to Mimoto | its own container | 21 |
| `vcstore-esignet-plugin` | eSignet authenticator plugin: a JAR that forwards login calls to the service | **inside eSignet** | 11 |

They are two artifacts on purpose: the plugin must live in eSignet's JVM (Java 11, Spring Boot 2.3), the service
is a separate Spring Boot 3 / Java 21 application. One `mvn -B package` builds both.

```
Certify  signs + stores the VC (claim code K7QM-2XPD-9TVR, email/phone encrypted)   [certify_vc_vault.patch]
Portal   shows the claim code on the card                                           [portal_show_credential_id.patch]
Wallet ─► Mimoto ─► eSignet login: claim code + OTP ─► vcstore-esignet-plugin ─► vc-store-service ─► vault DB
         Mimoto ─► vc-store-service /credential (token sub = claim code) ─► the stored credential
```

## Set-up order

1. **Certify:** apply `certify_vc_vault.patch`, run `certify-vc_vault.sql`, set the `mosip.certify.vc-vault.*`
   properties (see `docs/vc-vault.md` in the patch). Rebuild Certify.
2. **Portal:** apply `portal_show_credential_id.patch`, rebuild. Add `{{claimCode}}` to the card if it is an SVG.
3. **vc-store-service:** build, deploy, set its variables (see `vc-store-service/README.md`).
4. **eSignet:** add `vcstore-esignet-plugin.jar` and its properties (see `vcstore-esignet-plugin/README.md`).
5. **Mimoto:** add an issuer entry whose `wellknown_endpoint` is the vc-store service's
   `/v1/vault/.well-known/openid-credential-issuer` and that uses the same eSignet client. *(Not written yet.)*

## Build

```
mvn -B package
# vc-store-service/target/vc-store-service-0.1.0.jar      (java -jar, Java 21)
# vcstore-esignet-plugin/target/vcstore-esignet-plugin.jar (copy into eSignet, Java 11)
```
