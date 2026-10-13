# vc-store-service

Serves **already-signed** credentials from the `vc_vault` database to wallets (via Mimoto) after an
eSignet OTP login. It signs nothing and never calls Certify.

```
Certify signs the VC ─► stores it in vc_vault.credential (same database, inji_certify)
Wallet ─► Mimoto ─► eSignet login (credential id + OTP, custom plugin ─► this service /internal/otp/*)
          eSignet token: sub = claim code (e.g. K7QM-2XPD-9TVR)
Mimoto ─► POST /v1/vault/credential (Bearer token) ─► stored VC  {"format","credential"}
```

The table and grants come from Certify's `db_scripts/inji_certify/ddl/certify-vc_vault.sql`
(Certify writes, this service reads). Create a `vaultuser` role and point `VAULT_DB_*` at the same
`inji_certify` database.

## Endpoints (context path `/v1/vault`)

| Endpoint | Caller | Auth |
|---|---|---|
| `POST /internal/otp/send` `{credentialId}` -> `{channel, destinationMasked, expiresInSeconds, resendAfterSeconds}` | eSignet plugin | `X-Internal-Key` |
| `POST /internal/otp/verify` `{credentialId, otp}` -> `{valid, reason, psut}` | eSignet plugin | `X-Internal-Key` |
| `POST /credential` | Mimoto | eSignet access token (signature, issuer, audience) |
| `GET /.well-known/openid-credential-issuer` | Mimoto / wallets | none |
| `GET /actuator/health` | k8s | none |

`/internal/**` must NOT be routed through the public ingress.

## Configuration (env)

| Variable | Notes |
|---|---|
| `VAULT_DB_HOST/PORT/NAME/USER/PASSWORD` | Certify's database (`inji_certify`) with the `vaultuser` role |
| `VAULT_ENCRYPTION_KEY` | base64 of 32 bytes, **identical to Certify's** `mosip.certify.vc-vault.encryption-key` |
| `VAULT_INTERNAL_API_KEY` | >= 16 chars, shared with the eSignet plugin. Service refuses to start without it |
| `VAULT_OTP_PEPPER` | >= 16 chars. Service refuses to start without it |
| `VAULT_OIDC_ISSUER_URI` | `iss` of eSignet access tokens |
| `VAULT_OIDC_JWK_SET_URI` | eSignet JWKS |
| `VAULT_OIDC_ALLOWED_AUDIENCES` | the value(s) eSignet puts in the token's `aud` |
| `VAULT_PUBLIC_BASE_URL` | how Mimoto reaches this service, ending in `/v1/vault` |
| `VAULT_METADATA_TEMPLATE` | path to a copy of Certify's well-known JSON (see below) |
| `VAULT_OTP_SENDER` | SMS channel: `log` (dev, delivers nothing) or `http` |
| `VAULT_OTP_SENDER_URL` / `_TOKEN` | for `http`: POSTs `{"to","message"}`; adapt `HttpOtpSender` to your gateway |

Metadata template: save Certify's own document and mount it, e.g.
`curl https://certify.dev.openg2p.test/v1/certify/.well-known/openid-credential-issuer > issuer-metadata.json`
(the path is `.well-known/openid-credential-issuer` under Certify's `/v1/certify`; confirm on your deployment).
Only `credential_issuer`, `credential_endpoint` and `authorization_servers` are rewritten.

## OTP delivery: email first, SMS otherwise

When a credential is stored, Certify keeps the holder's email and phone (encrypted). To send an OTP this service
uses **the registered email if there is one, otherwise SMS to the registered phone**; no contact at all gives
`422 no_registered_contact`. If the chosen channel fails the OTP is discarded and `502 otp_delivery_failed` is
returned: there is no silent switch to the other channel.

| Variable | Notes |
|---|---|
| `VAULT_OTP_EMAIL_TYPE` | `smtp` (default) or `log` (dev, delivers nothing) |
| `VAULT_SMTP_HOST` / `VAULT_SMTP_PORT` | required for `smtp`; the service refuses to start without a host |
| `VAULT_SMTP_USERNAME` / `VAULT_SMTP_PASSWORD` | optional |
| `VAULT_SMTP_AUTH` / `VAULT_SMTP_STARTTLS` / `VAULT_SMTP_SSL` | defaults `true` / `true` / `false` |
| `VAULT_MAIL_FROM` | sender address, required for `smtp` |

Local mail catcher such as Mailpit or MailHog: `VAULT_SMTP_HOST=<host> VAULT_SMTP_PORT=1025 VAULT_SMTP_AUTH=false VAULT_SMTP_STARTTLS=false`.

## Behaviour worth knowing

- OTP: 6 digits, 5 min, 5 attempts, one OTP per 30 s, 5 per hour per credential; only an HMAC is stored.
- The credential id is the short claim code Certify generated (`K7QM-2XPD-9TVR`); it is bound into the AES-GCM encryption, so rows cannot be swapped.
- Codes are accepted in any case, with or without dashes/spaces, or as the full VC id (`urn:openg2p:credential:K7QM-...`).
- The wallet's `proof` JWT is **not** used: the stored VC is bound to the key used at issuance, not the wallet's.
- `vault.credential.max-downloads` (0 = unlimited) limits downloads per credential id.
- A requested `credential_definition.type` must match the stored credential's types.

## Build

```
mvn -B package        # Java 21, Spring Boot 3.2.3 (same as inji-certify 0.14.0)
docker build -t vc-store-service .
```
