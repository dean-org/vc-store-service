# vcstore-esignet-plugin

An eSignet `Authenticator` plugin. It lets a farmer log in to eSignet with the **claim code** printed on the
credential card plus an **OTP** (sent by email if the credential has an email, otherwise by SMS), and makes the
claim code the access token's `sub`. It holds no data of its own: every call goes to the **vc-store service**.

This is *not* the vc-store service. The plugin is a small JAR that runs **inside eSignet's JVM** (Java 11);
the vc-store service is a separate Spring Boot application.

```
eSignet login page                      this plugin                         vc-store service
 farmer types claim code ─► sendOtp    ─► POST /internal/otp/send   ─────►  picks email or SMS, sends the OTP
 farmer types OTP        ─► doKycAuth  ─► POST /internal/otp/verify ─────►  checks the OTP
                                         returns psut = claim code  ◄─────
 eSignet token:  sub = claim code   ─►  Mimoto ─► vc-store /credential ─►  returns the stored credential
```

## Build

```
mvn -B package                                  # from the project root: builds both modules
# or only the plugin:
mvn -B -pl vcstore-esignet-plugin package       # -> vcstore-esignet-plugin/target/vcstore-esignet-plugin.jar
```

The plugin is compiled for **Java 11 / eSignet 1.6.2** and bundles nothing: eSignet already provides everything
it uses. To target another eSignet version: `-Designet.version=<version>`.
If Maven cannot find `io.mosip.esignet:esignet-integration-api`, build it from the eSignet source once
(`mvn -pl esignet-integration-api -am install -DskipTests` in the eSignet project) and retry.

## Install into eSignet

Use either way the eSignet image supports:

* **Mount the jar** into the container at `/home/mosip/plugins/` and set the environment variable
  `plugin_name_env=vcstore-esignet-plugin.jar`. At start-up eSignet copies it to its class path.
* Or build it into an `esignet-with-plugins` image.

## eSignet configuration

```properties
# which authenticator eSignet uses, and where Spring finds it
mosip.esignet.integration.authenticator=VcStoreAuthenticationService
mosip.esignet.integration.scan-base-package=org.openg2p.esignet.vcstore

# the vc-store service (reachable from eSignet; do not expose /internal/** publicly)
mosip.esignet.vcstore.base-url=http://vc-store-service/v1/vault
mosip.esignet.vcstore.internal-api-key=<same value as VAULT_INTERNAL_API_KEY on the vc-store service, 16+ chars>

# optional (defaults shown)
mosip.esignet.vcstore.connect-timeout-ms=3000
mosip.esignet.vcstore.read-timeout-ms=10000
mosip.esignet.vcstore.otp-auth-factor=OTP
mosip.esignet.vcstore.supported-otp-channels=email,phone
```

eSignet refuses to start if the base URL or the key is missing or malformed.

## Things you must also check (not covered by this plugin)

1. **OTP login must be offered.** eSignet maps an ACR to an auth factor in `amr_acr_mapping.json`:
   `mosip:idp:acr:generated-code` -> `OTP`. The authorization request sent by the wallet must ask for an ACR
   that maps to OTP, and the eSignet **client registration** for Mimoto (`authContextRefs`) must allow it. I could
   not find where Inji Web sets `acr_values` (it is not in the Mimoto backend): look at the authorization URL the
   wallet opens.
2. **The login page.** eSignet's server only requires the individual id to be non-blank, so `K7QM-2XPD-9TVR` is
   accepted. The login page is a separate project (oidc-ui) that was not in the files I had; if it restricts the
   input (for example digits only), relax that for this client.
3. **`sub` is the claim code.** Mimoto sends the token to the vc-store service, which reads `sub` to find the
   credential. Nothing else needs configuring for that.

## Behaviour

* **Send OTP:** forwards the typed code. The vc-store service decides email or SMS; the plugin reports the masked
  address as `maskedEmail` or `maskedMobile`, so the login page shows where it went.
* **Verify:** the OTP is checked by the vc-store service (5 attempts, 5 minutes). On success the plugin returns the
  *canonical* claim code from the service (whatever case or dashes the farmer typed) as the user token.
* **Errors:** every refusal on the OTP request is the same `send_otp_failed`, and every failed login is
  `auth_failed`, whether the code is unknown, revoked, has no contact, is throttled or the service is down. A more
  specific error would let anyone probe which claim codes exist. Details are in eSignet's log.
* **Timeouts:** a slow or down vc-store service fails the login within the configured timeouts instead of hanging.
* **Not supported:** the userinfo endpoint (`doKycExchange` returns `not_implemented`). Wallets get the credential
  from the vc-store service, not from eSignet user claims.
* The internal key is sent as `X-Internal-Key`, redirects are never followed, and the key is never logged.

## Tests

`mvn test` runs 24 tests, including ones against a real local HTTP server that plays the vc-store service
(timeouts, wrong key, unreachable service, odd characters in the OTP, error mapping).
