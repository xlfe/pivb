# pivb

`pivb` turns a touch-gated, non-exportable RSA-2048 key in YubiKey PIV slot `9c`
into Google Cloud credentials through Workload Identity Federation. The daemon is
a **networkless signer**: it mints five-minute RS256 OIDC subject tokens and
nothing else. A trusted Google auth library runs `pivb subject-token`, receives the
assertion on stdout, and performs the STS exchange and service-account
impersonation itself.

pivbd never receives, caches, returns, or logs a Google access token, STS response,
or Google-issued ID token. It has no AF_INET socket, no Google HTTP client, and no
TCP listener. The only state it holds is the cached PIV PIN and the metadata of the
last signature.

```text
trusted app → Google auth library → exec `pivb subject-token --alias ro`
                                        ↓ HTTP over $XDG_RUNTIME_DIR/pivb/wif.sock
                                    pivbd → one ephemeral PIV session → RS256 signature
                                        ↓ five-minute assertion on helper stdout
        Google auth library → STS → IAM Credentials impersonation → target access token
```

The daemon runs as a systemd **user** service and exposes two same-UID sockets
under `$XDG_RUNTIME_DIR/pivb` (directory `0700`, sockets `0600`):

| Socket | API | Holder |
|---|---|---|
| `control.sock` | health, status, unlock, lock | trusted interactive session |
| `wif.sock` | mint one configured subject token | trusted host auth helper |

Both enforce Linux `SO_PEERCRED` same-real-UID checks, request deadlines, and body
limits. **The peer check cannot distinguish two processes running as the same host
UID.** Every unsandboxed process in your user session is inside the trust boundary.
Agent sandboxes must be excluded by mount and network isolation, not by this check —
see [Agent sandboxes](#agent-sandboxes).

A trusted launcher may create one additional, ephemeral `0600` socket with
`pivb agent-session`. That relay has one fixed alias and no alias-selection field;
mounting that one socket is the delegated capability. It is owned by the
supervisor process, not pivbd, and disappears with the supervised launcher.

### What this design guarantees

1. No pivb TCP listener exists, on loopback or any other interface.
2. pivbd holds only the cached PIV PIN and short-lived signing inputs. It holds no
   Google bearer token.
3. The only credential pivbd can mint is a short-lived OIDC assertion for a known
   provider, alias, target service account, and enrolled key.
4. A subject token minted for one alias cannot impersonate another alias's target,
   even if the assertion is copied before it expires.
5. The target Google access token lasts at most one hour and is owned by the
   requesting auth library or tool, never by pivbd.
6. A lost YubiKey is disabled by removing its JWK; new exchanges with that card
   then fail, and already-issued Google tokens expire naturally within the hour.
7. PIV touch and PIN behavior stays recognizable to the operator. No browser login
   and no exportable private key is introduced.

One further property depends on the machine configuration rather than on this
repository: an agent sandbox can reach only the single explicitly delegated
agent-session socket, cannot reach raw pivb or the YubiKey, and cannot escape to a
host process that can — provided the [sandbox contract](#agent-sandboxes) is
deployed. Until its complete production-launcher suite passes, the [interim
operating rule](#interim-operating-rule) applies.

**Out of scope:** kernel or root compromise, physical attacks on the YubiKey,
revoking an already-issued Google access token (Google has no API for it), AWS and
Azure support, and hosting a public OIDC discovery endpoint.

### Why executable-sourced WIF

Four other credential sources were considered and rejected. A secret header on the
metadata emulator still leaves an ambient access-token endpoint reachable through
shared loopback, and the secret has to reach every client. A WIF **URL source** on
localhost recreates that endpoint under a different protocol. A WIF **file source**
requires continuously writing a bearer subject token to disk. A WIF **X.509
source** needs certificate and private-key file paths, which a non-exportable PIV
key cannot provide without custom PKCS#11/mTLS integration and much narrower
client-library support.

The **executable source** works with the existing on-card keys, adds no local
network service and no token file, and is supported by the Google auth libraries
and gcloud. It is not self-securing: Google explicitly warns that any process able
to run the executable receives the credential on stdout. The sandbox boundary is
therefore a required part of this design, not defense in depth.

## Build and test

```console
nix build
nix develop --command go test ./...
```

The flake builds `pivb` with cgo against `pcsclite`, builds
`pivb-agent-subject-token` separately with `CGO_ENABLED=0` as a fully static
executable, and installs the user unit at `lib/systemd/user/pivb.service`. Go
dependencies are vendored so the build is network-independent. For a local
development build inside `nix develop`:

```console
go build ./cmd/pivb ./cmd/pivb-agent-subject-token
```

## Configure

Copy [`config.example.toml`](config.example.toml) to `~/.config/pivb/config.toml`:

```toml
piv_slot = "9c"
pin_cache = "session" # or "never": consume the cached PIN on each mint
notify_cmd = ["notify-send", "pivb"] # [] disables desktop notifications

[wif]
project_number = "123456789012"
pool_id = "pivb"
provider_id = "yubikey-piv"
issuer_uri = "https://auth.example.net/pivb/replace-with-deployment-id"

[keys.12345678]
jwk_kid = "replace-with-43-char-base64url-spki-digest0"

[keys.23456789]
jwk_kid = "replace-with-43-char-base64url-spki-digest1"

[aliases.ro]
cloud = "gcp" # optional; gcp is the only supported value
target = "readonly-sa@example-project-id.iam.gserviceaccount.com"
lifetime_s = 3600 # target access-token lifetime, 600..3600

[aliases.deploy]
target = "deployment-sa@example-project-id.iam.gserviceaccount.com"
lifetime_s = 3600
```

The schema is closed and fail-closed. Unknown keys are fatal, and every
identity-bearing value must match a conservative grammar before it can reach a
signed claim or a generated Google artifact:

- `piv_slot` must be `"9c"`; `pin_cache` must be `"session"` or `"never"`.
- `wif.project_number` is the nonzero decimal **project number**, not the project ID.
- `wif.pool_id` and `wif.provider_id` are 4–32 lowercase letters, digits, or
  hyphens, start with a letter, end with a letter or digit, and may not start with
  `gcp-` (Google reserves that prefix).
- `wif.issuer_uri` is HTTPS with a host, no user info, no query, no fragment, and
  is not a Google-owned domain. It is a durable trust-domain identifier; no
  metadata endpoint is hosted there, but the value must never be reused by another
  trust domain.
- `[keys.<serial>]` uses a positive integer YubiKey serial. `jwk_kid` is the
  43-character unpadded base64url SHA-256 of the slot-9c public key's DER
  SubjectPublicKeyInfo. Serials and kids must be unique, and at most **8** keys may
  be enrolled — Google's uploaded-JWK limit per OIDC provider.
- Alias names are 1–32 lowercase letters, digits, or hyphens, starting with a
  letter. `target` must be a `<name>@<project-id>.iam.gserviceaccount.com` address
  and must be unique across aliases: one alias, one target service account.
- `lifetime_s` is 600 through 3600 seconds. One hour is a security cap and is not
  raisable even where an organization policy permits twelve-hour tokens.

Only RSA-2048/RS256 is supported. The audiences are derived from
`project_number`/`pool_id`/`provider_id` and are never configured as free-form
strings.

### PIN caching

- `session`: retain the verified PIN in daemon RAM until `pivb lock` or restart.
- `never`: consume the cached PIN on the next signature, requiring `pivb unlock`
  before every subject token.

The PIN is zeroized on lock and after a failed cross-card verification. The serial
and its matching `jwk_kid` are resolved inside the same PIV session that signs, so
any enrolled fleet key works without editing config or restarting pivb. Set the
same PIV PIN on every fleet key for seamless swaps. If a swapped key rejects the
cached PIN, pivb spends at most one attempt, clears the cache, and asks you to run
`pivb unlock` with that key inserted.

### Retired configuration

`listen_metadata`, `default_alias`, `remote_allowed_aliases`, and any `broker_sa`,
`key_id`, `yubikey_serials`, `project_id`, or `numeric_project_id` key fail with one
migration error pointing back at this document:

```console
$ pivb serve
pivb: config key(s) listen_metadata belong to the retired metadata/broker architecture and are no longer supported; migrate to the Workload Identity Federation schema described in README.md
```

There is no compatibility shim. Silently accepting old trust configuration risks
running the wrong credential path.

## One-time YubiKey setup

Key generation is unchanged from the broker architecture. **Do not regenerate
existing slot `9c` keys to migrate** — exporting their public certificates again is
enough. For a new card (the example uses placeholder serial `12345678`):

```console
ykman piv access change-pin
ykman piv access change-puk
ykman piv access change-management-key --generate --protect

ykman piv keys generate --algorithm RSA2048 --pin-policy ONCE --touch-policy ALWAYS 9c pub.pem
ykman piv certificates generate --subject "CN=pivb-yk-12345678" --valid-days 730 9c pub.pem
ykman piv certificates export 9c cert-12345678.pem
```

Google validates the uploaded JWK, not the X.509 chain, subject, or certificate
lifetime. The certificate is only a transport for the public key.

## Provision the WIF provider

Set these once for the whole provisioning sequence:

```bash
export WIF_PROJECT_ID=…          # project hosting the pool
export WIF_PROJECT_NUMBER=…      # numeric; must equal wif.project_number
export POOL_ID=pivb              # must equal wif.pool_id
export PROVIDER_ID=yubikey-piv   # must equal wif.provider_id
export ISSUER_URI=…              # must equal wif.issuer_uri
```

Each of these must match `~/.config/pivb/config.toml` character for character.
The project number, pool, provider, and issuer are all baked into every signed
assertion; a mismatch fails at STS with an unhelpful error rather than a useful
one. `pivb wif provider-condition` prints the derived values so you can compare.

```console
gcloud services enable iam.googleapis.com iamcredentials.googleapis.com \
  sts.googleapis.com cloudresourcemanager.googleapis.com --project="$WIF_PROJECT_ID"

gcloud iam workload-identity-pools create "$POOL_ID" \
  --project="$WIF_PROJECT_ID" \
  --location=global \
  --display-name="pivb YubiKeys"
```

### Build the JWKS

You need every enrolled card in hand for this step. Export each card's public
certificate — do **not** regenerate the slot `9c` keys:

```console
ykman piv certificates export 9c cert-12345678.pem     # repeat per card
```

Then, with all certificates present in one invocation:

```console
pivb wif jwks \
  --cert 12345678=cert-12345678.pem \
  --cert 23456789=cert-23456789.pem \
  > jwks.json
```

`pivb wif jwks` fails unless every input is an RSA-2048/F4 certificate in a
single-block PEM file, every serial and derived kid is unique, the set has 1–8
keys, and the derived kids match the configured `[keys.<serial>]` entries exactly
— in both directions. A configured serial with no certificate is an error too,
because a provider update **replaces the entire uploaded JWKS**: a partial set
would silently revoke the cards you left out.

**Keep a copy of every JWKS you upload.** Rollback means re-uploading a known-good
set, and the file contains no secret material.

**Bootstrap:** you do not know the kids before the first run, so leave the
43-character placeholders from `config.example.toml` in place — they satisfy the
grammar so the config loads — and let the command report the real value:

```console
$ pivb wif jwks --cert 12345678=cert-12345678.pem --cert 23456789=cert-23456789.pem
pivb: YubiKey 12345678 certificate derives jwk_kid "g4tW--9GFcDvwdryp8vTG76EyUg-QhfOEjBo0YQg3Wg" but [keys.12345678] is configured with "replace-with-43-char-base64url-spki-digest0"; enroll the new key deliberately or use the matching certificate
```

Copy the derived kid into `[keys.12345678].jwk_kid` and re-run. The command reports
**one card per invocation**, in ascending serial order, so a fresh three-card
enrollment takes three runs before it prints the JWKS. That refusal to guess is
also the runtime protection: a replaced key on a known physical serial is not
trusted until its new JWK and config are deliberately rolled out.

### Create the provider

`pivb wif provider-condition` prints every derived value, including the two gcloud
flags, generated from your checked-in config:

```console
$ pivb wif provider-condition
# provider resource
projects/123456789012/locations/global/workloadIdentityPools/pivb/providers/yubikey-piv

# external-account audience (credential files, STS)
//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/pivb/providers/yubikey-piv

# OIDC audience (assertion aud claim)
https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/pivb/providers/yubikey-piv

# issuer
https://auth.example.net/pivb/replace-with-deployment-id

# gcloud --attribute-mapping
google.subject=assertion.sub,attribute.alias=assertion.alias,attribute.target=assertion.target,attribute.serial=assertion.serial,attribute.key_id=assertion.key_id

# gcloud --attribute-condition
assertion.iss == 'https://auth.example.net/pivb/replace-with-deployment-id' &&
assertion.aud == 'https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/pivb/providers/yubikey-piv' &&
assertion.sub.startsWith('pivb-key:') &&
(
  (assertion.alias == 'deploy' && assertion.target == 'deployment-sa@example-project-id.iam.gserviceaccount.com') ||
  (assertion.alias == 'ro' && assertion.target == 'readonly-sa@example-project-id.iam.gserviceaccount.com')
)
```

Review the condition, then create the provider with it:

```console
gcloud iam workload-identity-pools providers create-oidc "$PROVIDER_ID" \
  --project="$WIF_PROJECT_ID" \
  --location=global \
  --workload-identity-pool="$POOL_ID" \
  --issuer-uri="$ISSUER_URI" \
  --jwk-json-path=jwks.json \
  --attribute-mapping="$ATTRIBUTE_MAPPING" \
  --attribute-condition="$ATTRIBUTE_CONDITION"
```

The condition pins the exact issuer and audience, requires the `pivb-key:` subject
namespace, and allowlists explicit alias-to-target pairs. Regenerate and reapply it
whenever an alias is added, removed, or retargeted.

### Grant impersonation per alias

For each alias, grant `roles/iam.workloadIdentityUser` on **only that alias's
target service account** to the alias attribute principal set:

```console
gcloud iam service-accounts add-iam-policy-binding \
  readonly-sa@example-project-id.iam.gserviceaccount.com \
  --project=example-project-id \
  --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/$WIF_PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL_ID/attribute.alias/ro"
```

> **Never grant `roles/iam.workloadIdentityUser` to the whole pool** — that is any
> member of the form `principalSet://…/workloadIdentityPools/$POOL_ID/*`, and it is
> the most damaging mistake available in this procedure. Three independent controls
> stop a token minted for `ro` from impersonating `deploy`: the `alias` and `target`
> claims in the assertion, the provider attribute condition, and this per-target
> binding. A pool-wide grant collapses all three at once — every card could then
> reach every target, and the alias claim becomes decorative.

Verify what you actually created before moving on:

```console
gcloud iam service-accounts get-iam-policy \
  readonly-sa@example-project-id.iam.gserviceaccount.com --format=json
```

Each policy must name exactly one `attribute.alias/<name>` principal set and no
`/*` member.

### Audit logging

Enable STS and IAM Credentials data-access logs now, before the canary. The
identity in the audit trail changes shape at cutover: it was a dedicated broker
service-account principal, and becomes the WIF principal subject plus mapped
attributes. Confirm you can correlate `sub`, `serial`, `key_id`, alias, and target
for **every card** — that correlation is what makes a lost card actionable, and it
must work before the old broker accounts are deleted.

## Credential files

Generate one external-account file per alias — the impersonation URL is static in
the JSON, so there is no daemon-global "active alias":

```console
pivb wif credentials \
  --alias ro \
  --output ~/.config/pivb/credentials/ro.json \
  --executable /run/current-system/sw/bin/pivb
```

The file is written atomically as `0600` with parent directories `0700`:

```json
{
  "type": "external_account",
  "audience": "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/pivb/providers/yubikey-piv",
  "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
  "token_url": "https://sts.googleapis.com/v1/token",
  "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/readonly-sa@example-project-id.iam.gserviceaccount.com:generateAccessToken",
  "service_account_impersonation": {
    "token_lifetime_seconds": 3600
  },
  "credential_source": {
    "executable": {
      "command": "/run/current-system/sw/bin/pivb subject-token --alias ro",
      "timeout_millis": 30000
    }
  }
}
```

`--executable` must be an absolute path with no whitespace or control characters,
and pivb rejects a hashed `/nix/store/...` path outright: generated credentials
must survive a NixOS rebuild. The generator takes the audience, target, and
lifetime from config and never accepts a caller-supplied impersonation URL. The
credential source deliberately contains no `output_file` — caching subject tokens
on disk is prohibited, and the helper refuses to run if a hand-edited file sets
`GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE`.

The file holds no private key and no bearer token, but its `command` decides which
executable receives credential requests. Treat it as tamper-sensitive.

[Google documents `GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL` as present when
service-account impersonation is used](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-other-providers#executable-sourced-credentials).
Current Google Auth Python instead
[constructs the source credential without the impersonation URL](https://github.com/googleapis/google-cloud-python/blob/f1213c311d6b8d96e46763cb0e3cff8b68f72f70/packages/google-auth/google/auth/external_account.py#L631-L638),
then [injects the email only when that URL is present](https://github.com/googleapis/google-cloud-python/blob/f1213c311d6b8d96e46763cb0e3cff8b68f72f70/packages/google-auth/google/auth/pluggable.py#L348-L361).
The executable therefore does not receive the email on Python's impersonated
credential path. pivb validates the variable exactly when a client supplies it;
when it is absent, pivb derives the target from the selected alias in its closed
configuration. No manual email override is required.

Trusted non-gcloud client environment in Fish:

```fish
set -lx GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES 1
set -lx GOOGLE_APPLICATION_CREDENTIALS "$HOME/.config/pivb/credentials/ro.json"
```

For gcloud, use the credential-file override directly:

```fish
set -lx GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES 1
set -lx CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE "$HOME/.config/pivb/credentials/ro.json"
```

gcloud maintains its own access-token cache, so `~/.config/gcloud` is a credential
store and must be hidden from agent sandboxes.

**Google-issued ID tokens** come from the client library's ID-token support layered
on the external-account credential, never from pivb. pivbd is not involved after
issuing the subject token. If a deployed client cannot build ID-token credentials
from executable-sourced WIF plus impersonation, upgrade that client; do not restore
a local identity-token endpoint.

Long-running processes cache their Google access token. Changing an environment
variable or symlink does not revoke a credential a process already holds.

## Canary the clients before cutover

Executable-sourced WIF support is **version-dependent**, so this step decides your
schedule more often than any other. A synthetic parser test proves nothing: test
the production dependency graph with a real request, against the real provider,
before removing the old credential path.

```fish
set -lx GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES 1
set -lx CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE "$HOME/.config/pivb/credentials/ro.json"
set -e GCE_METADATA_HOST GCE_METADATA_IP GCE_METADATA_ROOT
```

- **gcloud** — perform a real, permitted Google API request through the
  credential-file override shown above. Do not set
  `GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL` manually.
- **The JVM backend**, with its real dependency tree. Old transitive
  `google-auth-library-oauth2-http` versions are the usual failure. If a deployed
  client cannot build the credential, **upgrade that client before cutover** —
  do not restore a local endpoint as a workaround.
- **Every ID-token consumer and audience**, not only access-token APIs. Google-issued
  ID tokens now come from the client library's ID-token support layered on the
  external-account credential; pivb is not involved after issuing the subject token.
  A consumer that cannot construct ID-token credentials from executable-sourced WIF
  plus impersonation needs upgrading too.

**Record the exact versions** of gcloud and every Google auth library you tested,
and whether each client supplied `GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL` to
the executable. That record is what later tells you whether a dependency bump is
safe.

Then prove the boundary rather than assuming it:

- Run the negative canary specifically through gcloud/Python: copy `ro.json`, edit
  only the copy's impersonation URL to `deploy`'s target service account, point
  `CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE` at the copy, and make a request. Python
  omits the email variable, so every local tripwire passes and pivb still signs the
  configured `ro` alias/target pair. STS should accept that pair; IAM
  `generateAccessToken` must then deny impersonation of `deploy`. Verify both
  events in the Google audit logs.
- A client that supplies the edited email will fail locally with `PIVB_ENV`. That
  is useful defense in depth, but it does not test the Google-side cross-alias
  boundary and is not a successful negative canary.
- Confirm audit entries name the expected `sub`, `serial`, and `key_id` per card.
- Mint with every card and confirm all of them work.

This canary may run against a development build while the production daemon is
still the old one. If it does, the test endpoint must not be reachable from an
agent sandbox.

## Use

Global flags come **before** the subcommand: `pivb [--config path]
[--control-socket path] [--wif-socket path] <command>`.

```console
pivb unlock                                   # hidden terminal PIN prompt
pivb unlock --if-needed                       # no-op when the PIN is already cached
pivb unlock --pinentry-program /run/current-system/sw/bin/pinentry-gnome3
pivb status                                   # card-free; never prints a token
pivb status --watch 5s --format waybar        # Waybar JSON on an interval
pivb lock                                     # discard cached PIN and signing metadata
pivb version
```

`unlock` verifies the PIN without spending the card's final retry and reports the
remaining count. Without `--pinentry-program` it requires a terminal for hidden
entry; a cancelled pinentry exits **2**.

`status` is card-free — it never probes for an inserted card:

```console
$ pivb status
{
  "pin_cached": false,
  "pin_verified_serial": 0,
  "wif_provider": "projects/123456789012/locations/global/workloadIdentityPools/pivb/providers/yubikey-piv",
  "version": "dev"
}
```

After a signature it also reports `last_sign_alias`, `last_sign_target`,
`last_sign_serial`, `last_sign_key_id`, and `last_sign_at`. `pin_verified_serial`
is the key the cached PIN was verified against; `last_sign_serial` is the key that
last signed.

`--format waybar` emits a `text`/`tooltip`/`class`/`alt` object with class `ready`,
`locked`, or `unavailable`, and exits **0** even when the daemon is down so the bar
keeps rendering. Plain `--format json` without `--watch` exits nonzero if the
daemon is unreachable; with `--watch` it emits `{"unavailable":true,"error":"…"}`
and keeps polling.

### `pivb subject-token` (machine interface)

This is the executable credential source. Auth libraries invoke it; you normally do
not. It writes exactly one JSON document to stdout per invocation and puts operator
detail — never token material — on stderr.

Before contacting the signing socket it requires
`GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE` equal to the OIDC ID-token type and
`GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE` equal to the derived external-account audience.
`GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL` is optional, but when supplied it
must equal the alias's configured target; a present-empty value is a mismatch.
`GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE` must be absent. The daemon request always
uses the configured alias target and the daemon revalidates the alias, audience,
and target against its own configuration.

These local checks catch some tampered, stale, or foreign credential files, but
Python clients never exercise the email tripwire on the service-account
impersonation path. In particular, changing only the impersonation URL remains
invisible to pivb under gcloud/Python. A local mismatch rejection therefore does
not prove the cross-alias boundary; the provider condition and per-alias IAM
bindings are authoritative, and the negative canary above must reach Google.

Success, exit 0:

```json
{"version":1,"success":true,"token_type":"urn:ietf:params:oauth:token-type:id_token","id_token":"HEADER.PAYLOAD.SIGNATURE","expiration_time":1785585870}
```

Failure, exit 1:

```json
{"version":1,"success":false,"code":"PIVB_LOCKED","message":"PIN is not cached; run `pivb unlock` first"}
```

Stable codes:

| Code | Meaning |
|---|---|
| `PIVB_ENV` | bad invocation, or credential-file environment does not match this host |
| `PIVB_CONFIG` | config missing/invalid, unknown alias, or audience/target mismatch |
| `PIVB_UNAVAILABLE` | the daemon is not reachable on the signing socket |
| `PIVB_LOCKED` | no cached PIN; run `pivb unlock` on the trusted host |
| `PIVB_PIN` | PIN rejected, or refusing to spend the final PIN retry |
| `PIVB_SIGN` | PIV signing failed: no/ambiguous card, ignored touch, deadline, PC/SC error |
| `PIVB_INTERNAL` | malformed daemon response or an unclassified daemon error |
| `PIVB_PEER` | the socket peer's real UID is not the daemon's — surfaced from the UDS layer |

### `pivb agent-session`

This trusted-host supervisor delegates exactly one configured alias to one outer
sandbox launcher:

```fish
pivb agent-session \
  --alias ro \
  --source-label codex:agentic/ro \
  -- agent-sandbox-launcher codex
```

The source label grammar is `<agent>:<project>/<role>`, with 1–32 lowercase ASCII
letters, digits, dots, underscores, or hyphens per component; each component starts
with a letter, and `role` must equal `--alias`. The label and session ID are bounded
operator context, not authorization. Any same-UID host process that already reaches
`wif.sock` can spoof them; the host socket is trusted-host-only for that reason.

Before starting the child, the supervisor resolves the alias, target, WIF audience,
and access-token lifetime from the closed config. It creates a unique `0700`
directory below `$XDG_RUNTIME_DIR/pivb-agent`, containing `session.sock`,
`credential.json`, and `session.json` as `0600`, then gives the launcher
`PIVB_AGENT_SESSION_DIR` and `PIVB_AGENT_SESSION_ID`. `session.json` contains the
non-secret session ID, creation time, alias, target, audience, lifetime, and source
label.

The child stays in the supervisor's foreground process group, so interactive Codex
and Claude TUIs retain normal terminal job control. The supervisor forwards
targeted `SIGHUP` and `SIGTERM`, escalating a repeated signal to `SIGKILL`,
propagates the child's exit status or fatal signal, and removes the session
directory before it exits. Terminal `SIGINT` and `SIGQUIT` already reach the whole
foreground process group and are not sent to the child a second time; service
managers and targeted lifecycle controls must use `SIGTERM`. If the relay itself
fails, the supervisor terminates the child because the session contract is no
longer usable. Cleanup errors are reported but never replace the child's exit
status.

Inside the sandbox, the generated credential invokes only the fully static helper:

```text
/run/pivb-agent/pivb-agent-subject-token --socket /run/pivb-agent/session.sock
```

That helper loads no PIVB config and has no control, PC/SC, YubiKey, STS, IAM
Credentials, or alias-selection capability. The relay request contains only the
executable audience and optional impersonated email for validation. It injects the
captured alias, target, audience, source label, and session ID into the ordinary WIF
request; pivbd revalidates all authorization values and validates the audit context
before it can enter logs or a touch notification. A daemon restart reconnects on a
later request or returns `PIVB_UNAVAILABLE`; it never falls back to broader access.

The socket intentionally allows repeated subject-token mints until the supervised
child exits. Removing it prevents new mints but cannot revoke Google credentials
already obtained by an auth library; those expire within the configured lifetime.

### Subject token

Each token is an RS256 compact JWS with `kid` bound to the enrolled key:

```json
{
  "iss": "https://auth.example.net/pivb/<deployment-id>",
  "sub": "pivb-key:<jwk_kid>",
  "aud": "https://iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>",
  "iat": 1785585570,
  "exp": 1785585870,
  "jti": "<128-bit CSPRNG base64url>",
  "alias": "ro",
  "target": "readonly-sa@example-project-id.iam.gserviceaccount.com",
  "serial": "12345678",
  "key_id": "<jwk_kid>"
}
```

`iat` is backdated 30 seconds for clock skew and `exp` is exactly `iat + 300`, so
the usable window after signing is about 270 seconds. Five minutes is hard-coded,
not a setting. The API accepts no custom claims, audiences, scopes, digests, raw
bytes, or arbitrary service-account addresses — it selects among configured values
and can introduce nothing new.

## Install the user service

Install the flake package through the machine configuration, or copy/link its unit
into the user unit search path, then:

```console
systemctl --user daemon-reload
systemctl --user enable --now pivb.service
journalctl --user -u pivb.service -f
```

The service runs in the **user** manager so `gpgconf --kill scdaemon`, `GNUPGHOME`,
and desktop notifications resolve in the right session. At startup it verifies that
pcscd is reachable; with `Restart=on-failure` it retries until the system
smart-card service is available. No YubiKey needs to be inserted for the daemon to
start.

The unit is hardened for a networkless signer. `PrivateNetwork=yes` is the primary
network boundary and `RestrictAddressFamilies=AF_UNIX` leaves only Unix sockets;
PC/SC is reached through `/run/pcscd/pcscd.comm`, and `PrivateDevices=yes` blocks a
direct USB fallback. The unit also sets `NoNewPrivileges=yes`, `UMask=0077`, empty
`CapabilityBoundingSet=`/`AmbientCapabilities=`, `ProtectSystem=strict`,
`ProtectHome=read-only`, `ProtectProc=invisible`, `ProcSubset=pid`,
`MemoryDenyWriteExecute=yes`, `RestrictNamespaces=yes`, `LockPersonality=yes`,
`SystemCallArchitectures=native`, the `ProtectKernel*`/`ProtectClock`/
`ProtectControlGroups` set, and `RuntimeDirectory=pivb` with
`RuntimeDirectoryMode=0700`.

Verify the effective sandbox after any change:

```console
systemd-analyze security --user pivb.service
ss -ltnp; ss -ltnp6      # no pivb listener, on any port
```

Do not tighten this block blindly, and do not trust it until it has run against
real hardware — hardening that has never met a YubiKey is a hypothesis, not a
control. Four paths can break under it, and only a live test settles each:

| Path | How to test | Notes |
|---|---|---|
| PC/SC under `PrivateDevices=yes` | `pivb unlock` with a card inserted | pcscd uses a filesystem socket, so this should pass. If it does not, find which device path is genuinely needed rather than dropping `PrivateDevices`. |
| `gpgconf --kill scdaemon` under `ProtectSystem=strict` | provoke a sharing violation: start a GPG smart-card operation, then mint concurrently | Expect exactly one WARN, one scdaemon kill, one retry, and a successful token. gpgconf execs a binary and talks to gpg-agent over a socket in `$XDG_RUNTIME_DIR`; connecting to a socket needs no writable mount, but verify rather than assume. |
| D-Bus notifications | mint and watch for the touch prompt naming alias, target, and `local-wif` | The session bus is a Unix socket, unaffected by `PrivateNetwork`. |
| Runtime socket creation under `ProtectSystem=strict` | `systemctl --user restart pivb`, then confirm both sockets are `0600` in a `0700` directory | `RuntimeDirectory=pivb` is what keeps that path writable. Removing it breaks socket creation. |

If desktop notifications cannot survive a tight unit, move notification delivery
into a separate unprivileged one-shot helper rather than weakening the signing
service. Also confirm `MemoryDenyWriteExecute=yes` does not break the binary at
runtime — Go does not JIT, but this build links C through cgo — and finish with a
negative network test: the daemon must be unable to reach a Google endpoint at all
while valid host clients keep working.

## Security and failure behavior

- A PIV connection exists only for one PIN verification or one signature. Card
  selection, serial lookup, the live-certificate check, cross-key PIN verification,
  and signing all happen inside that one session. Status uses cached memory only
  and never opens a card.
- The certificate is read from slot `9c` **in the session that will sign**, its key
  ID is derived, and it must equal the configured `keys.<serial>.jwk_kid`. A
  replaced key on a known serial fails closed until it is deliberately re-enrolled.
- Exactly one configured YubiKey may be inserted. Two enrolled cards at once is a
  hard error, not a silent choice.
- pivb refuses to spend a card's final PIN retry, both on `unlock` and when trying
  a cached PIN against a swapped card.
- A confirmed PC/SC sharing violation triggers exactly one `gpgconf --kill
  scdaemon` and one fresh retry. No other error does.
- Signing has a 20-second deadline; the YubiKey normally bounds an ignored touch at
  about 15 seconds. After cancellation pivb waits up to two more seconds for the
  worker to release the card. The helper's socket timeout is 28 seconds, inside the
  30-second credential-source budget.
- The assertion is never cached, written to disk, or logged. Daemon logs record
  alias, target, serial, key ID, and expiry — never a PIN, subject token, STS
  token, access token, Google ID token, or Authorization header.
- The cached PIN is held as a byte slice and zeroized on lock, on a failed
  cross-card verification, and after each mint under `pin_cache = "never"`. Go
  cannot reliably erase the string copies the PIN makes crossing API and signer
  boundaries, so process-memory compromise during an unlock or mint remains in
  the threat model.
- Touch notifications name the alias and target. Trusted-host requests retain the
  `local-wif` label; delegated requests show the structured source label and first
  12 session-ID characters, while logs and `session.json` retain the full ID. This
  is operator context, not authorization: raw `wif.sock` remains trusted-host-only.
- A subject token minted for one alias cannot impersonate another alias's target,
  even if copied before expiry — the alias/target claims, the provider condition,
  and the per-target binding all have to agree.
- Target access tokens last at most one hour and are owned by the requesting client
  library, never by pivbd.
- A lost YubiKey is disabled by removing its JWK and re-uploading the **complete**
  set — a provider update replaces the whole JWKS, so always include every key that
  should remain trusted, and keep the previous set for rollback. New exchanges with
  that card then fail. **Google has no revocation API for already-issued tokens**;
  they expire naturally within the hour.

Kernel/root compromise, physical attacks on the YubiKey, and revocation of an
already-issued Google access token are out of scope. AWS and Azure remain out of
scope; a future AWS module would need IAM Roles Anywhere and a CA-chained
certificate (reserved slot `82`), and an Azure module an Entra client assertion in
slot `83`.

## Agent sandboxes

**Raw PIVB, the YubiKey, configuration, and ordinary sockets must remain
unavailable. A sandbox may receive one explicitly delegated, fixed-alias
agent-session socket after the complete sandbox acceptance suite passes.**

The machine configuration owns this boundary, not PIVB or the products' inner
command sandboxes. A same-UID agent passes `SO_PEERCRED` on any socket it can see;
hiding the `pivb` binary is therefore cosmetic. Apply the outer-launcher contract
to every Claude and Codex entry point, including fresh, resumed, nested-tool, and
alternate wrappers. The [Codex sandbox](https://learn.chatgpt.com/docs/sandboxing)
and [Claude Code Bash sandbox](https://code.claude.com/docs/en/sandboxing) constrain
spawned commands and their subprocesses; the outer launcher remains responsible
for which host Unix capabilities enter that boundary.

The launcher consumes `PIVB_AGENT_SESSION_DIR` only on the host. It creates a
private read-only `/run/pivb-agent` and binds exactly these paths:

| Host source | Sandbox destination |
|---|---|
| `$PIVB_AGENT_SESSION_DIR/session.sock` | `/run/pivb-agent/session.sock` |
| `$PIVB_AGENT_SESSION_DIR/credential.json` | `/run/pivb-agent/credential.json` |
| `$PIVB_AGENT_SESSION_DIR/session.json` | `/run/pivb-agent/session.json` |
| dereferenced installed `pivb-agent-subject-token` | `/run/pivb-agent/pivb-agent-subject-token` |

Read-only bind mounts do not prevent `connect(2)` to the `0600` socket. Do not bind
the helper's parent Nix output or `/run/current-system`; resolve the installed
symlink on the host and bind only the static executable file.

### Mount and device namespace

- Start from an empty private `/run`; add only the four paths above and unrelated
  paths the workload genuinely needs.
- Never bind `$XDG_RUNTIME_DIR/pivb`, `/run/pcscd`, `/dev/bus/usb`, any YubiKey
  device node, the user D-Bus or systemd sockets, Docker/Podman sockets, SSH or GPG
  agent sockets, or a forwarded pivb file descriptor.
- Use a minimal private `/dev` with no raw USB and no smart-card devices.
- Hide `~/.config/pivb`, ordinary generated credential files, `~/.config/gcloud`,
  ADC files, and every application-specific credential cache.
- Do not expose `/run/current-system` or the Nix store wholesale. Build the sandbox
  package closure explicitly and omit raw pivb.
- Use a private PID namespace and proc mount, so a same-UID agent cannot inspect or
  signal host user processes.

### Network namespace

- Give the sandbox its own network namespace. **Sharing the host network namespace
  is forbidden** — that alone re-exposes every host loopback service.
- If agents need no Internet, give them no interface beyond private loopback.
- If they need outbound Internet, use `slirp4netns --disable-host-loopback` or a
  filtered egress proxy. Default user-mode networking that maps the host through a
  gateway is **not** sufficient.
- Deny the host gateway, loopback, link-local, RFC1918, local IPv6, and other
  host/LAN routes unless a specific destination is genuinely required.
- A host HTTP proxy must independently reject local addresses, DNS rebinding, Unix
  sockets, and redirects to host-local services. Otherwise it becomes an SSRF bridge
  straight around the network namespace.

### Environment and escape surfaces

Scrub at least:

```text
GCE_METADATA_HOST
GCE_METADATA_IP
GCE_METADATA_ROOT
GOOGLE_APPLICATION_CREDENTIALS
GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES
CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE
CLOUDSDK_AUTH_ACCESS_TOKEN
CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT
DBUS_SESSION_BUS_ADDRESS
DOCKER_HOST
SSH_AUTH_SOCK
GPG_AGENT_INFO
PIVB_AGENT_SESSION_DIR
```

After scrubbing inherited credential selection, set exactly:

```fish
set -gx GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES 1
set -gx GOOGLE_APPLICATION_CREDENTIALS /run/pivb-agent/credential.json
set -gx CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE /run/pivb-agent/credential.json
```

The non-secret `PIVB_AGENT_SESSION_ID` may remain for correlation. A nested launcher
must reuse the inherited `/run/pivb-agent` or refuse to start; it must never replace
the session by reaching a host-side launcher or creating a new delegation.

Also block `systemd-run --user`, the host user manager, container-daemon sockets,
`nsenter` targets, and any helper that can spawn a process outside the sandbox. A
cgroup firewall or a genuinely separate host UID is good defense in depth, but must
not replace the mount and network namespaces.

### Sandbox acceptance tests

Run these **from inside the real production launcher** — a unit test of the Nix
expression is not enough — while pivb has a cached PIN, a YubiKey is inserted, and
a trusted host client can successfully authenticate:

1. The `ro` session authenticates through both gcloud and a real ADC client with
   `GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1`; no browser login is involved.
2. A cache miss produces a YubiKey signature and the touch prompt contains the
   source, short session ID, and fixed target without token material.
3. Raw requests carrying an alias or attempting `deploy` fail before signing.
4. Tampered audience and supplied impersonation targets fail locally; an edited
   impersonation URL whose client omits the email still fails through signed claims,
   the provider condition, and per-alias IAM binding.
5. Two concurrent sessions for different aliases cannot cross-select or cross-use
   their sockets.
6. The helper runs with no config, PIVB CLI, PC/SC, YubiKey, gcloud cache, or
   ordinary credential file visible.
7. `command -v pivb` fails; neither `$XDG_RUNTIME_DIR/pivb` nor any control,
   discovery, configuration, STS, IAM Credentials, or access-token endpoint exists.
8. Interrupting, killing, or crashing the child removes its three generated
   artifacts; child exit codes and fatal signals propagate after cleanup.
9. Connecting to host `127.0.0.1`, `::1`, the user-mode-network gateway, and the
   host LAN address reaches no host service.
10. `/run/pcscd`, USB, D-Bus/systemd, Docker/Podman, SSH/GPG, `systemd-run --user`,
    `nsenter`, inherited descriptors, and host-proxy bypass attempts all fail while
    approved DNS/HTTPS still work.
11. Existing trusted-host subject-token credentials remain compatible, and agent
    logs/notifications identify the full source/session without logging secrets.
12. A daemon restart either reconnects on a later request or yields the structured
    `PIVB_UNAVAILABLE` response; it never widens or falls back. Run all tests for
    fresh, resumed, nested-tool, and alternate launchers for both agent products.

### Interim operating rule

Until the production launcher implements the four-path bind and every acceptance
test above passes, the honest position is unchanged: **do not run an untrusted
agent sandbox while the pivb service is running.** Do not treat the presence of
`agent-session` alone as permission to relax this rule.

```fish
systemctl --user stop pivb.service
systemctl --user mask pivb.service      # unmask when you need pivb again
```

This is an operational workaround, not a control. It exists so the known exposure
is never treated as acceptable while the real boundary is being built.

Remote forwarding of the old agent socket is **removed and unsupported**. Never
forward the control socket. A remote design would need a distinct socket, an origin
alias allowlist, relay authentication, and remote-labelled touch prompts; until it
exists, use pivb locally.

## Migrating from the metadata/broker architecture

The GCE metadata emulator on `127.0.0.1:8642`, the per-card broker service
accounts, and the `pivb token`/`use`/`renew`/`metadata` commands are gone. To cut
over:

1. Deploy the new binary and the WIF configuration together. Old config keys fail
   closed with the migration error above.
2. Remove `GCE_METADATA_HOST`, `GCE_METADATA_IP`, and `GCE_METADATA_ROOT` from
   shell, direnv, service, IDE, and backend configuration.
3. Set `GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1` and point trusted clients at
   the per-alias credential file.
4. Confirm `ss -ltnp` shows no listener on 8642 and that pivbd has no Internet
   socket.
5. Run the manual acceptance list below, for every alias and every card.

### Retiring broker trust

Keep the old uploaded broker keys **disabled**, with the broker grants still in
place, for a short explicit rollback window — seven normal working days is the
recommendation. Rollback during that window requires deliberately re-enabling a
key, which is the point: it cannot happen by accident.

After the window, in this order:

1. Disable, then delete, the uploaded keys on every broker service account.
2. Remove each broker's `roles/iam.serviceAccountTokenCreator` grants from the
   target service accounts.
3. Disable, then delete, the now-unused broker service accounts.

Do not leave unused brokers or Token Creator grants in place indefinitely — they
are standing impersonation authority with no remaining purpose.

### Rollback

**Before broker trust is deleted**, keep the last old binary and configuration as
an emergency rollback artifact. Rolling back reintroduces the localhost token
exposure, so it must be an explicit operator decision, and the agent sandbox must
stay stopped while the old binary runs.

**JWKS rollback** is independent and available at any time: keep a copy of the
previous uploaded set before every provider update, since an update replaces the
complete set. Re-uploading a known-good set is the rollback; it recovers no
revoked private key and contains no secret material.

**After broker deletion**, rollback is forward-only — fix the WIF path, or
deliberately recreate the old Google trust. Neither path can revoke Google tokens
already issued; the one-hour maximum lifetime bounds that residual window.

## Manual acceptance

With the operator and enrolled hardware, verify:

1. `pivb unlock`, then obtain a Google token for each alias through a real client
   library and the generated credential file; touch when prompted.
2. Swap to each other configured fleet key and repeat without changing config or
   restarting; re-unlock only if the fleet PINs differ.
3. Ignore a touch; confirm a loud `PIVB_SIGN` failure within roughly 20 seconds and
   a successful retry afterwards.
4. Collide a signature with an in-flight GPG operation; observe at most one WARN,
   one scdaemon kill, and one retry.
5. `ss -ltnp` and `ss -ltnp6` show no pivb listener, and the daemon cannot reach a
   Google endpoint.
6. `journalctl --user -u pivb.service` contains no PIN, subject token, STS token,
   access token, or Authorization header — under success and every tested failure.
7. Through gcloud/Python, a credential file edited to target another alias's
   service account succeeds at STS but is denied by IAM `generateAccessToken`, not
   merely rejected locally.
8. Remove one card's JWK, re-upload the remaining set, and confirm new exchanges
   with that card fail while other cards keep working.
9. gcloud and the production JVM backend authenticate through the external-account
   file with no metadata variables, no browser login, and no manually supplied
   impersonated-email variable.
10. Generated credential files still work after a NixOS rebuild changes the pivb
    store path.
11. Fixed-alias agent sessions pass every [sandbox acceptance
    test](#sandbox-acceptance-tests), including real gcloud/ADC authentication,
    while raw PIVB and host capabilities remain unreachable.
12. Every target access token expires within 3600 seconds.
13. Old broker uploaded keys, Token Creator grants, and broker service accounts are
    absent after the rollback window.
14. Old remote configuration fails closed with a migration error, and no raw pivb
    socket is forwarded anywhere.

## References

- Google Cloud, [Configure Workload Identity Federation with other identity providers](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-other-providers)
- Google Cloud, [Authenticate workloads with Google Cloud auth libraries](https://docs.cloud.google.com/iam/docs/authenticate-with-auth-libraries)
- Google Cloud, [Best practices for Workload Identity Federation](https://docs.cloud.google.com/iam/docs/best-practices-for-using-workload-identity-federation)
- Google Cloud Java, [Get started with Google Auth Library](https://docs.cloud.google.com/java/getting-started/getting-started-with-google-auth-library)
- Google Cloud, [Roles for service account authentication](https://docs.cloud.google.com/iam/docs/service-account-permissions)
- bubblewrap, [sandbox implementation and namespace options](https://github.com/containers/bubblewrap)
- slirp4netns, [`--disable-host-loopback`](https://github.com/rootless-containers/slirp4netns/blob/master/slirp4netns.1.md)
- systemd, [resource-control security caveats](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html)
- Linux, [`unix(7)` and peer credentials](https://man7.org/linux/man-pages/man7/unix.7.html)
