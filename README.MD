# pivb

`pivb` turns a touch-gated, non-exportable RSA-2048 key in YubiKey PIV slot
`9c` into short-lived Google Cloud service-account credentials. It keeps the PIV
session ephemeral, caches only derived tokens in RAM, and presents them through a
small GCE metadata server on `127.0.0.1:8642`.

The daemon is a systemd **user** service. It never stores a PIN or token on disk.
Every access-token or ID-token mint signs a new broker assertion and therefore
requires a physical touch.

## Build and test

```console
nix build
nix develop --command go test ./...
```

The flake builds with cgo against `pcsclite` and includes the user unit at
`lib/systemd/user/pivb.service`. Go dependencies are vendored so the build is
network-independent.

For a local development build inside `nix develop`:

```console
go build ./cmd/pivb
```

## Configure

Copy [`config.example.toml`](config.example.toml) to
`~/.config/pivb/config.toml`, then set the enrolled YubiKey serials, broker
service-account address, uploaded key ID, and aliases. The parser rejects unknown
keys and names missing required keys at startup.

`cloud = "gcp"` is optional on aliases and defaults to GCP. It is present as the
extension seam for future AWS and Azure minters; other cloud values are rejected
until their protocol implementations exist. `remote_allowed_aliases` is accepted
and validated but intentionally not enforced in v1.

PIN caching has two modes:

- `session`: retain the verified PIN in daemon RAM until `pivb lock` or restart.
- `never`: consume the cached PIN on the next mint attempt, requiring `pivb
  unlock` before every access- or ID-token mint.

An empty `notify_cmd = []` disables desktop notifications. The default is
`["notify-send", "pivb"]`; pivb appends the touch or expiry message as the last
argument.

## Install the user service

Install the flake package through the machine configuration, or copy/link its unit
into the user unit search path, then run:

```console
systemctl --user daemon-reload
systemctl --user enable --now pivb.service
journalctl --user -u pivb.service -f
```

The service deliberately runs in the user manager so `gpgconf --kill scdaemon`,
`GNUPGHOME`, and desktop notifications resolve in the correct session. On startup
it verifies that pcscd is reachable; with `Restart=on-failure`, it retries until
the system smart-card service is available. No YubiKey needs to be inserted for
the daemon itself to start.

Set these variables for clients:

```bash
export GCE_METADATA_HOST=127.0.0.1:8642
export GCE_METADATA_IP=127.0.0.1:8642
export GCE_METADATA_ROOT=127.0.0.1:8642
```

Remove `CLOUDSDK_CORE_CHECK_GCE_METADATA=false`,
`CLOUDSDK_AUTH_IMPERSONATE_SA`, `GOOGLE_APPLICATION_CREDENTIALS`, and any old ADC
login hook from the surrounding environment.

## Use

```console
pivb unlock             # hidden terminal PIN prompt; verifies without spending the final retry
pivb use ro             # notification, touch, then atomically serve the ro identity
pivb status             # never prints a token
pivb renew              # notification + touch
pivb use deploy         # old cached token is dropped after the new mint succeeds
pivb token              # metadata only
pivb token --print      # explicit debugging escape hatch
pivb lock               # discard cached PIN, access token, and ID tokens
```

The metadata token endpoint never auto-mints. If the token is missing or expired,
it returns HTTP 503 with a remedy; below four minutes it emits one expiry
notification per token window. The identity endpoint mints on demand and caches by
audience, so the first request for each audience requires a touch. The token
endpoint accepts `?scopes=` for client compatibility but ignores it, logs that fact
at debug level, and returns the cached cloud-platform token.

The agent API listens on `$XDG_RUNTIME_DIR/pivb/agent.sock` with directory mode
`0700`, socket mode `0600`, and Linux `SO_PEERCRED` UID enforcement. For a forwarded
socket, run the frontend only:

```console
pivb metadata --agent /path/to/forwarded-agent.sock --listen 127.0.0.1:8642
```

The remote sees only derived credentials. Signing and touch approval remain on the
machine containing the YubiKey.

## One-time GCP and YubiKey setup

First verify that `iam.disableServiceAccountKeyUpload` is not enforced and that any
`iam.serviceAccountKeyExpiryHours` policy permits the certificate lifetime. The
broker service account must receive no project roles; its only grants are
`roles/iam.serviceAccountTokenCreator` on explicit target service accounts.

For each card (the example uses placeholder serial `12345678`):

```console
ykman piv access change-pin
ykman piv access change-puk
ykman piv access change-management-key --generate --protect

ykman piv keys generate --algorithm RSA2048 --pin-policy ONCE --touch-policy ALWAYS 9c pub.pem
ykman piv certificates generate --subject "CN=pivb-yk-12345678" --valid-days 730 9c pub.pem
ykman piv certificates export 9c cert-12345678.pem
```

Create and constrain the broker:

```console
gcloud iam service-accounts create pivb-broker \
  --project=example-project-id \
  --display-name="pivb YubiKey broker"

gcloud iam service-accounts keys upload cert-12345678.pem \
  --iam-account=pivb-broker@example-project-id.iam.gserviceaccount.com

for target in readonly-sa deployment-sa; do
  gcloud iam service-accounts add-iam-policy-binding \
    "$target@example-project-id.iam.gserviceaccount.com" \
    --member="serviceAccount:pivb-broker@example-project-id.iam.gserviceaccount.com" \
    --role="roles/iam.serviceAccountTokenCreator"
done
```

Repeat only key generation, certificate export, and key upload for additional
YubiKeys. GCP allows up to ten user-managed keys on the broker service account.

## Security and failure behavior

- A PIV connection exists only for selection/PIN verification or one signature.
- A confirmed PC/SC sharing violation triggers exactly one
  `gpgconf --kill scdaemon` and one fresh retry. Other errors never trigger it.
- Signing has a 20-second request deadline; the YubiKey normally bounds an ignored
  touch at about 15 seconds. After cancellation, pivb waits up to two additional
  seconds for the signing worker to release the card before returning.
- The broker access-token byte buffer is zeroed immediately after the IAM
  Credentials request returns. Go cannot guarantee erasure of temporary runtime or
  HTTP copies, so process-memory compromise during a mint remains in the threat
  model.
- Switching stops serving the old token locally, but an already exfiltrated token
  remains cryptographically valid until its expiry; Google has no revocation API
  for these tokens.
- Provider failures include the HTTP status and a response body capped at 64 KiB in
  both the daemon log and API error.

AWS and Azure are intentionally out of scope for v1. The signer, per-cloud state,
agent transport, and alias cloud discriminator are reusable. A future AWS module
will need IAM Roles Anywhere and a CA-chained certificate (reserved slot `82`); an
Azure module can use an Entra client assertion in slot `83`.

## Manual acceptance

With the operator and enrolled hardware, verify:

1. `pivb unlock && pivb use ro`, touch, then inspect `pivb status`.
2. Run `gcloud auth list` and an authorized storage operation with no ADC file.
3. Exercise the JVM backend with only `GCE_METADATA_HOST` configured.
4. Switch to `deploy` and confirm only the new identity is served.
5. Collide a renew with an in-flight GPG operation and observe at most one WARN,
   one scdaemon kill, and one retry.
6. Ignore a touch; confirm a loud failure within roughly 20 seconds and a successful
   subsequent renew.
7. Reboot; confirm the daemon starts and metadata serves a remedial 503 until
   unlock plus use.
