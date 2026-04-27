# dns01-spike

Vertical-slice proof of concept for the DNS-01 ACME challenge work in the [Private Services with Real Certs roadmap](../../../../roadmap.md).

## What this proves

- Lego (`github.com/go-acme/lego/v4`) drops cleanly into the netbird Go module
- The Cloudflare DNS-01 provider in Lego is straightforward to configure
- A `CertBackend` interface (`proxy/internal/acme/backend.go`) accommodates both the existing autocert path and a new Lego path without forcing a method-signature change — the existing `*Manager` already satisfies it (compile-time assertion proves this)
- A standalone CLI can issue a real Let's Encrypt cert via Cloudflare DNS-01 end-to-end

## What this skips (deliberately)

This is a spike, not a deliverable. It explicitly does not:

- Plumb per-service config through the proto / management server
- Use encrypted credential storage (env vars instead)
- Integrate with the existing distributed locker
- Wire `LegoBackend` into the running `Server` (it compiles alongside `*Manager` but is not invoked)
- Test renewal lifecycle, multi-replica coordination, or rate-limit handling
- Support providers other than Cloudflare
- Use Let's Encrypt production by default (staging is the default to avoid burning rate limits)

The full Phase 1 scope is in [`p1-plan.md`](../../../../p1-plan.md).

## Prerequisites

1. A domain managed in Cloudflare (e.g. `test.example.com` where `example.com` is in your Cloudflare account)
2. A scoped Cloudflare API token with `Zone:DNS:Edit` permission for the target zone — **not the global API key**
3. An email address for the ACME account

### Creating the Cloudflare token

1. Cloudflare dashboard → My Profile → API Tokens → Create Token
2. Use the "Edit zone DNS" template
3. Zone Resources → Include → Specific zone → your test zone
4. Save and copy the token

## Running

From the `netbird/` repo root:

```sh
export CF_DNS_API_TOKEN="cf_xxx..."
export SPIKE_DOMAIN="test.example.com"
export SPIKE_EMAIL="you@example.com"

go run ./proxy/cmd/dns01-spike
```

Or pass flags explicitly:

```sh
go run ./proxy/cmd/dns01-spike \
  --domain test.example.com \
  --email you@example.com \
  --cf-token cf_xxx... \
  --output ./certs-spike
```

## Expected output

The CLI logs each step at `info` level (use `--log-level debug` for more):

```
[spike] domain=test.example.com email=... output=./certs-spike acme=https://acme-staging-v02.api.letsencrypt.org/directory
[spike] using Let's Encrypt STAGING — issued certs will not be browser-trusted (this is intentional for the spike)
[legoclient] registered new ACME account for ...
[legoclient] requesting cert for test.example.com via DNS-01 (a TXT record will be set & cleaned up at Cloudflare)
... (Lego library logs the challenge present / clean up)
[legoclient] cert written to ./certs-spike/test.example.com.crt, key written to ./certs-spike/test.example.com.key
[spike] done. inspect ./certs-spike/test.example.com.crt to see the issued cert
```

While issuance is happening, you should see a `_acme-challenge.test.example.com` TXT record briefly appear in your Cloudflare dashboard, then disappear when Lego cleans it up.

## Verifying the issued cert

```sh
openssl x509 -in ./certs-spike/test.example.com.crt -text -noout | head -20
```

Issuer should show "Fake LE Intermediate" (Let's Encrypt staging). The chain is valid X.509 but is not browser-trusted because it's signed by the staging CA — that's expected and intentional.

## Switching to production (NOT recommended for spike runs)

```sh
export SPIKE_ACME_DIR="https://acme-v02.api.letsencrypt.org/directory"
```

Production has tight rate limits (50 certs / registered domain / week). Only switch after staging is fully verified.

## Idempotent reruns

The CLI persists ACME account state under `--output` (`account.key` + `account.json`) and the issued cert. Re-running with the same domain is a no-op once the cert exists. To re-issue, delete the `.crt` and `.key` files for the domain.

## Files

- `main.go` — entry point
- `cmd/root.go` — cobra root command, env var / flag parsing, run logic
- `../../internal/acme/backend.go` — `CertBackend` interface + compile-time assertion that existing `*Manager` satisfies it
- `../../internal/acme/lego_backend.go` — `LegoBackend` (compile-only sketch, not wired into Server)
- `../../internal/acme/legoclient/client.go` — shared Lego helper used by both the CLI and `LegoBackend`

## After running the spike

Capture findings in `spike-findings.md` (in the parent working directory, not committed). What worked, what was harder than expected, scope corrections to feed back into `roadmap.md` and `p1-plan.md`, and any remaining unknowns Phase 1 will need to resolve.
