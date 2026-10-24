# MCP E2E tests

These tests run a real combined management server in Docker with nothing set
beyond `NB_MCP_ENABLED=true`, and drive the MCP endpoint and its OAuth broker the
way a remote MCP client does.

Run from the repository root with Docker and Go available:

```bash
go test -tags e2e -timeout 25m -v ./e2e/mcp/...
```

The harness builds the combined server from the current checkout. To test an
existing image, pass a full image reference:

```bash
NB_E2E_COMBINED_IMAGE=local/netbird-combined:mcp go test -tags e2e -timeout 25m -v ./e2e/mcp/...
```

The suite covers:

- A personal access token: the advertised tools, a read and a write tool, with
  the write confirmed and undone through the REST API, and the endpoint refusing
  an `?account=` other than the caller's own.
- OAuth through the embedded Dex: discovery from the 401 challenge, dynamic
  registration, consent, sign-in as the bootstrapped admin, the code exchange
  with PKCE, tool calls with the broker's token, refresh and revocation. Dex
  accepts the broker's callback only because the embedded IdP registers it on
  its own, so this test passing shows a self-hosted deployment needs no other
  configuration.
- A read-only consent, a declined consent, a cross-site consent post, a replayed
  authorization code, and a broker token presented outside `/api/mcp`.

The embedded IdP's issuer is `http://localhost:8080/oauth2` inside the
container, so every URL the login flow hands out names `localhost:8080`. The
tests reach it through `harness.Combined.Browser`, which dials the container's
mapped port for that address and keeps cookies between steps.

The `MCP E2E` workflow runs this package for pull requests that touch the MCP
module, the management server wiring, the embedded IdP, or the harness. The
nightly `./e2e/...` run includes it as well.
