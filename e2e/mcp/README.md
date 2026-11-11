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

The suite calls read and write tools with a personal access token, and again
with a token from the full OAuth login at the embedded Dex, with the REST API
confirming the group `create_group` made and its removal by `delete_group`. It
also covers refresh, revocation, a broker token refused outside `/api/mcp`, a
read-only consent and a replayed authorization code.

The embedded IdP's issuer is `http://localhost:8080/oauth2` inside the
container, so every URL the login flow hands out names `localhost:8080`. The
tests reach it through `harness.Combined.Browser`, which dials the container's
mapped port for that address and keeps cookies between steps.

The `MCP E2E` workflow runs this package for pull requests that touch the code
it exercises, and the nightly `./e2e/...` run includes it as well.
