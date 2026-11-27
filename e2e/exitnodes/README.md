# Exit node E2E tests

These tests run a real combined management server and three NetBird clients in
Docker. An HTTP target sits alone on an internal Docker network that stands in
for the internet. Only the exit peer is attached to it, so the other peers
reach the target only when management routes their traffic through the exit
node.

Each test configures exit nodes, policies, and groups through the management
API, then checks from inside the clients which peers reach the target. The
target replies with the address it sees, which confirms that traffic arrives
masqueraded by the exit peer.

Run from the repository root with Docker and Go available:

```bash
go test -tags e2e -timeout 40m -v ./e2e/exitnodes/...
```

The harness builds the combined server and client from the current checkout.
To test existing images, set `NB_E2E_COMBINED_IMAGE` and `NB_E2E_CLIENT_IMAGE`.

The suite covers policy source changes, multiple source groups, source group
membership, disabled and deleted policies, disabled exit nodes and exit peers, port-restricted policies,
deleted exit nodes, and exit nodes that are not auto applied. It runs in the
nightly `./e2e/...` job.
