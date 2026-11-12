# Reverse-proxy access E2E tests

These tests run a real combined management server, reverse proxy, and HTTP
upstream in isolated Docker containers. Services are configured through the
management API, then requests go through the proxy's HTTPS listener. No external
identity provider, public DNS record, or API credential is needed.

Run from the repository root with Docker and Go available:

```bash
go test -tags e2e -timeout 25m -v ./e2e/reverseproxy/...
```

The harness builds the combined server and proxy from the current checkout.
To test existing images, pass full image references:

```bash
NB_E2E_COMBINED_IMAGE=local/netbird-combined:target-access \
NB_E2E_PROXY_IMAGE=local/netbird-proxy:target-access \
go test -tags e2e -timeout 25m -v ./e2e/reverseproxy/...
```

Rebuild locally tagged images after backend changes. Both components must
support target access actions; using an older management image does not test
the feature.

The suite checks inherited service authentication, anonymous bypass, blocked
paths, longest-prefix precedence, credential stripping, live action updates,
service restrictions, deletion, and private-service bypass rejection. Upstream
request markers distinguish successful forwarding from proxy-generated
responses and verify that denied requests never reach the backend.

The `Reverse Proxy E2E` workflow runs this package for relevant pull requests
and manual dispatches. It also remains part of the nightly `./e2e/...` suite.
Dashboard browser coverage lives in the dashboard repository: it creates and
edits services through the UI, then probes their real proxy behavior.
