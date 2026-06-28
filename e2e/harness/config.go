//go:build e2e

package harness

// combinedConfigYAML is a minimal combined-server config for tests: plain HTTP
// on :8080 (no TLS cert configured → the server serves HTTP and expects to sit
// behind a reverse proxy, which is exactly what we want for in-cluster tests),
// embedded IdP, local signal/relay/STUN, and a sqlite store under the mounted
// data dir. exposedAddress is the address peers use to reach this container; it
// is overridden per-run so the value matches the container's network alias.
const combinedConfigYAML = `server:
  listenAddress: ":8080"
  exposedAddress: "%s"
  healthcheckAddress: ":9000"
  metricsPort: 9090
  logLevel: "info"
  logFile: "console"
  authSecret: "e2e-relay-secret"
  dataDir: "/nb/data"
  auth:
    issuer: "%s"
  store:
    engine: "sqlite"
`
