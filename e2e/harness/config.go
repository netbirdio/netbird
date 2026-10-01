//go:build e2e

package harness

// combinedConfigYAML is a minimal combined-server config for tests: plain HTTP
// on :8080 (no TLS cert configured → the server serves HTTP and expects to sit
// behind a reverse proxy, which is exactly what we want for in-cluster tests),
// embedded IdP, local signal/relay/STUN, and a sqlite store under the mounted
// data dir. exposedAddress is the address peers use to reach this container; it
// is overridden per-run so the value matches the container's network alias.
//
// pricingDefaultsFile is deliberately a BARE FILENAME, not an absolute path: it
// must resolve against dataDir (→ /nb/data/<name>), which is the resolution rule
// the combined server applies. It is also an EXPLICITLY configured path, so the
// server is required to load it — a broken path or malformed file fails startup
// rather than silently falling back to the compiled-in rates, and TestMain then
// fails with the container logs.
//
// disableGeoliteUpdate is a parameter rather than a fixed true because a suite
// that exercises geolocation needs the database: management can only evaluate a
// location rule with GeoLite loaded, and a rule it cannot evaluate fails rather
// than passing vacuously. See WithGeolocation.
const combinedConfigYAML = `server:
  listenAddress: ":8080"
  exposedAddress: "%s"
  healthcheckAddress: ":9000"
  metricsPort: 9090
  logLevel: "info"
  logFile: "console"
  authSecret: "e2e-relay-secret"
  dataDir: "/nb/data"
  disableAnonymousMetrics: true
  disableGeoliteUpdate: %t
  auth:
    issuer: "%s"
  store:
    engine: "sqlite"
  agentNetwork:
    pricingDefaultsFile: "` + PricingDefaultsFileName + `"
`

const (
	// PricingDefaultsFileName is the basename of the operator-supplied LLM
	// pricing defaults file the combined server is configured to load. Written
	// into the bind-mounted datadir by StartCombined.
	PricingDefaultsFileName = "e2e_llm_pricing.yaml"

	// PricedDefaultModel is a real catalog model (openai surface) whose rates the
	// defaults file below REPLACES. Tests drive it against the mock vLLM upstream
	// and assert the file's rates were billed, which is only true if the file
	// travelled: config → LoadFile → DefaultTable → synthesizer → the proxy's
	// cost_meter defaults table.
	PricedDefaultModel = "gpt-4.1-mini"
	// PricedDefaultInputPer1k / PricedDefaultOutputPer1k are deliberately odd
	// values that no compiled-in catalog entry carries (gpt-4.1-mini ships as
	// 0.0004 / 0.0016), so a test asserting them cannot pass on the built-in
	// table.
	PricedDefaultInputPer1k  = 0.0123
	PricedDefaultOutputPer1k = 0.0456
)

// pricingDefaultsYAML is the operator-supplied pricing defaults file. Its schema
// is surface -> model -> per-1k rates. Entries replace the compiled-in entry for
// the same surface+model whole; every other model keeps its built-in rates, so
// this file overriding one model must not disturb the rest of the table.
const pricingDefaultsYAML = `openai:
  gpt-4.1-mini:
    input_per_1k: 0.0123
    output_per_1k: 0.0456
`
