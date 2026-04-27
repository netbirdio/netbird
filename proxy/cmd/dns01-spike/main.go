// Command dns01-spike is a vertical-slice proof of concept for the
// "Private Services with Real Certs" roadmap. It uses Lego with
// Cloudflare DNS-01 to issue a real Let's Encrypt cert for a configured
// domain — without requiring the proxy to be publicly reachable.
//
// SPIKE NOTE: this binary is throwaway. It exists to prove the integration
// is tractable and to surface unknowns before Phase 1 engineering capacity
// is committed. See roadmap.md and p1-plan.md (Wave 0) for context.
package main

import (
	"github.com/netbirdio/netbird/proxy/cmd/dns01-spike/cmd"
)

func main() {
	cmd.Execute()
}
