//go:build ignore

// Regenerates defaults_llm_pricing.example.yaml from the compiled-in
// default pricing table. Run via:
//
//	go generate ./management/internals/modules/agentnetwork/pricing
package main

import (
	"log"
	"os"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/pricing"
)

func main() {
	if err := os.WriteFile("defaults_llm_pricing.example.yaml", pricing.MarshalDefaultsYAML(), 0o644); err != nil {
		log.Fatalf("write defaults_llm_pricing.example.yaml: %v", err)
	}
}
