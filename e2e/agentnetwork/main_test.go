//go:build e2e

// Package agentnetwork holds the container-based agent-network e2e suite. A
// single combined server is built and bootstrapped once per package run
// (TestMain) and shared across tests via srv; each test creates and cleans up
// its own resources so order doesn't matter.
package agentnetwork

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/netbirdio/netbird/e2e/harness"
)

// srv is the shared combined server for the package, ready (PAT-authenticated)
// by the time any Test runs.
var srv *harness.Combined

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	// Generous timeout to cover a cold image build on first run.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	var err error
	srv, err = harness.StartCombined(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: start combined server: %v\n", err)
		return 1
	}
	defer func() { _ = srv.Terminate(context.Background()) }()

	if _, err := srv.Bootstrap(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: bootstrap admin PAT: %v\n", err)
		return 1
	}

	return m.Run()
}
