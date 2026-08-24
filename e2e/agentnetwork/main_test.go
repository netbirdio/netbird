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
	"github.com/netbirdio/netbird/shared/management/http/api"
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

	// Bootstrap the account's agent-network endpoint once for the package:
	// providers no longer have settings side effects, and every data-plane
	// test expects the shared account pinned to the combined proxy cluster.
	cluster := harness.AgentNetworkCluster
	if _, err := srv.CreateSettings(ctx, api.AgentNetworkSettingsCreateRequest{ProxyAddress: &cluster}); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: bootstrap agent-network endpoint: %v\n", err)
		return 1
	}

	return m.Run()
}

// waitBeforeRetry pauses between attempts of a polling loop and reports
// whether the caller should keep going. A cancelled context ends the loop
// where a plain sleep would keep retrying against it: every call fails
// instantly once ctx is done, so the loop would spend its whole remaining
// window sleeping between failures nobody is waiting for any more.
func waitBeforeRetry(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
