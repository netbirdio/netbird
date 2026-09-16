//go:build e2e

// Package remotejobs holds the container-based e2e suite for the remote-jobs
// opt-in (PR #7153) and the debug-bundle job parameters anonymize_level /
// upload_url (PR #7147). A combined server is built and bootstrapped once per
// package run (TestMain) and shared via srv; each test registers its own client
// and cleans it up.
package remotejobs

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/netbirdio/netbird/e2e/harness"
)

// srv is the shared combined server for the package, PAT-authenticated by the
// time any Test runs.
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
