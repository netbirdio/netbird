// Package peerlivenesstest provides peer liveness controllers for tests.
package peerlivenesstest

import (
	"context"

	"github.com/netbirdio/netbird/management/internals/controllers/peerliveness"
	"github.com/netbirdio/netbird/management/internals/controllers/peerliveness/controller"
)

// TB is the part of testing.TB the helpers need, so harnesses with their own test
// interface can use them.
type TB interface {
	Helper()
	Cleanup(func())
	Fatalf(format string, args ...any)
}

// NewStarted returns a controller over store that is already started and releases it when
// the test ends. Releasing it earlier is safe.
func NewStarted(t TB, store peerliveness.Store) peerliveness.Controller {
	t.Helper()

	liveness := controller.NewController(store)
	if err := liveness.Start(context.Background()); err != nil {
		t.Fatalf("start peer liveness: %v", err)
	}
	t.Cleanup(func() { _ = liveness.Release(context.Background()) })
	return liveness
}
