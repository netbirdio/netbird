package lifecycle

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStopHandlers_RunOnceInReverseOrder(t *testing.T) {
	var h StopHandlers
	var order []string
	h.OnStop(func() { order = append(order, "first") })
	h.OnStop(func() { order = append(order, "second") })

	h.RunStopHandlers()
	h.RunStopHandlers()

	assert.Equal(t, []string{"second", "first"}, order, "handlers must run once, last registered first")
}

func TestStopHandlers_PanicDoesNotSkipRemainingHandlers(t *testing.T) {
	var h StopHandlers
	var order []string
	h.OnStop(func() { order = append(order, "first") })
	h.OnStop(func() { panic("boom") })
	h.OnStop(func() { order = append(order, "third") })

	h.RunStopHandlers()

	assert.Equal(t, []string{"third", "first"}, order, "handlers around a panicking one must still run")
}

func TestStopHandlers_LateRegistrationRunsImmediately(t *testing.T) {
	var h StopHandlers
	h.RunStopHandlers()

	runs := 0
	h.OnStop(func() { runs++ })
	assert.Equal(t, 1, runs, "a handler registered after the stop must run right away")

	h.RunStopHandlers()
	assert.Equal(t, 1, runs, "later runs must stay no-ops and must not repeat the handler")
}
