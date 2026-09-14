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
