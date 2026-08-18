package client

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/netstate"
)

func TestWaitForNetworkSettlesAfterOutage(t *testing.T) {
	ns := netstate.New()
	ns.Set(false)
	g := NewGuard(nil, 0, ns)

	const outage = 2 * verdictSettleWindow
	go func() {
		time.Sleep(outage)
		ns.Set(true)
	}()

	start := time.Now()
	ok := g.waitForNetwork(context.Background())
	elapsed := time.Since(start)

	assert.True(t, ok, "recovered network must let the quick reconnect proceed")
	assert.GreaterOrEqual(t, elapsed, outage+verdictSettleWindow, "reconnect must wait a full settle window after the network returns")
}
