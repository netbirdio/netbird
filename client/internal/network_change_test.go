package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/networkmonitor"
	nbnet "github.com/netbirdio/netbird/client/net"
)

func TestCanHandleWithoutRestart(t *testing.T) {
	// The light path is available only with advanced routing and on a platform
	// that does not pin the underlay at start; everything else restarts.
	lightPath := nbnet.AdvancedRouting() && !underlayPinnedAtStart

	tests := []struct {
		name         string
		kind         networkmonitor.ChangeKind
		hasNetEvents bool
		want         bool
	}{
		{name: "unchanged underlay restarts", kind: networkmonitor.ChangeNone, hasNetEvents: true, want: false},
		{name: "no netevents manager restarts", kind: networkmonitor.ChangeGateway, hasNetEvents: false, want: false},
		{name: "gateway change", kind: networkmonitor.ChangeGateway, hasNetEvents: true, want: lightPath},
		{name: "interface change, as with a cable plugged in", kind: networkmonitor.ChangeInterface, hasNetEvents: true, want: lightPath},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			change := networkmonitor.Change{Kind: tt.kind}
			assert.Equal(t, tt.want, canHandleWithoutRestart(change, tt.hasNetEvents), "restart decision")
		})
	}
}
