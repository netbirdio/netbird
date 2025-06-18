package inactivity

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/netbirdio/netbird/util"
)

func init() {
	_ = util.InitLog("trace", "console")
}

func TestNewManager(t *testing.T) {
	for i, sc := range scenarios {
		timer := NewFakeTimer()
		newTicker = func(d time.Duration) Ticker {
			return newFakeTicker(d, timer)
		}

		t.Run(fmt.Sprintf("Scenario %d", i), func(t *testing.T) {
			mock := newMockWgInterface("peer1", sc.Data, timer)
			manager := NewManager(mock)
			manager.AddPeer("peer1")

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			manager.Start(ctx)

			var inactiveResult bool
			select {
			case <-manager.InactivePeersChan:
				inactiveResult = true
			default:
				inactiveResult = false
			}

			if inactiveResult != sc.ExpectedInactive {
				t.Errorf("Expected inactive peers: %v, got: %v", sc.ExpectedInactive, inactiveResult)
			}
		})
	}
}
