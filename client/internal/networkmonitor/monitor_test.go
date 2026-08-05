package networkmonitor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

type MocMultiEvent struct {
	counter int
}

func (m *MocMultiEvent) checkChange(ctx context.Context, nexthopv4, nexthopv6 systemops.Nexthop) error {
	if m.counter == 0 {
		<-ctx.Done()
		return ctx.Err()
	}

	time.Sleep(1 * time.Second)
	m.counter--
	return nil
}

func TestNetworkMonitor_Close(t *testing.T) {
	checkChangeFn = func(ctx context.Context, nexthopv4, nexthopv6 systemops.Nexthop) error {
		<-ctx.Done()
		return ctx.Err()
	}
	nw := New()

	var resErr error
	done := make(chan struct{})
	go func() {
		resErr = nw.Listen(context.Background())
		close(done)
	}()

	time.Sleep(1 * time.Second) // wait for the goroutine to start
	nw.Stop()

	<-done
	if !errors.Is(resErr, context.Canceled) {
		t.Errorf("unexpected error: %v", resErr)
	}
}

func TestNetworkMonitor_Event(t *testing.T) {
	checkChangeFn = func(ctx context.Context, nexthopv4, nexthopv6 systemops.Nexthop) error {
		timeout, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout.Done():
			return nil
		}
	}
	nw := New()
	nw.nexthopChanged = func(_, _ systemops.Nexthop) bool { return true }
	defer nw.Stop()

	var resErr error
	done := make(chan struct{})
	go func() {
		resErr = nw.Listen(context.Background())
		close(done)
	}()

	<-done
	if !errors.Is(resErr, nil) {
		t.Errorf("unexpected error: %v", nil)
	}
}

func TestNetworkMonitor_MultiEvent(t *testing.T) {
	eventsRepeated := 3
	me := &MocMultiEvent{counter: eventsRepeated}
	checkChangeFn = me.checkChange

	nw := New()
	nw.nexthopChanged = func(_, _ systemops.Nexthop) bool { return true }
	defer nw.Stop()

	done := make(chan struct{})
	started := time.Now()
	go func() {
		if resErr := nw.Listen(context.Background()); resErr != nil {
			t.Errorf("unexpected error: %v", resErr)
		}
		close(done)
	}()

	<-done
	expectedResponseTime := time.Duration(eventsRepeated)*time.Second + debounceTime
	if time.Since(started) < expectedResponseTime {
		t.Errorf("unexpected duration: %v", time.Since(started))
	}
}

func TestSameNexthop(t *testing.T) {
	eth0 := &net.Interface{Index: 1, Name: "eth0"}
	eth1 := &net.Interface{Index: 2, Name: "eth1"}
	ip1 := netip.MustParseAddr("192.168.1.1")
	ip2 := netip.MustParseAddr("192.168.2.1")

	tests := []struct {
		name string
		a, b systemops.Nexthop
		want bool
	}{
		{"identical", systemops.Nexthop{IP: ip1, Intf: eth0}, systemops.Nexthop{IP: ip1, Intf: eth0}, true},
		{"same index different pointer", systemops.Nexthop{IP: ip1, Intf: eth0}, systemops.Nexthop{IP: ip1, Intf: &net.Interface{Index: 1, Name: "eth0"}}, true},
		{"different ip", systemops.Nexthop{IP: ip1, Intf: eth0}, systemops.Nexthop{IP: ip2, Intf: eth0}, false},
		{"different interface", systemops.Nexthop{IP: ip1, Intf: eth0}, systemops.Nexthop{IP: ip1, Intf: eth1}, false},
		{"both nil interface", systemops.Nexthop{IP: ip1}, systemops.Nexthop{IP: ip1}, true},
		{"one nil interface", systemops.Nexthop{IP: ip1, Intf: eth0}, systemops.Nexthop{IP: ip1}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sameNexthop(tt.a, tt.b); got != tt.want {
				t.Errorf("sameNexthop() = %v, want %v", got, tt.want)
			}
		})
	}
}
