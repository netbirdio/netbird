package internal

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/lazyconn"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/peerstore"
	"github.com/netbirdio/netbird/monotime"
)

func TestResolveLazyForce(t *testing.T) {
	tests := []struct {
		name   string
		env    string
		envSet bool
		mdm    lazyconn.State
		want   lazyForce
	}{
		{name: "env unset, mdm unset -> defer to management", mdm: lazyconn.StateUnset, want: lazyForceNone},
		{name: "env on -> force on", env: "on", envSet: true, mdm: lazyconn.StateUnset, want: lazyForceOn},
		{name: "env off -> force off", env: "off", envSet: true, mdm: lazyconn.StateUnset, want: lazyForceOff},
		{name: "env unset, mdm on -> force on", mdm: lazyconn.StateOn, want: lazyForceOn},
		{name: "env unset, mdm off -> force off", mdm: lazyconn.StateOff, want: lazyForceOff},
		{name: "env on beats mdm off", env: "on", envSet: true, mdm: lazyconn.StateOff, want: lazyForceOn},
		{name: "env off beats mdm on", env: "off", envSet: true, mdm: lazyconn.StateOn, want: lazyForceOff},
		{name: "unrecognized env, mdm on -> mdm wins", env: "auto", envSet: true, mdm: lazyconn.StateOn, want: lazyForceOn},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(lazyconn.EnvLazyConn, tt.env)
			if !tt.envSet {
				os.Unsetenv(lazyconn.EnvLazyConn)
			}

			if got := resolveLazyForce(tt.mdm); got != tt.want {
				t.Fatalf("resolveLazyForce(%v) = %v, want %v", tt.mdm, got, tt.want)
			}
		})
	}
}

type mockLazyWGIface struct{}

func (mockLazyWGIface) RemovePeer(string) error { return nil }
func (mockLazyWGIface) UpdatePeer(string, []netip.Prefix, time.Duration, *net.UDPAddr, *wgtypes.Key) error {
	return nil
}
func (mockLazyWGIface) IsUserspaceBind() bool                    { return false }
func (mockLazyWGIface) Address() wgaddr.Address                  { return wgaddr.Address{} }
func (mockLazyWGIface) LastActivities() map[string]monotime.Time { return nil }
func (mockLazyWGIface) MTU() uint16                              { return 1280 }

// TestConnMgr_ActivatePeerConcurrentWithLifecycle exercises ActivatePeer from
// non-engine goroutines (the DNS warm-up path) racing the manager lifecycle,
// which stays on the engine loop. Run with -race: it fails if ActivatePeer
// still requires engine.syncMsgMux for safety.
func TestConnMgr_ActivatePeerConcurrentWithLifecycle(t *testing.T) {
	t.Setenv(lazyconn.EnvLazyConn, "on")

	status := peer.NewRecorder("https://mgm")
	store := peerstore.NewConnStore()
	connMgr := NewConnMgr(&EngineConfig{}, status, store, mockLazyWGIface{})

	conn := newTestPeerConn(t, "peerA")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	connMgr.Start(ctx)

	done := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					connMgr.ActivatePeer(ctx, conn)
				}
			}
		}()
	}

	// Let the activators spin against the started manager, then tear it down
	// underneath them and let them spin against the stopped manager.
	time.Sleep(100 * time.Millisecond)
	connMgr.Close()
	time.Sleep(50 * time.Millisecond)

	close(done)
	wg.Wait()
}
