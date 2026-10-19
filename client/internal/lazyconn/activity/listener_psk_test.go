package activity

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
)

// pskRecordingIface records the preshared key each idle peer is installed with.
type pskRecordingIface struct {
	MocWGIface
	mu   sync.Mutex
	psks []*wgtypes.Key
}

func (r *pskRecordingIface) UpdatePeer(_ string, _ []netip.Prefix, _ time.Duration, _ *net.UDPAddr, psk *wgtypes.Key) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.psks = append(r.psks, psk)
	return nil
}

func (r *pskRecordingIface) installed() []*wgtypes.Key {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*wgtypes.Key(nil), r.psks...)
}

type idleListener interface {
	ReadPackets()
	Close()
}

func closeListener(t *testing.T, l idleListener) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		l.ReadPackets()
		close(done)
	}()
	l.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for ReadPackets to exit after Close")
	}
}

// TestListeners_InstallIdlePeerWithItsPresharedKey covers ML-KEM strict mode with lazy
// connections. An idle peer is installed in WireGuard so a handshake the remote initiates
// directly is accepted; installed without a key, a fresh peer accepted a classical session
// before any post-quantum exchange, breaking strict mode's promise. Both listeners must
// install the key the peer config provides, and leave it unchanged when there is none.
func TestListeners_InstallIdlePeerWithItsPresharedKey(t *testing.T) {
	sentinel := wgtypes.Key{1, 2, 3}
	newCfg := func(psk func() *wgtypes.Key) lazyconn.PeerConfig {
		peer := &MocPeer{PeerID: "testPeer1"}
		return lazyconn.PeerConfig{
			PublicKey:    peer.PeerID,
			PeerConnID:   peer.ConnID(),
			AllowedIPs:   []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
			Log:          log.WithField("peer", "testPeer1"),
			PresharedKey: psk,
		}
	}
	listeners := map[string]func(WgInterface, lazyconn.PeerConfig) (idleListener, error){
		"udp": func(iface WgInterface, cfg lazyconn.PeerConfig) (idleListener, error) {
			return NewUDPListener(iface, cfg)
		},
		"bind": func(iface WgInterface, cfg lazyconn.PeerConfig) (idleListener, error) {
			return NewBindListener(iface, newMockEndpointManager(), cfg)
		},
	}
	for name, newListener := range listeners {
		t.Run(name+"/with key", func(t *testing.T) {
			iface := &pskRecordingIface{}
			l, err := newListener(iface, newCfg(func() *wgtypes.Key { return &sentinel }))
			require.NoError(t, err)
			closeListener(t, l)

			installed := iface.installed()
			require.Len(t, installed, 1, "the idle peer must be installed once")
			require.NotNil(t, installed[0], "the idle peer must be installed with the provided key")
			assert.Equal(t, sentinel, *installed[0], "the idle peer must carry the provided key")
		})
		t.Run(name+"/without key", func(t *testing.T) {
			iface := &pskRecordingIface{}
			l, err := newListener(iface, newCfg(nil))
			require.NoError(t, err)
			closeListener(t, l)

			installed := iface.installed()
			require.Len(t, installed, 1, "the idle peer must be installed once")
			assert.Nil(t, installed[0], "without a key the idle peer's key must be left unchanged")
		})
	}
}
