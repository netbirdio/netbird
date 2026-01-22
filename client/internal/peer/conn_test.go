package peer

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/internal/peer/dispatcher"
	"github.com/netbirdio/netbird/client/internal/peer/guard"
	"github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/util"
	semaphoregroup "github.com/netbirdio/netbird/util/semaphore-group"
)

var testDispatcher = dispatcher.NewConnectionDispatcher()

var connConf = ConnConfig{
	Key:         "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
	LocalKey:    "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
	Timeout:     time.Second,
	LocalWgPort: 51820,
	ICEConfig: ice.Config{
		InterfaceBlackList: nil,
	},
}

func TestMain(m *testing.M) {
	_ = util.InitLog("trace", util.LogConsole)
	code := m.Run()
	os.Exit(code)
}

func TestNewConn_interfaceFilter(t *testing.T) {
	ignore := []string{iface.WgInterfaceDefault, "tun0", "zt", "ZeroTier", "utun", "wg", "ts",
		"Tailscale", "tailscale"}

	filter := stdnet.InterfaceFilter(ignore)

	for _, s := range ignore {
		assert.Equal(t, filter(s), false)
	}

}

func TestConn_GetKey(t *testing.T) {
	swWatcher := guard.NewSRWatcher(nil, nil, nil, connConf.ICEConfig)

	sd := ServiceDependencies{
		SrWatcher:          swWatcher,
		Semaphore:          semaphoregroup.NewSemaphoreGroup(1),
		PeerConnDispatcher: testDispatcher,
	}
	conn, err := NewConn(connConf, sd)
	if err != nil {
		return
	}

	got := conn.GetKey()

	assert.Equal(t, got, connConf.Key, "they should be equal")
}

func TestConn_OnRemoteOffer(t *testing.T) {
	swWatcher := guard.NewSRWatcher(nil, nil, nil, connConf.ICEConfig)
	sd := ServiceDependencies{
		StatusRecorder:     NewRecorder("https://mgm"),
		SrWatcher:          swWatcher,
		Semaphore:          semaphoregroup.NewSemaphoreGroup(1),
		PeerConnDispatcher: testDispatcher,
	}
	conn, err := NewConn(connConf, sd)
	if err != nil {
		return
	}

	onNewOfferChan := make(chan struct{})

	conn.handshaker.AddRelayListener(func(remoteOfferAnswer *OfferAnswer) {
		onNewOfferChan <- struct{}{}
	})

	conn.OnRemoteOffer(OfferAnswer{
		IceCredentials: IceCredentials{
			UFrag: "test",
			Pwd:   "test",
		},
		WgListenPort: 0,
		Version:      "",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	select {
	case <-onNewOfferChan:
		// success
	case <-ctx.Done():
		t.Error("expected to receive a new offer notification, but timed out")
	}
}

func TestConn_OnRemoteAnswer(t *testing.T) {
	swWatcher := guard.NewSRWatcher(nil, nil, nil, connConf.ICEConfig)
	sd := ServiceDependencies{
		StatusRecorder:     NewRecorder("https://mgm"),
		SrWatcher:          swWatcher,
		Semaphore:          semaphoregroup.NewSemaphoreGroup(1),
		PeerConnDispatcher: testDispatcher,
	}
	conn, err := NewConn(connConf, sd)
	if err != nil {
		return
	}

	onNewOfferChan := make(chan struct{})

	conn.handshaker.AddRelayListener(func(remoteOfferAnswer *OfferAnswer) {
		onNewOfferChan <- struct{}{}
	})

	conn.OnRemoteAnswer(OfferAnswer{
		IceCredentials: IceCredentials{
			UFrag: "test",
			Pwd:   "test",
		},
		WgListenPort: 0,
		Version:      "",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	select {
	case <-onNewOfferChan:
		// success
	case <-ctx.Done():
		t.Error("expected to receive a new offer notification, but timed out")
	}
}

func TestConn_presharedKey(t *testing.T) {
	conn1 := Conn{
		config: ConnConfig{
			Key:             "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
			LocalKey:        "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
			RosenpassConfig: RosenpassConfig{},
		},
	}
	conn2 := Conn{
		config: ConnConfig{
			Key:             "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
			LocalKey:        "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
			RosenpassConfig: RosenpassConfig{},
		},
	}

	tests := []struct {
		conn1Permissive         bool
		conn1RosenpassEnabled   bool
		conn2Permissive         bool
		conn2RosenpassEnabled   bool
		conn1ExpectedInitialKey bool
		conn2ExpectedInitialKey bool
	}{
		{
			conn1Permissive:         false,
			conn1RosenpassEnabled:   false,
			conn2Permissive:         false,
			conn2RosenpassEnabled:   false,
			conn1ExpectedInitialKey: false,
			conn2ExpectedInitialKey: false,
		},
		{
			conn1Permissive:         false,
			conn1RosenpassEnabled:   true,
			conn2Permissive:         false,
			conn2RosenpassEnabled:   true,
			conn1ExpectedInitialKey: true,
			conn2ExpectedInitialKey: true,
		},
		{
			conn1Permissive:         false,
			conn1RosenpassEnabled:   true,
			conn2Permissive:         false,
			conn2RosenpassEnabled:   false,
			conn1ExpectedInitialKey: true,
			conn2ExpectedInitialKey: false,
		},
		{
			conn1Permissive:         false,
			conn1RosenpassEnabled:   false,
			conn2Permissive:         false,
			conn2RosenpassEnabled:   true,
			conn1ExpectedInitialKey: false,
			conn2ExpectedInitialKey: true,
		},
		{
			conn1Permissive:         true,
			conn1RosenpassEnabled:   true,
			conn2Permissive:         false,
			conn2RosenpassEnabled:   false,
			conn1ExpectedInitialKey: false,
			conn2ExpectedInitialKey: false,
		},
		{
			conn1Permissive:         false,
			conn1RosenpassEnabled:   false,
			conn2Permissive:         true,
			conn2RosenpassEnabled:   true,
			conn1ExpectedInitialKey: false,
			conn2ExpectedInitialKey: false,
		},
		{
			conn1Permissive:         true,
			conn1RosenpassEnabled:   true,
			conn2Permissive:         true,
			conn2RosenpassEnabled:   true,
			conn1ExpectedInitialKey: true,
			conn2ExpectedInitialKey: true,
		},
		{
			conn1Permissive:         false,
			conn1RosenpassEnabled:   false,
			conn2Permissive:         false,
			conn2RosenpassEnabled:   true,
			conn1ExpectedInitialKey: false,
			conn2ExpectedInitialKey: true,
		},
		{
			conn1Permissive:         false,
			conn1RosenpassEnabled:   true,
			conn2Permissive:         true,
			conn2RosenpassEnabled:   true,
			conn1ExpectedInitialKey: true,
			conn2ExpectedInitialKey: true,
		},
	}

	conn1.config.RosenpassConfig.PermissiveMode = true
	for i, test := range tests {
		tcase := i + 1
		t.Run(fmt.Sprintf("Rosenpass test case %d", tcase), func(t *testing.T) {
			conn1.config.RosenpassConfig = RosenpassConfig{}
			conn2.config.RosenpassConfig = RosenpassConfig{}

			if test.conn1RosenpassEnabled {
				conn1.config.RosenpassConfig.PubKey = []byte("dummykey")
			}
			conn1.config.RosenpassConfig.PermissiveMode = test.conn1Permissive

			if test.conn2RosenpassEnabled {
				conn2.config.RosenpassConfig.PubKey = []byte("dummykey")
			}
			conn2.config.RosenpassConfig.PermissiveMode = test.conn2Permissive

			conn1PresharedKey := conn1.presharedKey(conn2.config.RosenpassConfig.PubKey)
			conn2PresharedKey := conn2.presharedKey(conn1.config.RosenpassConfig.PubKey)

			if test.conn1ExpectedInitialKey {
				if conn1PresharedKey == nil {
					t.Errorf("Case %d: Expected conn1 to have a non-nil key, but got nil", tcase)
				}
			} else {
				if conn1PresharedKey != nil {
					t.Errorf("Case %d: Expected conn1 to have a nil key, but got %v", tcase, conn1PresharedKey)
				}
			}

			// Assert conn2's key expectation
			if test.conn2ExpectedInitialKey {
				if conn2PresharedKey == nil {
					t.Errorf("Case %d: Expected conn2 to have a non-nil key, but got nil", tcase)
				}
			} else {
				if conn2PresharedKey != nil {
					t.Errorf("Case %d: Expected conn2 to have a nil key, but got %v", tcase, conn2PresharedKey)
				}
			}
		})
	}
}

func TestConn_presharedKey_RosenpassManaged(t *testing.T) {
	conn := Conn{
		config: ConnConfig{
			Key:             "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
			LocalKey:        "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
			RosenpassConfig: RosenpassConfig{PubKey: []byte("dummykey")},
		},
	}

	// When Rosenpass has already initialized the PSK for this peer,
	// presharedKey must return nil to avoid UpdatePeer overwriting it.
	conn.rosenpassInitializedPresharedKeyValidator = func(peerKey string) bool { return true }
	if k := conn.presharedKey([]byte("remote")); k != nil {
		t.Fatalf("expected nil presharedKey when Rosenpass manages PSK, got %v", k)
	}

	// When Rosenpass hasn't taken over yet, presharedKey should provide
	// a non-nil initial key (deterministic or from NetBird PSK).
	conn.rosenpassInitializedPresharedKeyValidator = func(peerKey string) bool { return false }
	if k := conn.presharedKey([]byte("remote")); k == nil {
		t.Fatalf("expected non-nil presharedKey before Rosenpass manages PSK")
	}
}
