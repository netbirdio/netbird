package peer

import (
	"os"
	"sync"
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
	_ = util.InitLog("trace", "console")
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

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		<-conn.handshaker.remoteOffersCh
		wg.Done()
	}()

	go func() {
		for {
			accepted := conn.OnRemoteOffer(OfferAnswer{
				IceCredentials: IceCredentials{
					UFrag: "test",
					Pwd:   "test",
				},
				WgListenPort: 0,
				Version:      "",
			})
			if accepted {
				wg.Done()
				return
			}
		}
	}()

	wg.Wait()
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

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		<-conn.handshaker.remoteAnswerCh
		wg.Done()
	}()

	go func() {
		for {
			accepted := conn.OnRemoteAnswer(OfferAnswer{
				IceCredentials: IceCredentials{
					UFrag: "test",
					Pwd:   "test",
				},
				WgListenPort: 0,
				Version:      "",
			})
			if accepted {
				wg.Done()
				return
			}
		}
	}()

	wg.Wait()
}
