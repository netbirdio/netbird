package peer

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/magiconair/properties/assert"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/client/internal/wgproxy"
	"github.com/netbirdio/netbird/iface"
	relayClient "github.com/netbirdio/netbird/relay/client"
	"github.com/netbirdio/netbird/util"
)

var connConf = ConnConfig{
	Key:         "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
	LocalKey:    "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
	Timeout:     time.Second,
	LocalWgPort: 51820,
	ICEConfig: ICEConfig{
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
	wgProxyFactory := wgproxy.NewFactory(context.Background(), connConf.LocalWgPort)
	defer func() {
		_ = wgProxyFactory.Free()
	}()
	conn, err := NewConn(context.Background(), connConf, nil, wgProxyFactory, nil, nil, nil)
	if err != nil {
		return
	}

	got := conn.GetKey()

	assert.Equal(t, got, connConf.Key, "they should be equal")
}

func TestConn_OnRemoteOffer(t *testing.T) {
	wgProxyFactory := wgproxy.NewFactory(context.Background(), connConf.LocalWgPort)
	defer func() {
		_ = wgProxyFactory.Free()
	}()
	conn, err := NewConn(context.Background(), connConf, NewRecorder("https://mgm"), wgProxyFactory, nil, nil, nil)
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
	wgProxyFactory := wgproxy.NewFactory(context.Background(), connConf.LocalWgPort)
	defer func() {
		_ = wgProxyFactory.Free()
	}()
	conn, err := NewConn(context.Background(), connConf, NewRecorder("https://mgm"), wgProxyFactory, nil, nil, nil)
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
func TestConn_Status(t *testing.T) {
	wgProxyFactory := wgproxy.NewFactory(context.Background(), connConf.LocalWgPort)
	defer func() {
		_ = wgProxyFactory.Free()
	}()
	conn, err := NewConn(context.Background(), connConf, NewRecorder("https://mgm"), wgProxyFactory, nil, nil, nil)
	if err != nil {
		return
	}

	tables := []struct {
		name        string
		statusIce   ConnStatus
		statusRelay ConnStatus
		want        ConnStatus
	}{
		{"StatusConnected", StatusConnected, StatusConnected, StatusConnected},
		{"StatusDisconnected", StatusDisconnected, StatusDisconnected, StatusDisconnected},
		{"StatusConnecting", StatusConnecting, StatusConnecting, StatusConnecting},
		{"StatusConnectingIce", StatusConnecting, StatusDisconnected, StatusConnecting},
		{"StatusConnectingIceAlternative", StatusConnecting, StatusConnected, StatusConnected},
		{"StatusConnectingRelay", StatusDisconnected, StatusConnecting, StatusConnecting},
		{"StatusConnectingRelayAlternative", StatusConnected, StatusConnecting, StatusConnected},
	}

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			conn.statusICE = table.statusIce
			conn.statusRelay = table.statusRelay

			got := conn.Status()
			assert.Equal(t, got, table.want, "they should be equal")
		})
	}
}

func TestConn_Switch(t *testing.T) {
	ctx := context.Background()

	wgProxyFactory := wgproxy.NewFactory(ctx, connConf.LocalWgPort)
	connConfAlice := ConnConfig{
		Key:         "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		LocalKey:    "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		Timeout:     time.Second,
		LocalWgPort: 51820,
		ICEConfig: ICEConfig{
			InterfaceBlackList: nil,
		},
		WgConfig: WgConfig{
			WgListenPort: 51820,
			RemoteKey:    "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
			AllowedIps:   "172.16.254.0/16",
		},
	}
	relayManagerAlice := relayClient.NewManager(ctx, "127.0.0.1:1234", connConf.LocalKey)
	connAlice, err := NewConn(ctx, connConfAlice, NewRecorder("https://mgm"), wgProxyFactory, nil, nil, relayManagerAlice)
	if err != nil {
		log.Fatalf("failed to create conn: %v", err)
	}
	connAlice.Open()

	connConfbob := ConnConfig{
		Key:         "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		LocalKey:    "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		Timeout:     time.Second,
		LocalWgPort: 51820,
		ICEConfig: ICEConfig{
			InterfaceBlackList: nil,
		},
		WgConfig: WgConfig{
			WgListenPort: 51820,
			RemoteKey:    "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
			AllowedIps:   "172.16.254.0/16",
		},
	}
	relayManagerBob := relayClient.NewManager(ctx, "127.0.0.1:1234", connConf.LocalKey)
	connBob, err := NewConn(ctx, connConfbob, NewRecorder("https://mgm"), wgProxyFactory, nil, nil, relayManagerBob)
	if err != nil {
		log.Fatalf("failed to create conn: %v", err)
	}
	connBob.Open()
}
