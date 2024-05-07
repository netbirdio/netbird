package peer

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/magiconair/properties/assert"
	"github.com/pion/stun/v2"

	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/client/internal/wgproxy"
	"github.com/netbirdio/netbird/iface"
)

var connConf = ConnConfig{
	Key:                "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
	LocalKey:           "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
	StunTurn:           []*stun.URI{},
	InterfaceBlackList: nil,
	Timeout:            time.Second,
	LocalWgPort:        51820,
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
	conn, err := NewConn(connConf, nil, wgProxyFactory, nil, nil)
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
	conn, err := NewConn(connConf, NewRecorder("https://mgm"), wgProxyFactory, nil, nil)
	if err != nil {
		return
	}

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		<-conn.remoteOffersCh
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
	conn, err := NewConn(connConf, NewRecorder("https://mgm"), wgProxyFactory, nil, nil)
	if err != nil {
		return
	}

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		<-conn.remoteAnswerCh
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
	conn, err := NewConn(connConf, NewRecorder("https://mgm"), wgProxyFactory, nil, nil)
	if err != nil {
		return
	}

	tables := []struct {
		name   string
		status ConnStatus
		want   ConnStatus
	}{
		{"StatusConnected", StatusConnected, StatusConnected},
		{"StatusDisconnected", StatusDisconnected, StatusDisconnected},
		{"StatusConnecting", StatusConnecting, StatusConnecting},
	}

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			conn.status = table.status

			got := conn.Status()
			assert.Equal(t, got, table.want, "they should be equal")
		})
	}
}

func TestConn_Close(t *testing.T) {
	wgProxyFactory := wgproxy.NewFactory(context.Background(), connConf.LocalWgPort)
	defer func() {
		_ = wgProxyFactory.Free()
	}()
	conn, err := NewConn(connConf, NewRecorder("https://mgm"), wgProxyFactory, nil, nil)
	if err != nil {
		return
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		<-conn.closeCh
		wg.Done()
	}()

	go func() {
		for {
			err := conn.Close()
			if err != nil {
				continue
			} else {
				return
			}
		}
	}()

	wg.Wait()
}
