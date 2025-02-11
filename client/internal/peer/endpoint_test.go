package peer

import (
	"net"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
)

type MockWgInterface struct {
	mock.Mock

	lastSetAddr *net.UDPAddr
}

func (m *MockWgInterface) GetStats(peerKey string) (configurer.WGStats, error) {
	panic("implement me")
}

func (m *MockWgInterface) GetProxy() wgproxy.Proxy {
	panic("implement me")
}

func (m *MockWgInterface) UpdatePeer(peerKey string, allowedIps string, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error {
	args := m.Called(peerKey, allowedIps, keepAlive, endpoint, preSharedKey)
	m.lastSetAddr = endpoint
	return args.Error(0)
}

func (m *MockWgInterface) RemovePeer(publicKey string) error {
	args := m.Called(publicKey)
	return args.Error(0)
}

func Test_endpointUpdater_initiator(t *testing.T) {
	mockWgInterface := &MockWgInterface{}
	e := &endpointUpdater{
		log: log.WithField("peer", "my-peer-key"),
		wgConfig: WgConfig{
			WgListenPort: 51820,
			RemoteKey:    "secret-remote-key",
			WgInterface:  mockWgInterface,
			AllowedIps:   "172.16.254.1",
		},
		initiator: true,
	}
	addr := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 1234,
	}

	mockWgInterface.On(
		"UpdatePeer",
		e.wgConfig.RemoteKey,
		e.wgConfig.AllowedIps,
		defaultWgKeepAlive,
		addr,
		(*wgtypes.Key)(nil),
	).Return(nil)

	if err := e.configureWGEndpoint(addr); err != nil {
		t.Fatalf("updateWireGuardPeer() failed: %v", err)
	}

	mockWgInterface.AssertCalled(t, "UpdatePeer", e.wgConfig.RemoteKey, e.wgConfig.AllowedIps, defaultWgKeepAlive, addr, (*wgtypes.Key)(nil))
}

func Test_endpointUpdater_nonInitiator(t *testing.T) {
	fallbackDelay = 1 * time.Second
	mockWgInterface := &MockWgInterface{}
	e := &endpointUpdater{
		log: log.WithField("peer", "my-peer-key"),
		wgConfig: WgConfig{
			WgListenPort: 51820,
			RemoteKey:    "secret-remote-key",
			WgInterface:  mockWgInterface,
			AllowedIps:   "172.16.254.1",
		},
		initiator: false,
	}
	addr := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 1234,
	}

	mockWgInterface.On(
		"UpdatePeer",
		e.wgConfig.RemoteKey,
		e.wgConfig.AllowedIps,
		defaultWgKeepAlive,
		(*net.UDPAddr)(nil),
		(*wgtypes.Key)(nil),
	).Return(nil)

	mockWgInterface.On(
		"UpdatePeer",
		e.wgConfig.RemoteKey,
		e.wgConfig.AllowedIps,
		defaultWgKeepAlive,
		addr,
		(*wgtypes.Key)(nil),
	).Return(nil)

	err := e.configureWGEndpoint(addr)
	if err != nil {
		t.Fatalf("updateWireGuardPeer() failed: %v", err)
	}
	mockWgInterface.AssertCalled(t, "UpdatePeer", e.wgConfig.RemoteKey, e.wgConfig.AllowedIps, defaultWgKeepAlive, (*net.UDPAddr)(nil), (*wgtypes.Key)(nil))

	time.Sleep(fallbackDelay + time.Second)

	mockWgInterface.AssertCalled(t, "UpdatePeer", e.wgConfig.RemoteKey, e.wgConfig.AllowedIps, defaultWgKeepAlive, addr, (*wgtypes.Key)(nil))
}

func Test_endpointUpdater_overRule(t *testing.T) {
	fallbackDelay = 1 * time.Second
	mockWgInterface := &MockWgInterface{}
	e := &endpointUpdater{
		log: log.WithField("peer", "my-peer-key"),
		wgConfig: WgConfig{
			WgListenPort: 51820,
			RemoteKey:    "secret-remote-key",
			WgInterface:  mockWgInterface,
			AllowedIps:   "172.16.254.1",
		},
		initiator: false,
	}
	addr1 := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 1000,
	}

	addr2 := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 1001,
	}

	mockWgInterface.On(
		"UpdatePeer",
		e.wgConfig.RemoteKey,
		e.wgConfig.AllowedIps,
		defaultWgKeepAlive,
		(*net.UDPAddr)(nil),
		(*wgtypes.Key)(nil),
	).Return(nil)

	mockWgInterface.On(
		"UpdatePeer",
		e.wgConfig.RemoteKey,
		e.wgConfig.AllowedIps,
		defaultWgKeepAlive,
		addr2,
		(*wgtypes.Key)(nil),
	).Return(nil)

	if err := e.configureWGEndpoint(addr1); err != nil {
		t.Fatalf("updateWireGuardPeer() failed: %v", err)
	}
	mockWgInterface.AssertCalled(t, "UpdatePeer", e.wgConfig.RemoteKey, e.wgConfig.AllowedIps, defaultWgKeepAlive, (*net.UDPAddr)(nil), (*wgtypes.Key)(nil))

	if err := e.configureWGEndpoint(addr2); err != nil {
		t.Fatalf("updateWireGuardPeer() failed: %v", err)
	}

	time.Sleep(fallbackDelay + time.Second)

	mockWgInterface.AssertCalled(t, "UpdatePeer", e.wgConfig.RemoteKey, e.wgConfig.AllowedIps, defaultWgKeepAlive, addr2, (*wgtypes.Key)(nil))

	if mockWgInterface.lastSetAddr != addr2 {
		t.Fatalf("lastSetAddr is not equal to addr2")
	}
}
