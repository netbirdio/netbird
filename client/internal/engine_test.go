package internal

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	wgdevice "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/management/server/job"

	"github.com/netbirdio/management-integrations/integrations"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/internals/modules/peers"
	"github.com/netbirdio/netbird/management/internals/modules/peers/ephemeral/manager"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"

	"github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/groups"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/udpmux"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/peer/guard"
	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/internal/routemanager"
	nbssh "github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/client/system"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/integrations/port_forwarding"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/monotime"
	"github.com/netbirdio/netbird/route"
	mgmt "github.com/netbirdio/netbird/shared/management/client"
	mgmtProto "github.com/netbirdio/netbird/shared/management/proto"
	relayClient "github.com/netbirdio/netbird/shared/relay/client"
	signal "github.com/netbirdio/netbird/shared/signal/client"
	"github.com/netbirdio/netbird/shared/signal/proto"
	signalServer "github.com/netbirdio/netbird/signal/server"
	"github.com/netbirdio/netbird/util"
)

var (
	kaep = keepalive.EnforcementPolicy{
		MinTime:             15 * time.Second,
		PermitWithoutStream: true,
	}

	kasp = keepalive.ServerParameters{
		MaxConnectionIdle:     15 * time.Second,
		MaxConnectionAgeGrace: 5 * time.Second,
		Time:                  5 * time.Second,
		Timeout:               2 * time.Second,
	}
)

type MockWGIface struct {
	CreateFunc                 func() error
	CreateOnAndroidFunc        func(routeRange []string, ip string, domains []string) error
	IsUserspaceBindFunc        func() bool
	NameFunc                   func() string
	AddressFunc                func() wgaddr.Address
	ToInterfaceFunc            func() *net.Interface
	UpFunc                     func() (*udpmux.UniversalUDPMuxDefault, error)
	UpdateAddrFunc             func(newAddr string) error
	UpdatePeerFunc             func(peerKey string, allowedIps []netip.Prefix, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error
	RemovePeerFunc             func(peerKey string) error
	AddAllowedIPFunc           func(peerKey string, allowedIP netip.Prefix) error
	RemoveAllowedIPFunc        func(peerKey string, allowedIP netip.Prefix) error
	CloseFunc                  func() error
	SetFilterFunc              func(filter device.PacketFilter) error
	GetFilterFunc              func() device.PacketFilter
	GetDeviceFunc              func() *device.FilteredDevice
	GetWGDeviceFunc            func() *wgdevice.Device
	GetStatsFunc               func() (map[string]configurer.WGStats, error)
	GetInterfaceGUIDStringFunc func() (string, error)
	GetProxyFunc               func() wgproxy.Proxy
	GetProxyPortFunc           func() uint16
	GetNetFunc                 func() *netstack.Net
	LastActivitiesFunc         func() map[string]monotime.Time
}

func (m *MockWGIface) RenewTun(_ int) error {
	return nil
}

func (m *MockWGIface) RemoveEndpointAddress(_ string) error {
	return nil
}

func (m *MockWGIface) FullStats() (*configurer.Stats, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockWGIface) GetInterfaceGUIDString() (string, error) {
	return m.GetInterfaceGUIDStringFunc()
}

func (m *MockWGIface) Create() error {
	return m.CreateFunc()
}

func (m *MockWGIface) CreateOnAndroid(routeRange []string, ip string, domains []string) error {
	return m.CreateOnAndroidFunc(routeRange, ip, domains)
}

func (m *MockWGIface) IsUserspaceBind() bool {
	return m.IsUserspaceBindFunc()
}

func (m *MockWGIface) Name() string {
	return m.NameFunc()
}

func (m *MockWGIface) Address() wgaddr.Address {
	return m.AddressFunc()
}

func (m *MockWGIface) ToInterface() *net.Interface {
	return m.ToInterfaceFunc()
}

func (m *MockWGIface) Up() (*udpmux.UniversalUDPMuxDefault, error) {
	return m.UpFunc()
}

func (m *MockWGIface) UpdateAddr(newAddr string) error {
	return m.UpdateAddrFunc(newAddr)
}

func (m *MockWGIface) UpdatePeer(peerKey string, allowedIps []netip.Prefix, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error {
	return m.UpdatePeerFunc(peerKey, allowedIps, keepAlive, endpoint, preSharedKey)
}

func (m *MockWGIface) RemovePeer(peerKey string) error {
	return m.RemovePeerFunc(peerKey)
}

func (m *MockWGIface) AddAllowedIP(peerKey string, allowedIP netip.Prefix) error {
	return m.AddAllowedIPFunc(peerKey, allowedIP)
}

func (m *MockWGIface) RemoveAllowedIP(peerKey string, allowedIP netip.Prefix) error {
	return m.RemoveAllowedIPFunc(peerKey, allowedIP)
}

func (m *MockWGIface) Close() error {
	return m.CloseFunc()
}

func (m *MockWGIface) SetFilter(filter device.PacketFilter) error {
	return m.SetFilterFunc(filter)
}

func (m *MockWGIface) GetFilter() device.PacketFilter {
	return m.GetFilterFunc()
}

func (m *MockWGIface) GetDevice() *device.FilteredDevice {
	return m.GetDeviceFunc()
}

func (m *MockWGIface) GetWGDevice() *wgdevice.Device {
	return m.GetWGDeviceFunc()
}

func (m *MockWGIface) GetStats() (map[string]configurer.WGStats, error) {
	return m.GetStatsFunc()
}

func (m *MockWGIface) GetProxy() wgproxy.Proxy {
	return m.GetProxyFunc()
}

func (m *MockWGIface) GetProxyPort() uint16 {
	if m.GetProxyPortFunc != nil {
		return m.GetProxyPortFunc()
	}
	return 0
}

func (m *MockWGIface) GetNet() *netstack.Net {
	return m.GetNetFunc()
}

func (m *MockWGIface) LastActivities() map[string]monotime.Time {
	if m.LastActivitiesFunc != nil {
		return m.LastActivitiesFunc()
	}
	return nil
}

func (m *MockWGIface) SetPresharedKey(peerKey string, psk wgtypes.Key, updateOnly bool) error {
	return nil
}

func TestMain(m *testing.M) {
	_ = util.InitLog("debug", util.LogConsole)
	code := m.Run()
	os.Exit(code)
}

func TestEngine_SSH(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}

	sshKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	if err != nil {
		t.Fatal(err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	relayMgr := relayClient.NewManager(ctx, nil, key.PublicKey().String(), iface.DefaultMTU)
	engine := NewEngine(
		ctx, cancel,
		&signal.MockClient{},
		&mgmt.MockClient{},
		relayMgr,
		&EngineConfig{
			WgIfaceName:      "utun101",
			WgAddr:           "100.64.0.1/24",
			WgPrivateKey:     key,
			WgPort:           33100,
			ServerSSHAllowed: true,
			MTU:              iface.DefaultMTU,
			SSHKey:           sshKey,
		},
		MobileDependency{},
		peer.NewRecorder("https://mgm"),
		nil,
		nil,
	)

	engine.dnsServer = &dns.MockServer{
		UpdateDNSServerFunc: func(serial uint64, update nbdns.Config) error { return nil },
	}

	err = engine.Start(nil, nil)
	require.NoError(t, err)

	defer func() {
		err := engine.Stop()
		if err != nil {
			return
		}
	}()

	peerWithSSH := &mgmtProto.RemotePeerConfig{
		WgPubKey:   "MNHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		AllowedIps: []string{"100.64.0.21/24"},
		SshConfig: &mgmtProto.SSHConfig{
			SshPubKey: []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFATYCqaQw/9id1Qkq3n16JYhDhXraI6Pc1fgB8ynEfQ"),
		},
	}

	// SSH server is not enabled so SSH config of a remote peer should be ignored
	networkMap := &mgmtProto.NetworkMap{
		Serial:             6,
		PeerConfig:         nil,
		RemotePeers:        []*mgmtProto.RemotePeerConfig{peerWithSSH},
		RemotePeersIsEmpty: false,
	}

	err = engine.updateNetworkMap(networkMap)
	require.NoError(t, err)

	assert.Nil(t, engine.sshServer)

	// SSH server is enabled, therefore SSH config should be applied
	networkMap = &mgmtProto.NetworkMap{
		Serial: 7,
		PeerConfig: &mgmtProto.PeerConfig{Address: "100.64.0.1/24",
			SshConfig: &mgmtProto.SSHConfig{
				SshEnabled: true,
				JwtConfig: &mgmtProto.JWTConfig{
					Issuer:       "test-issuer",
					Audience:     "test-audience",
					KeysLocation: "test-keys",
					MaxTokenAge:  3600,
				},
			}},
		RemotePeers:        []*mgmtProto.RemotePeerConfig{peerWithSSH},
		RemotePeersIsEmpty: false,
	}

	err = engine.updateNetworkMap(networkMap)
	require.NoError(t, err)

	time.Sleep(250 * time.Millisecond)
	assert.NotNil(t, engine.sshServer)

	// now remove peer
	networkMap = &mgmtProto.NetworkMap{
		Serial:             8,
		RemotePeers:        []*mgmtProto.RemotePeerConfig{},
		RemotePeersIsEmpty: false,
	}

	err = engine.updateNetworkMap(networkMap)
	require.NoError(t, err)

	// time.Sleep(250 * time.Millisecond)
	assert.NotNil(t, engine.sshServer)

	// now disable SSH server
	networkMap = &mgmtProto.NetworkMap{
		Serial: 9,
		PeerConfig: &mgmtProto.PeerConfig{Address: "100.64.0.1/24",
			SshConfig: &mgmtProto.SSHConfig{SshEnabled: false}},
		RemotePeers:        []*mgmtProto.RemotePeerConfig{peerWithSSH},
		RemotePeersIsEmpty: false,
	}

	err = engine.updateNetworkMap(networkMap)
	require.NoError(t, err)

	assert.Nil(t, engine.sshServer)
}

func TestEngine_SSHUpdateLogic(t *testing.T) {
	// Test that SSH server start/stop logic works based on config
	engine := &Engine{
		config: &EngineConfig{
			ServerSSHAllowed: false, // Start with SSH disabled
		},
		syncMsgMux: &sync.Mutex{},
	}

	// Test SSH disabled config
	sshConfig := &mgmtProto.SSHConfig{SshEnabled: false}
	err := engine.updateSSH(sshConfig)
	assert.NoError(t, err)
	assert.Nil(t, engine.sshServer)

	// Test inbound blocked
	engine.config.BlockInbound = true
	err = engine.updateSSH(&mgmtProto.SSHConfig{SshEnabled: true})
	assert.NoError(t, err)
	assert.Nil(t, engine.sshServer)
	engine.config.BlockInbound = false

	// Test with server SSH not allowed
	err = engine.updateSSH(&mgmtProto.SSHConfig{SshEnabled: true})
	assert.NoError(t, err)
	assert.Nil(t, engine.sshServer)
}

func TestEngine_SSHServerConsistency(t *testing.T) {

	t.Run("server set only on successful creation", func(t *testing.T) {
		engine := &Engine{
			config: &EngineConfig{
				ServerSSHAllowed: true,
				SSHKey:           []byte("test-key"),
			},
			syncMsgMux: &sync.Mutex{},
		}

		engine.wgInterface = nil

		err := engine.updateSSH(&mgmtProto.SSHConfig{SshEnabled: true})

		assert.Error(t, err)
		assert.Nil(t, engine.sshServer)
	})

	t.Run("cleanup handles nil gracefully", func(t *testing.T) {
		engine := &Engine{
			config: &EngineConfig{
				ServerSSHAllowed: false,
			},
			syncMsgMux: &sync.Mutex{},
		}

		err := engine.stopSSHServer()
		assert.NoError(t, err)
		assert.Nil(t, engine.sshServer)
	})
}

func TestEngine_UpdateNetworkMap(t *testing.T) {
	// test setup
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	relayMgr := relayClient.NewManager(ctx, nil, key.PublicKey().String(), iface.DefaultMTU)
	engine := NewEngine(ctx, cancel, &signal.MockClient{}, &mgmt.MockClient{}, relayMgr, &EngineConfig{
		WgIfaceName:  "utun102",
		WgAddr:       "100.64.0.1/24",
		WgPrivateKey: key,
		WgPort:       33100,
		MTU:          iface.DefaultMTU,
	}, MobileDependency{}, peer.NewRecorder("https://mgm"), nil, nil)

	wgIface := &MockWGIface{
		NameFunc: func() string { return "utun102" },
		RemovePeerFunc: func(peerKey string) error {
			return nil
		},
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("10.20.0.1"),
				Network: netip.MustParsePrefix("10.20.0.0/24"),
			}
		},
		UpdatePeerFunc: func(peerKey string, allowedIps []netip.Prefix, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error {
			return nil
		},
	}
	engine.wgInterface = wgIface
	engine.routeManager = routemanager.NewManager(routemanager.ManagerConfig{
		Context:          ctx,
		PublicKey:        key.PublicKey().String(),
		DNSRouteInterval: time.Minute,
		WGInterface:      engine.wgInterface,
		StatusRecorder:   engine.statusRecorder,
		RelayManager:     relayMgr,
	})
	err = engine.routeManager.Init()
	require.NoError(t, err)
	engine.dnsServer = &dns.MockServer{
		UpdateDNSServerFunc: func(serial uint64, update nbdns.Config) error { return nil },
	}
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	engine.udpMux = udpmux.NewUniversalUDPMuxDefault(udpmux.UniversalUDPMuxParams{UDPConn: conn, MTU: 1280})
	engine.ctx = ctx
	engine.srWatcher = guard.NewSRWatcher(nil, nil, nil, icemaker.Config{})
	engine.connMgr = NewConnMgr(engine.config, engine.statusRecorder, engine.peerStore, wgIface)
	engine.connMgr.Start(ctx)

	type testCase struct {
		name       string
		networkMap *mgmtProto.NetworkMap

		expectedLen    int
		expectedPeers  []*mgmtProto.RemotePeerConfig
		expectedSerial uint64
	}

	peer1 := &mgmtProto.RemotePeerConfig{
		WgPubKey:   "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		AllowedIps: []string{"100.64.0.10/24"},
	}

	peer2 := &mgmtProto.RemotePeerConfig{
		WgPubKey:   "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		AllowedIps: []string{"100.64.0.11/24"},
	}

	peer3 := &mgmtProto.RemotePeerConfig{
		WgPubKey:   "GGHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		AllowedIps: []string{"100.64.0.12/24"},
	}

	modifiedPeer3 := &mgmtProto.RemotePeerConfig{
		WgPubKey:   "GGHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		AllowedIps: []string{"100.64.0.20/24"},
	}

	case1 := testCase{
		name: "input with a new peer to add",
		networkMap: &mgmtProto.NetworkMap{
			Serial:     1,
			PeerConfig: nil,
			RemotePeers: []*mgmtProto.RemotePeerConfig{
				peer1,
			},
			RemotePeersIsEmpty: false,
		},
		expectedLen:    1,
		expectedPeers:  []*mgmtProto.RemotePeerConfig{peer1},
		expectedSerial: 1,
	}

	// 2nd case - one extra peer added and network map has CurrentSerial grater than local => apply the update
	case2 := testCase{
		name: "input with an old peer and a new peer to add",
		networkMap: &mgmtProto.NetworkMap{
			Serial:     2,
			PeerConfig: nil,
			RemotePeers: []*mgmtProto.RemotePeerConfig{
				peer1, peer2,
			},
			RemotePeersIsEmpty: false,
		},
		expectedLen:    2,
		expectedPeers:  []*mgmtProto.RemotePeerConfig{peer1, peer2},
		expectedSerial: 2,
	}

	case3 := testCase{
		name: "input with outdated (old) update to ignore",
		networkMap: &mgmtProto.NetworkMap{
			Serial:     0,
			PeerConfig: nil,
			RemotePeers: []*mgmtProto.RemotePeerConfig{
				peer1, peer2, peer3,
			},
			RemotePeersIsEmpty: false,
		},
		expectedLen:    2,
		expectedPeers:  []*mgmtProto.RemotePeerConfig{peer1, peer2},
		expectedSerial: 2,
	}

	case4 := testCase{
		name: "input with one peer to remove and one new to add",
		networkMap: &mgmtProto.NetworkMap{
			Serial:     4,
			PeerConfig: nil,
			RemotePeers: []*mgmtProto.RemotePeerConfig{
				peer2, peer3,
			},
			RemotePeersIsEmpty: false,
		},
		expectedLen:    2,
		expectedPeers:  []*mgmtProto.RemotePeerConfig{peer2, peer3},
		expectedSerial: 4,
	}

	case5 := testCase{
		name: "input with one peer to modify",
		networkMap: &mgmtProto.NetworkMap{
			Serial:     4,
			PeerConfig: nil,
			RemotePeers: []*mgmtProto.RemotePeerConfig{
				modifiedPeer3, peer2,
			},
			RemotePeersIsEmpty: false,
		},
		expectedLen:    2,
		expectedPeers:  []*mgmtProto.RemotePeerConfig{peer2, modifiedPeer3},
		expectedSerial: 4,
	}

	case6 := testCase{
		name: "input with all peers to remove",
		networkMap: &mgmtProto.NetworkMap{
			Serial:             5,
			PeerConfig:         nil,
			RemotePeers:        []*mgmtProto.RemotePeerConfig{},
			RemotePeersIsEmpty: true,
		},
		expectedLen:    0,
		expectedPeers:  nil,
		expectedSerial: 5,
	}

	for _, c := range []testCase{case1, case2, case3, case4, case5, case6} {
		t.Run(c.name, func(t *testing.T) {
			err = engine.updateNetworkMap(c.networkMap)
			if err != nil {
				t.Fatal(err)
				return
			}

			if len(engine.peerStore.PeersPubKey()) != c.expectedLen {
				t.Errorf("expecting Engine.peerConns to be of size %d, got %d", c.expectedLen, len(engine.peerStore.PeersPubKey()))
			}

			if engine.networkSerial != c.expectedSerial {
				t.Errorf("expecting Engine.networkSerial to be equal to %d, actual %d", c.expectedSerial, engine.networkSerial)
			}

			for _, p := range c.expectedPeers {
				conn, ok := engine.peerStore.PeerConn(p.GetWgPubKey())
				if !ok {
					t.Errorf("expecting Engine.peerConns to contain peer %s", p)
				}
				expectedAllowedIPs := strings.Join(p.AllowedIps, ",")
				if !compareNetIPLists(conn.WgConfig().AllowedIps, p.AllowedIps) {
					t.Errorf("expecting peer %s to have AllowedIPs= %s, got %s", p.GetWgPubKey(),
						expectedAllowedIPs, conn.WgConfig().AllowedIps)
				}
			}
		})
	}
}

func TestEngine_Sync(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// feed updates to Engine via mocked Management client
	updates := make(chan *mgmtProto.SyncResponse)
	defer close(updates)
	syncFunc := func(ctx context.Context, info *system.Info, msgHandler func(msg *mgmtProto.SyncResponse) error) error {
		for msg := range updates {
			err := msgHandler(msg)
			if err != nil {
				t.Fatal(err)
			}
		}
		return nil
	}
	relayMgr := relayClient.NewManager(ctx, nil, key.PublicKey().String(), iface.DefaultMTU)
	engine := NewEngine(ctx, cancel, &signal.MockClient{}, &mgmt.MockClient{SyncFunc: syncFunc}, relayMgr, &EngineConfig{
		WgIfaceName:  "utun103",
		WgAddr:       "100.64.0.1/24",
		WgPrivateKey: key,
		WgPort:       33100,
		MTU:          iface.DefaultMTU,
	}, MobileDependency{}, peer.NewRecorder("https://mgm"), nil, nil)
	engine.ctx = ctx

	engine.dnsServer = &dns.MockServer{
		UpdateDNSServerFunc: func(serial uint64, update nbdns.Config) error { return nil },
	}

	defer func() {
		err := engine.Stop()
		if err != nil {
			return
		}
	}()

	err = engine.Start(nil, nil)
	if err != nil {
		t.Fatal(err)
		return
	}

	peer1 := &mgmtProto.RemotePeerConfig{
		WgPubKey:   "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		AllowedIps: []string{"100.64.0.10/24"},
	}
	peer2 := &mgmtProto.RemotePeerConfig{
		WgPubKey:   "LLHf3Ma6z6mdLbriAJbqhX9+nM/B71lgw2+91q3LlhU=",
		AllowedIps: []string{"100.64.0.11/24"},
	}
	peer3 := &mgmtProto.RemotePeerConfig{
		WgPubKey:   "GGHf3Ma6z6mdLbriAJbqhX9+nM/B71lgw2+91q3LlhU=",
		AllowedIps: []string{"100.64.0.12/24"},
	}
	// 1st update with just 1 peer and serial larger than the current serial of the engine => apply update
	updates <- &mgmtProto.SyncResponse{
		NetworkMap: &mgmtProto.NetworkMap{
			Serial:             10,
			PeerConfig:         nil,
			RemotePeers:        []*mgmtProto.RemotePeerConfig{peer1, peer2, peer3},
			RemotePeersIsEmpty: false,
		},
	}

	timeout := time.After(time.Second * 2)
	for {
		select {
		case <-timeout:
			t.Fatalf("timeout while waiting for test to finish")
			return
		default:
		}

		if getPeers(engine) == 3 && engine.networkSerial == 10 {
			break
		}
	}
}

func TestEngine_UpdateNetworkMapWithRoutes(t *testing.T) {
	testCases := []struct {
		name                 string
		inputErr             error
		networkMap           *mgmtProto.NetworkMap
		expectedLen          int
		expectedClientRoutes route.HAMap
		expectedSerial       uint64
	}{
		{
			name: "Routes Config Should Be Passed To Manager",
			networkMap: &mgmtProto.NetworkMap{
				Serial:             1,
				PeerConfig:         nil,
				RemotePeersIsEmpty: false,
				Routes: []*mgmtProto.Route{
					{
						ID:          "a",
						Network:     "192.168.0.0/24",
						NetID:       "n1",
						Peer:        "p1",
						NetworkType: 1,
						Masquerade:  false,
					},
					{
						ID:          "b",
						Network:     "192.168.1.0/24",
						NetID:       "n2",
						Peer:        "p1",
						NetworkType: 1,
						Masquerade:  false,
					},
				},
			},
			expectedLen: 2,
			expectedClientRoutes: route.HAMap{
				"n1|192.168.0.0/24": []*route.Route{
					{
						ID:          "a",
						Network:     netip.MustParsePrefix("192.168.0.0/24"),
						NetID:       "n1",
						Peer:        "p1",
						NetworkType: 1,
						Masquerade:  false,
					},
				},
				"n2|192.168.1.0/24": []*route.Route{
					{
						ID:          "b",
						Network:     netip.MustParsePrefix("192.168.1.0/24"),
						NetID:       "n2",
						Peer:        "p1",
						NetworkType: 1,
						Masquerade:  false,
					},
				},
			},
			expectedSerial: 1,
		},
		{
			name: "Empty Routes Config Should Be Passed",
			networkMap: &mgmtProto.NetworkMap{
				Serial:             1,
				PeerConfig:         nil,
				RemotePeersIsEmpty: false,
				Routes:             nil,
			},
			expectedLen:          0,
			expectedClientRoutes: nil,
			expectedSerial:       1,
		},
		{
			name:     "Error Shouldn't Break Engine",
			inputErr: fmt.Errorf("mocking error"),
			networkMap: &mgmtProto.NetworkMap{
				Serial:             1,
				PeerConfig:         nil,
				RemotePeersIsEmpty: false,
				Routes:             nil,
			},
			expectedLen:          0,
			expectedClientRoutes: nil,
			expectedSerial:       1,
		},
	}

	for n, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// test setup
			key, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				t.Fatal(err)
				return
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			wgIfaceName := fmt.Sprintf("utun%d", 104+n)
			wgAddr := fmt.Sprintf("100.66.%d.1/24", n)

			relayMgr := relayClient.NewManager(ctx, nil, key.PublicKey().String(), iface.DefaultMTU)
			engine := NewEngine(ctx, cancel, &signal.MockClient{}, &mgmt.MockClient{}, relayMgr, &EngineConfig{
				WgIfaceName:  wgIfaceName,
				WgAddr:       wgAddr,
				WgPrivateKey: key,
				WgPort:       33100,
				MTU:          iface.DefaultMTU,
			}, MobileDependency{}, peer.NewRecorder("https://mgm"), nil, nil)
			engine.ctx = ctx
			newNet, err := stdnet.NewNet(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}

			opts := iface.WGIFaceOpts{
				IFaceName:    wgIfaceName,
				Address:      wgAddr,
				WGPort:       engine.config.WgPort,
				WGPrivKey:    key.String(),
				MTU:          iface.DefaultMTU,
				TransportNet: newNet,
			}
			engine.wgInterface, err = iface.NewWGIFace(opts)
			assert.NoError(t, err, "shouldn't return error")
			input := struct {
				inputSerial  uint64
				clientRoutes route.HAMap
			}{}

			mockRouteManager := &routemanager.MockManager{
				UpdateRoutesFunc: func(updateSerial uint64, serverRoutes map[route.ID]*route.Route, clientRoutes route.HAMap, useNewDNSRoute bool) error {
					input.inputSerial = updateSerial
					input.clientRoutes = clientRoutes
					return testCase.inputErr
				},
				ClassifyRoutesFunc: func(newRoutes []*route.Route) (map[route.ID]*route.Route, route.HAMap) {
					if len(newRoutes) == 0 {
						return nil, nil
					}

					// Classify all routes as client routes (not matching our public key)
					clientRoutes := make(route.HAMap)
					for _, r := range newRoutes {
						haID := r.GetHAUniqueID()
						clientRoutes[haID] = append(clientRoutes[haID], r)
					}
					return nil, clientRoutes
				},
			}

			engine.routeManager = mockRouteManager
			engine.dnsServer = &dns.MockServer{}
			engine.connMgr = NewConnMgr(engine.config, engine.statusRecorder, engine.peerStore, engine.wgInterface)
			engine.connMgr.Start(ctx)

			defer func() {
				exitErr := engine.Stop()
				if exitErr != nil {
					return
				}
			}()

			err = engine.updateNetworkMap(testCase.networkMap)
			assert.NoError(t, err, "shouldn't return error")
			assert.Equal(t, testCase.expectedSerial, input.inputSerial, "serial should match")
			assert.Len(t, input.clientRoutes, testCase.expectedLen, "clientRoutes len should match")
			assert.Equal(t, testCase.expectedClientRoutes, input.clientRoutes, "clientRoutes should match")
		})
	}
}

func TestEngine_UpdateNetworkMapWithDNSUpdate(t *testing.T) {
	testCases := []struct {
		name                string
		inputErr            error
		networkMap          *mgmtProto.NetworkMap
		expectedZonesLen    int
		expectedZones       []nbdns.CustomZone
		expectedNSGroupsLen int
		expectedNSGroups    []*nbdns.NameServerGroup
		expectedSerial      uint64
	}{
		{
			name: "DNS Config Should Be Passed To DNS Server",
			networkMap: &mgmtProto.NetworkMap{
				Serial:             1,
				PeerConfig:         nil,
				RemotePeersIsEmpty: false,
				Routes:             nil,
				DNSConfig: &mgmtProto.DNSConfig{
					ServiceEnable: true,
					CustomZones: []*mgmtProto.CustomZone{
						{
							Domain: "netbird.cloud.",
							Records: []*mgmtProto.SimpleRecord{
								{
									Name:  "peer-a.netbird.cloud.",
									Type:  1,
									Class: nbdns.DefaultClass,
									TTL:   300,
									RData: "100.64.0.1",
								},
							},
						},
						{
							Domain: "0.66.100.in-addr.arpa.",
						},
					},
					NameServerGroups: []*mgmtProto.NameServerGroup{
						{
							Primary: true,
							NameServers: []*mgmtProto.NameServer{
								{
									IP:     "8.8.8.8",
									NSType: 1,
									Port:   53,
								},
							},
						},
					},
				},
			},
			expectedZonesLen: 1,
			expectedZones: []nbdns.CustomZone{
				{
					Domain: "netbird.cloud.",
					Records: []nbdns.SimpleRecord{
						{
							Name:  "peer-a.netbird.cloud.",
							Type:  1,
							Class: nbdns.DefaultClass,
							TTL:   300,
							RData: "100.64.0.1",
						},
					},
				},
				{
					Domain: "0.66.100.in-addr.arpa.",
				},
			},
			expectedNSGroupsLen: 1,
			expectedNSGroups: []*nbdns.NameServerGroup{
				{
					Primary: true,
					NameServers: []nbdns.NameServer{
						{
							IP:     netip.MustParseAddr("8.8.8.8"),
							NSType: 1,
							Port:   53,
						},
					},
				},
			},
			expectedSerial: 1,
		},
		{
			name: "Empty DNS Config Should Be OK",
			networkMap: &mgmtProto.NetworkMap{
				Serial:             1,
				PeerConfig:         nil,
				RemotePeersIsEmpty: false,
				Routes:             nil,
				DNSConfig:          nil,
			},
			expectedZonesLen:    0,
			expectedZones:       []nbdns.CustomZone{},
			expectedNSGroupsLen: 0,
			expectedNSGroups:    []*nbdns.NameServerGroup{},
			expectedSerial:      1,
		},
		{
			name:     "Error Shouldn't Break Engine",
			inputErr: fmt.Errorf("mocking error"),
			networkMap: &mgmtProto.NetworkMap{
				Serial:             1,
				PeerConfig:         nil,
				RemotePeersIsEmpty: false,
				Routes:             nil,
			},
			expectedZonesLen:    0,
			expectedZones:       []nbdns.CustomZone{},
			expectedNSGroupsLen: 0,
			expectedNSGroups:    []*nbdns.NameServerGroup{},
			expectedSerial:      1,
		},
	}

	for n, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// test setup
			key, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				t.Fatal(err)
				return
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			wgIfaceName := fmt.Sprintf("utun%d", 104+n)
			wgAddr := fmt.Sprintf("100.66.%d.1/24", n)

			relayMgr := relayClient.NewManager(ctx, nil, key.PublicKey().String(), iface.DefaultMTU)
			engine := NewEngine(ctx, cancel, &signal.MockClient{}, &mgmt.MockClient{}, relayMgr, &EngineConfig{
				WgIfaceName:  wgIfaceName,
				WgAddr:       wgAddr,
				WgPrivateKey: key,
				WgPort:       33100,
				MTU:          iface.DefaultMTU,
			}, MobileDependency{}, peer.NewRecorder("https://mgm"), nil, nil)
			engine.ctx = ctx

			newNet, err := stdnet.NewNet(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			opts := iface.WGIFaceOpts{
				IFaceName:    wgIfaceName,
				Address:      wgAddr,
				WGPort:       33100,
				WGPrivKey:    key.String(),
				MTU:          iface.DefaultMTU,
				TransportNet: newNet,
			}
			engine.wgInterface, err = iface.NewWGIFace(opts)
			assert.NoError(t, err, "shouldn't return error")

			mockRouteManager := &routemanager.MockManager{
				UpdateRoutesFunc: func(updateSerial uint64, serverRoutes map[route.ID]*route.Route, clientRoutes route.HAMap, useNewDNSRoute bool) error {
					return nil
				},
			}

			engine.routeManager = mockRouteManager

			input := struct {
				inputSerial   uint64
				inputNSGroups []*nbdns.NameServerGroup
				inputZones    []nbdns.CustomZone
			}{}

			mockDNSServer := &dns.MockServer{
				UpdateDNSServerFunc: func(serial uint64, update nbdns.Config) error {
					input.inputSerial = serial
					input.inputZones = update.CustomZones
					input.inputNSGroups = update.NameServerGroups
					return testCase.inputErr
				},
			}

			engine.dnsServer = mockDNSServer
			engine.connMgr = NewConnMgr(engine.config, engine.statusRecorder, engine.peerStore, engine.wgInterface)
			engine.connMgr.Start(ctx)

			defer func() {
				exitErr := engine.Stop()
				if exitErr != nil {
					return
				}
			}()

			err = engine.updateNetworkMap(testCase.networkMap)
			assert.NoError(t, err, "shouldn't return error")
			assert.Equal(t, testCase.expectedSerial, input.inputSerial, "serial should match")
			assert.Len(t, input.inputNSGroups, testCase.expectedZonesLen, "zones len should match")
			assert.Equal(t, testCase.expectedZones, input.inputZones, "custom zones should match")
			assert.Len(t, input.inputNSGroups, testCase.expectedNSGroupsLen, "ns groups len should match")
			assert.Equal(t, testCase.expectedNSGroups, input.inputNSGroups, "ns groups should match")
		})
	}
}

func TestEngine_MultiplePeers(t *testing.T) {
	// log.SetLevel(log.DebugLevel)

	ctx, cancel := context.WithCancel(CtxInitState(context.Background()))
	defer cancel()

	sigServer, signalAddr, err := startSignal(t)
	if err != nil {
		t.Fatal(err)
		return
	}
	defer sigServer.Stop()
	mgmtServer, mgmtAddr, err := startManagement(t, t.TempDir(), "../testdata/store.sql")
	if err != nil {
		t.Fatal(err)
		return
	}
	defer mgmtServer.GracefulStop()

	setupKey := "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"

	mu := sync.Mutex{}
	engines := []*Engine{}
	numPeers := 10
	wg := sync.WaitGroup{}
	wg.Add(numPeers)
	// create and start peers
	for i := 0; i < numPeers; i++ {
		j := i
		go func() {
			engine, err := createEngine(ctx, cancel, setupKey, j, mgmtAddr, signalAddr)
			if err != nil {
				wg.Done()
				t.Errorf("unable to create the engine for peer %d with error %v", j, err)
				return
			}
			engine.dnsServer = &dns.MockServer{}
			mu.Lock()
			defer mu.Unlock()
			guid := fmt.Sprintf("{%s}", uuid.New().String())
			device.CustomWindowsGUIDString = strings.ToLower(guid)
			err = engine.Start(nil, nil)
			if err != nil {
				t.Errorf("unable to start engine for peer %d with error %v", j, err)
				wg.Done()
				return
			}
			engines = append(engines, engine)
			wg.Done()
		}()
	}

	// wait until all have been created and started
	wg.Wait()
	if len(engines) != numPeers {
		t.Fatal("not all peers was started")
	}
	// check whether all the peer have expected peers connected

	expectedConnected := numPeers * (numPeers - 1)

	// adjust according to timeouts
	timeout := 50 * time.Second
	timeoutChan := time.After(timeout)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
loop:
	for {
		select {
		case <-timeoutChan:
			t.Fatalf("waiting for expected connections timeout after %s", timeout.String())
			break loop
		case <-ticker.C:
			totalConnected := 0
			for _, engine := range engines {
				totalConnected += getConnectedPeers(engine)
			}
			if totalConnected == expectedConnected {
				log.Infof("total connected=%d", totalConnected)
				break loop
			}
			log.Infof("total connected=%d", totalConnected)
		}
	}
	// cleanup test
	for n, peerEngine := range engines {
		t.Logf("stopping peer with interface %s from multipeer test, loopIndex %d", peerEngine.wgInterface.Name(), n)
		errStop := peerEngine.mgmClient.Close()
		if errStop != nil {
			log.Infoln("got error trying to close management clients from engine: ", errStop)
		}
		errStop = peerEngine.Stop()
		if errStop != nil {
			log.Infoln("got error trying to close testing peers engine: ", errStop)
		}
	}
}

func Test_ParseNATExternalIPMappings(t *testing.T) {
	ifaceList, err := net.Interfaces()
	if err != nil {
		t.Fatalf("could get the interface list, got error: %s", err)
	}

	var testingIP string
	var testingInterface string

	for _, iface := range ifaceList {
		addrList, err := iface.Addrs()
		if err != nil {
			t.Fatalf("could get the addr list, got error: %s", err)
		}
		for _, addr := range addrList {
			prefix := netip.MustParsePrefix(addr.String())
			if prefix.Addr().Is4() && !prefix.Addr().IsLoopback() {
				testingIP = prefix.Addr().String()
				testingInterface = iface.Name
			}
		}
	}

	testCases := []struct {
		name                    string
		inputMapList            []string
		inputBlacklistInterface []string
		expectedOutput          []string
	}{
		{
			name:                    "Parse Valid List Should Be OK",
			inputBlacklistInterface: profilemanager.DefaultInterfaceBlacklist,
			inputMapList:            []string{"1.1.1.1", "8.8.8.8/" + testingInterface},
			expectedOutput:          []string{"1.1.1.1", "8.8.8.8/" + testingIP},
		},
		{
			name:                    "Only Interface name Should Return Nil",
			inputBlacklistInterface: profilemanager.DefaultInterfaceBlacklist,
			inputMapList:            []string{testingInterface},
			expectedOutput:          nil,
		},
		{
			name:                    "Invalid IP Return Nil",
			inputBlacklistInterface: profilemanager.DefaultInterfaceBlacklist,
			inputMapList:            []string{"1.1.1.1000"},
			expectedOutput:          nil,
		},
		{
			name:                    "Invalid Mapping Element Should return Nil",
			inputBlacklistInterface: profilemanager.DefaultInterfaceBlacklist,
			inputMapList:            []string{"1.1.1.1/10.10.10.1/eth0"},
			expectedOutput:          nil,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			engine := &Engine{
				config: &EngineConfig{
					IFaceBlackList: testCase.inputBlacklistInterface,
					NATExternalIPs: testCase.inputMapList,
					MTU:            iface.DefaultMTU,
				},
			}
			parsedList := engine.parseNATExternalIPMappings()
			require.ElementsMatchf(t, testCase.expectedOutput, parsedList, "elements of parsed list should match expected list")
		})
	}
}

func Test_CheckFilesEqual(t *testing.T) {
	testCases := []struct {
		name         string
		inputChecks1 []*mgmtProto.Checks
		inputChecks2 []*mgmtProto.Checks
		expectedBool bool
	}{
		{
			name: "Equal Files In Equal Order Should Return True",
			inputChecks1: []*mgmtProto.Checks{
				{
					Files: []string{
						"testfile1",
						"testfile2",
					},
				},
			},
			inputChecks2: []*mgmtProto.Checks{
				{
					Files: []string{
						"testfile1",
						"testfile2",
					},
				},
			},
			expectedBool: true,
		},
		{
			name: "Equal Files In Reverse Order Should Return True",
			inputChecks1: []*mgmtProto.Checks{
				{
					Files: []string{
						"testfile1",
						"testfile2",
					},
				},
			},
			inputChecks2: []*mgmtProto.Checks{
				{
					Files: []string{
						"testfile2",
						"testfile1",
					},
				},
			},
			expectedBool: true,
		},
		{
			name: "Unequal Files Should Return False",
			inputChecks1: []*mgmtProto.Checks{
				{
					Files: []string{
						"testfile1",
						"testfile2",
					},
				},
			},
			inputChecks2: []*mgmtProto.Checks{
				{
					Files: []string{
						"testfile1",
						"testfile3",
					},
				},
			},
			expectedBool: false,
		},
		{
			name: "Compared With Empty Should Return False",
			inputChecks1: []*mgmtProto.Checks{
				{
					Files: []string{
						"testfile1",
						"testfile2",
					},
				},
			},
			inputChecks2: []*mgmtProto.Checks{
				{
					Files: []string{},
				},
			},
			expectedBool: false,
		},
		{
			name: "Compared Slices with same files but different order should return true",
			inputChecks1: []*mgmtProto.Checks{
				{
					Files: []string{
						"testfile1",
						"testfile2",
					},
				},
				{
					Files: []string{
						"testfile4",
						"testfile3",
					},
				},
			},
			inputChecks2: []*mgmtProto.Checks{
				{
					Files: []string{
						"testfile3",
						"testfile4",
					},
				},
				{
					Files: []string{
						"testfile2",
						"testfile1",
					},
				},
			},
			expectedBool: true,
		},
		{
			name: "Compared Slices with same files but different order while first is equal should return true",
			inputChecks1: []*mgmtProto.Checks{
				{
					Files: []string{
						"testfile0",
						"testfile1",
					},
				},
				{
					Files: []string{
						"testfile0",
						"testfile2",
					},
				},
				{
					Files: []string{
						"testfile0",
						"testfile3",
					},
				},
			},
			inputChecks2: []*mgmtProto.Checks{
				{
					Files: []string{
						"testfile0",
						"testfile1",
					},
				},
				{
					Files: []string{
						"testfile0",
						"testfile3",
					},
				},
				{
					Files: []string{
						"testfile0",
						"testfile2",
					},
				},
			},
			expectedBool: true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result := isChecksEqual(testCase.inputChecks1, testCase.inputChecks2)
			assert.Equal(t, testCase.expectedBool, result, "result should match expected bool")
		})
	}
}

func TestCompareNetIPLists(t *testing.T) {
	tests := []struct {
		name     string
		list1    []netip.Prefix
		list2    []string
		expected bool
	}{
		{
			name:     "both empty",
			list1:    []netip.Prefix{},
			list2:    []string{},
			expected: true,
		},
		{
			name:     "single match ipv4",
			list1:    []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")},
			list2:    []string{"192.168.0.0/24"},
			expected: true,
		},
		{
			name:     "multiple match ipv4, different order",
			list1:    []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("10.0.0.0/8")},
			list2:    []string{"10.0.0.0/8", "192.168.1.0/24"},
			expected: true,
		},
		{
			name:     "ipv4 mismatch due to extra element in list2",
			list1:    []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			list2:    []string{"192.168.1.0/24", "10.0.0.0/8"},
			expected: false,
		},
		{
			name:     "ipv4 mismatch due to duplicate count",
			list1:    []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("192.168.1.0/24")},
			list2:    []string{"192.168.1.0/24"},
			expected: false,
		},
		{
			name:     "invalid prefix in list2",
			list1:    []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			list2:    []string{"invalid-prefix"},
			expected: false,
		},
		{
			name:     "ipv4 mismatch because different prefixes",
			list1:    []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			list2:    []string{"10.0.0.0/8"},
			expected: false,
		},
		{
			name:     "single match ipv6",
			list1:    []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
			list2:    []string{"2001:db8::/32"},
			expected: true,
		},
		{
			name:     "multiple match ipv6, different order",
			list1:    []netip.Prefix{netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("fe80::/10")},
			list2:    []string{"fe80::/10", "2001:db8::/32"},
			expected: true,
		},
		{
			name:     "mixed ipv4 and ipv6 match",
			list1:    []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("2001:db8::/32")},
			list2:    []string{"2001:db8::/32", "192.168.1.0/24"},
			expected: true,
		},
		{
			name:     "ipv6 mismatch with invalid prefix",
			list1:    []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
			list2:    []string{"invalid-ipv6"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareNetIPLists(tt.list1, tt.list2)
			if result != tt.expected {
				t.Errorf("compareNetIPLists(%v, %v) = %v; want %v", tt.list1, tt.list2, result, tt.expected)
			}
		})
	}
}

func createEngine(ctx context.Context, cancel context.CancelFunc, setupKey string, i int, mgmtAddr string, signalAddr string) (*Engine, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	mgmtClient, err := mgmt.NewClient(ctx, mgmtAddr, key, false)
	if err != nil {
		return nil, err
	}
	signalClient, err := signal.NewClient(ctx, signalAddr, key, false)
	if err != nil {
		return nil, err
	}

	publicKey, err := mgmtClient.GetServerPublicKey()
	if err != nil {
		return nil, err
	}

	info := system.GetInfo(ctx)
	resp, err := mgmtClient.Register(*publicKey, setupKey, "", info, nil, nil)
	if err != nil {
		return nil, err
	}

	var ifaceName string
	if runtime.GOOS == "darwin" {
		ifaceName = fmt.Sprintf("utun1%d", i)
	} else {
		ifaceName = fmt.Sprintf("wt%d", i)
	}

	wgPort := 33100 + i
	conf := &EngineConfig{
		WgIfaceName:  ifaceName,
		WgAddr:       resp.PeerConfig.Address,
		WgPrivateKey: key,
		WgPort:       wgPort,
		MTU:          iface.DefaultMTU,
	}

	relayMgr := relayClient.NewManager(ctx, nil, key.PublicKey().String(), iface.DefaultMTU)
	e, err := NewEngine(ctx, cancel, signalClient, mgmtClient, relayMgr, conf, MobileDependency{}, peer.NewRecorder("https://mgm"), nil, nil), nil
	e.ctx = ctx
	return e, err
}

func startSignal(t *testing.T) (*grpc.Server, string, error) {
	t.Helper()

	s := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))

	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	srv, err := signalServer.NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	proto.RegisterSignalExchangeServer(s, srv)

	go func() {
		if err = s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	return s, lis.Addr().String(), nil
}

func startManagement(t *testing.T, dataDir, testFile string) (*grpc.Server, string, error) {
	t.Helper()

	config := &config.Config{
		Stuns:      []*config.Host{},
		TURNConfig: &config.TURNConfig{},
		Relay: &config.Relay{
			Addresses:      []string{"127.0.0.1:1234"},
			CredentialsTTL: util.Duration{Duration: time.Hour},
			Secret:         "222222222222222222",
		},
		Signal: &config.Host{
			Proto: "http",
			URI:   "localhost:10000",
		},
		Datadir:    dataDir,
		HttpConfig: nil,
	}

	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, "", err
	}
	s := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))

	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), testFile, config.Datadir)
	if err != nil {
		return nil, "", err
	}
	t.Cleanup(cleanUp)

	eventStore := &activity.InMemoryEventStore{}
	if err != nil {
		return nil, "", err
	}

	permissionsManager := permissions.NewManager(store)
	peersManager := peers.NewManager(store, permissionsManager)
	jobManager := job.NewJobManager(nil, store, peersManager)

	ia, _ := integrations.NewIntegratedValidator(context.Background(), peersManager, nil, eventStore)

	metrics, err := telemetry.NewDefaultAppMetrics(context.Background())
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	settingsMockManager := settings.NewMockManager(ctrl)
	settingsMockManager.EXPECT().
		GetSettings(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&types.Settings{}, nil).
		AnyTimes()
	settingsMockManager.EXPECT().
		GetExtraSettings(gomock.Any(), gomock.Any()).
		Return(&types.ExtraSettings{}, nil).
		AnyTimes()

	groupsManager := groups.NewManagerMock()

	updateManager := update_channel.NewPeersUpdateManager(metrics)
	requestBuffer := server.NewAccountRequestBuffer(context.Background(), store)
	networkMapController := controller.NewController(context.Background(), store, metrics, updateManager, requestBuffer, server.MockIntegratedValidator{}, settingsMockManager, "netbird.selfhosted", port_forwarding.NewControllerMock(), manager.NewEphemeralManager(store, peersManager), config)
	accountManager, err := server.BuildManager(context.Background(), config, store, networkMapController, jobManager, nil, "", eventStore, nil, false, ia, metrics, port_forwarding.NewControllerMock(), settingsMockManager, permissionsManager, false)
	if err != nil {
		return nil, "", err
	}

	secretsManager, err := nbgrpc.NewTimeBasedAuthSecretsManager(updateManager, config.TURNConfig, config.Relay, settingsMockManager, groupsManager)
	if err != nil {
		return nil, "", err
	}
	mgmtServer, err := nbgrpc.NewServer(config, accountManager, settingsMockManager, jobManager, secretsManager, nil, nil, &server.MockIntegratedValidator{}, networkMapController, nil)
	if err != nil {
		return nil, "", err
	}
	mgmtProto.RegisterManagementServiceServer(s, mgmtServer)
	go func() {
		if err = s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	return s, lis.Addr().String(), nil
}

// getConnectedPeers returns a connection Status or nil if peer connection wasn't found
func getConnectedPeers(e *Engine) int {
	e.syncMsgMux.Lock()
	defer e.syncMsgMux.Unlock()
	i := 0
	for _, id := range e.peerStore.PeersPubKey() {
		conn, _ := e.peerStore.PeerConn(id)
		if conn.IsConnected() {
			i++
		}
	}
	return i
}

func getPeers(e *Engine) int {
	e.syncMsgMux.Lock()
	defer e.syncMsgMux.Unlock()

	return len(e.peerStore.PeersPubKey())
}
