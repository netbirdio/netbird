//go:build privileged

package internal

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/peer"
	nbssh "github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/client/system"
	nbdns "github.com/netbirdio/netbird/dns"
	mgmt "github.com/netbirdio/netbird/shared/management/client"
	mgmtProto "github.com/netbirdio/netbird/shared/management/proto"
	relayClient "github.com/netbirdio/netbird/shared/relay/client"
	signal "github.com/netbirdio/netbird/shared/signal/client"
)

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
		&EngineConfig{
			WgIfaceName:      "utun101",
			WgAddr:           wgaddr.MustParseWGAddress("100.64.0.1/24"),
			WgPrivateKey:     key,
			WgPort:           33100,
			ServerSSHAllowed: true,
			MTU:              iface.DefaultMTU,
			SSHKey:           sshKey,
		},
		EngineServices{
			SignalClient:   &signal.MockClient{},
			MgmClient:      &mgmt.MockClient{},
			RelayManager:   relayMgr,
			StatusRecorder: peer.NewRecorder("https://mgm"),
		},
		MobileDependency{},
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
	engine := NewEngine(ctx, cancel, &EngineConfig{
		WgIfaceName:  "utun103",
		WgAddr:       wgaddr.MustParseWGAddress("100.64.0.1/24"),
		WgPrivateKey: key,
		WgPort:       33100,
		MTU:          iface.DefaultMTU,
	}, EngineServices{
		SignalClient:   &signal.MockClient{},
		MgmClient:      &mgmt.MockClient{SyncFunc: syncFunc},
		RelayManager:   relayMgr,
		StatusRecorder: peer.NewRecorder("https://mgm"),
	}, MobileDependency{})
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
