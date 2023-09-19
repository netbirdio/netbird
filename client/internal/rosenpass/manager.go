package rosenpass

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"sync"

	rp "cunicu.li/go-rosenpass"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func HashRosenpassKey(key []byte) string {
	hasher := sha256.New()
	hasher.Write(key)
	return hex.EncodeToString(hasher.Sum(nil))
}

type Manager struct {
	spk          []byte
	ssk          []byte
	rpKeyHash    string
	preSharedKey *[32]byte
	rpPeerIDs    map[string]*rp.PeerID
	rpWgHandler  *NetbirdHandler
	server       *rp.Server
	lock         sync.Mutex
}

// NewManager creates a new Rosenpass manager
func NewManager(preSharedKey *wgtypes.Key) (*Manager, error) {
	public, secret, err := rp.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	rpKeyHash := HashRosenpassKey(public)
	log.Infof("generated new rosenpass key pair with public key %s", rpKeyHash)
	return &Manager{rpKeyHash: rpKeyHash, spk: public, ssk: secret, preSharedKey: (*[32]byte)(preSharedKey), rpPeerIDs: make(map[string]*rp.PeerID), lock: sync.Mutex{}}, nil
}

func (m *Manager) GetPubKey() []byte {
	return m.spk
}

// GetAddress returns the address of the Rosenpass server
func (m *Manager) GetAddress() *net.UDPAddr {
	return &net.UDPAddr{Port: 9999}
}

// addPeer adds a new peer to the Rosenpass server
func (m *Manager) addPeer(rosenpassPubKey []byte, rosenpassAddr string, wireGuardIP string, wireGuardPubKey string) error {
	var err error
	pcfg := rp.PeerConfig{PublicKey: rosenpassPubKey}
	if m.preSharedKey != nil {
		pcfg.PresharedKey = *m.preSharedKey
	}
	if bytes.Compare(m.spk, rosenpassPubKey) == 1 {
		_, strPort, err := net.SplitHostPort(rosenpassAddr)
		if err != nil {
			return fmt.Errorf("failed to parse rosenpass address: %w", err)
		}
		peerAddr := fmt.Sprintf("%s:%s", wireGuardIP, strPort)
		if pcfg.Endpoint, err = net.ResolveUDPAddr("udp", peerAddr); err != nil {
			return fmt.Errorf("failed to resolve peer endpoint address: %w", err)
		}
	}
	peerID, err := m.server.AddPeer(pcfg)
	if err != nil {
		return err
	}
	var ifaceName string
	switch runtime.GOOS {
	case "darwin":
		ifaceName = "utun100"
	default:
		ifaceName = "wt0"
	}
	key, err := wgtypes.ParseKey(wireGuardPubKey)
	if err != nil {
		return err
	}
	m.rpWgHandler.AddPeer(peerID, ifaceName, rp.Key(key))
	m.rpPeerIDs[wireGuardPubKey] = &peerID
	return nil
}

// removePeer removes a peer from the Rosenpass server
func (m *Manager) removePeer(wireGuardPubKey string) error {
	err := m.server.RemovePeer(*m.rpPeerIDs[wireGuardPubKey])
	if err != nil {
		return err
	}
	m.rpWgHandler.RemovePeer(*m.rpPeerIDs[wireGuardPubKey])
	return nil
}

func (m *Manager) generateConfig() (rp.Config, error) {
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, opts))
	cfg := rp.Config{Logger: logger}

	cfg.ListenAddrs = []*net.UDPAddr{m.GetAddress()}
	cfg.PublicKey = m.spk
	cfg.SecretKey = m.ssk

	cfg.Peers = []rp.PeerConfig{}
	m.rpWgHandler, _ = NewNetbirdHandler(*m.preSharedKey)

	cfg.Handlers = []rp.Handler{m.rpWgHandler}

	return cfg, nil
}

func (m *Manager) OnDisconnected(peerKey string, wgIP string) {
	if m == nil {
		return
	}
	m.lock.Lock()
	defer m.lock.Unlock()

	if _, ok := m.rpPeerIDs[peerKey]; !ok {
		// if we didn't have this peer yet, just skip
		return
	}

	err := m.removePeer(peerKey)
	if err != nil {
		log.Error("failed to remove rosenpass peer", err)
	}

	delete(m.rpPeerIDs, peerKey)
}

// Run starts the Rosenpass server
func (m *Manager) Run() error {
	conf, err := m.generateConfig()
	if err != nil {
		return err
	}

	m.server, err = rp.NewUDPServer(conf)
	if err != nil {
		return err
	}

	return m.server.Run()
}

// Close closes the Rosenpass server
func (m *Manager) Close() error {
	if m.server != nil {
		err := m.server.Close()
		if err != nil {
			log.Errorf("failed closing local rosenpass server")
		}
		m.server = nil
	}
	return nil
}

// OnConnected is a handler function that is triggered when a connection to a remote peer establishes
func (m *Manager) OnConnected(remoteWireGuardKey string, remoteRosenpassPubKey []byte, wireGuardIP string, remoteRosenpassAddr string) {
	if m == nil {
		return
	}
	m.lock.Lock()
	defer m.lock.Unlock()

	if remoteRosenpassPubKey == nil {
		log.Debugf("remote peer does not support rosenpass")
		return
	}

	rpKeyHash := HashRosenpassKey(remoteRosenpassPubKey)
	log.Debugf("received remote rosenpass key %s, my key %s", rpKeyHash, m.rpKeyHash)

	err := m.addPeer(remoteRosenpassPubKey, remoteRosenpassAddr, wireGuardIP, remoteWireGuardKey)
	if err != nil {
		log.Errorf("failed to add rosenpass peer: %s", err)
		return
	}
}
