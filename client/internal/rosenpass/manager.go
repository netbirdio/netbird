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
	"strings"
	"sync"

	rp "cunicu.li/go-rosenpass"
	"cunicu.li/go-rosenpass/handlers"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func HashRosenpassKey(key []byte) string {
	hasher := sha256.New()
	hasher.Write(key)
	return hex.EncodeToString(hasher.Sum(nil))
}

// remotePeer is a representation of a remote Rosenpass peer
type remotePeer struct {
	// wireGuardPubKey  string
	// wireGuardIP      string
	// rosenpassPubKey  []byte
	// rosenpassKeyHash string
	// rosenpassAddr    string
	rosenpassPeerID string
}

type Manager struct {
	spk           []byte
	ssk           []byte
	rpKeyHash     string
	rpConnections map[string]*remotePeer
	rpWgHandler   *handlers.WireGuardHandler
	server        *rp.Server
	lock          sync.Mutex
}

func NewManager() (*Manager, error) {
	public, secret, err := rp.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	rpKeyHash := HashRosenpassKey(public)
	log.Infof("generated new rosenpass key pair with public key %s", rpKeyHash)
	return &Manager{rpKeyHash: rpKeyHash, spk: public, ssk: secret, rpConnections: make(map[string]*remotePeer), lock: sync.Mutex{}}, nil
}

func (m *Manager) GetPubKey() []byte {
	return m.spk
}

// GetAddress returns the address of the Rosenpass server
func (m *Manager) GetAddress() *net.UDPAddr {
	return &net.UDPAddr{Port: 9999}
}

// AddPeer adds a new peer to the Rosenpass server
func (m *Manager) AddPeer(rosenpassPubKey []byte, rosenpassAddr string, wireGuardIP string, wireGuardPubKey string) error {
	var err error
	pcfg := rp.PeerConfig{PublicKey: rosenpassPubKey}
	if bytes.Compare(m.spk, rosenpassPubKey) == 1 {
		strPort := strings.Split(rosenpassAddr, ":")[1]
		peerAddr := fmt.Sprintf("%s:%s", wireGuardIP, strPort)
		if pcfg.Endpoint, err = net.ResolveUDPAddr("udp", peerAddr); err != nil {
			return fmt.Errorf("failed to resolve peer endpoint address: %w", err)
		}
	}
	peerID := m.server.AddPeer(pcfg)
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
	m.rpConnections[wireGuardPubKey] = &remotePeer{
		rosenpassPeerID: peerID,
	}
	return nil
}

// RemovePeer removes a peer from the Rosenpass server
func (m *Manager) RemovePeer(wireGuardPubKey string) error {
	m.server.RemovePeer(m.rpConnections[wireGuardPubKey].rosenpassPeerID)
	m.rpWgHandler.RemovePeer(m.rpConnections[wireGuardPubKey].rosenpassPeerID)
	return nil
}

// UpdatePeer updates a peer in the Rosenpass server
func (m *Manager) UpdatePeer() error {
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
	wireGuardHandler, _ := handlers.NewWireGuardHandler()

	cfg.Handlers = []rp.Handler{wireGuardHandler}
	// var err error
	// for _, peer := range m.rpConnections {
	// 	pcfg := rp.PeerConfig{PublicKey: peer.rosenpassPubKey}
	// 	if bytes.Compare(m.spk, peer.rosenpassPubKey) == 1 {
	// 		strPort := strings.Split(peer.rosenpassAddr, ":")[1]
	// 		peerAddr := fmt.Sprintf("%s:%s", peer.wireGuardIP, strPort)
	// 		if pcfg.Endpoint, err = net.ResolveUDPAddr("udp", peerAddr); err != nil {
	// 			return cfg, fmt.Errorf("failed to resolve peer endpoint address: %w", err)
	// 		}
	// 	}
	//
	// 	cfg.Peers = append(cfg.Peers, pcfg)
	// 	key, err := wgtypes.ParseKey(peer.wireGuardPubKey)
	// 	if err != nil {
	// 		continue
	// 	}
	// 	var ifaceName string
	// 	switch runtime.GOOS {
	// 	case "darwin":
	// 		ifaceName = "utun100"
	// 	default:
	// 		ifaceName = "wt0"
	// 	}
	// 	wireGuardHandler.AddPeer(pcfg.PID(), ifaceName, rp.Key(key))
	// }
	return cfg, nil
}

func (m *Manager) OnDisconnected(peerKey string, wgIP string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if _, ok := m.rpConnections[peerKey]; !ok {
		// if we didn't have this peer yet, just skip
		return
	}

	err := m.RemovePeer(peerKey)
	if err != nil {
		log.Error("failed to remove rosenpass peer", err)
	}

	delete(m.rpConnections, peerKey)

	// if len(m.rpConnections) == 0 {
	// 	if m.server != nil {
	// 		err := m.server.Close()
	// 		if err != nil {
	// 			log.Errorf("failed closing local rosenpass server")
	// 		}
	// 		m.server = nil
	// 	}
	// 	return
	// }
}

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

// func (m *Manager) restartServer() error {
// 	conf, err := m.generateConfig()
// 	if err != nil {
// 		return err
// 	}
//
// 	if m.server != nil {
// 		err = m.server.Close()
// 		if err != nil {
// 			return err
// 		}
// 	}
//
// 	m.server, err = rp.NewUDPServer(conf)
// 	if err != nil {
// 		return err
// 	}
//
// 	return m.server.Run()
// }

// OnConnected is a handler function that is triggered when a connection to a remote peer establishes
func (m *Manager) OnConnected(remoteWireGuardKey string, remoteRosenpassPubKey []byte, wireGuardIP string, remoteRosenpassAddr string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	rpKeyHash := HashRosenpassKey(remoteRosenpassPubKey)
	log.Debugf("received remote rosenpass key %s, my key %s", rpKeyHash, m.rpKeyHash)

	peerID := m.addPeer(remoteRosenpassPubKey, remoteRosenpassAddr, wireGuardIP, remoteWireGuardKey)
	m.rpConnections[remoteWireGuardKey] = &remotePeer{
		// wireGuardPubKey:  remoteWireGuardKey,
		// wireGuardIP:      wireGuardIP,
		// rosenpassPubKey:  remoteRosenpassPubKey,
		// rosenpassKeyHash: rpKeyHash,
		// rosenpassAddr:    remoteRosenpassAddr,
		rosenpassPeerID: peerID,
	}

	return
}
