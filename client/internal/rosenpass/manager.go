package rosenpass

import (
	"crypto/sha256"
	"cunicu.li/go-rosenpass/handlers"
	"encoding/hex"
	"fmt"
	log "github.com/sirupsen/logrus"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"

	rp "cunicu.li/go-rosenpass"
)

func HashRosenpassKey(key []byte) string {
	hasher := sha256.New()
	hasher.Write(key)
	return hex.EncodeToString(hasher.Sum(nil))
}

// remotePeer is a representation of a remote Rosenpass peer
type remotePeer struct {
	wireGuardPubKey  string
	wireGuardIP      string
	rosenpassPubKey  []byte
	rosenpassKeyHash string
	rosenpassAddr    string
}

type Manager struct {
	spk           []byte
	ssk           []byte
	rpKeyHash     string
	rpConnections map[string]*remotePeer
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
	return &net.UDPAddr{IP: []byte{0, 0, 0, 0}, Port: 9999}
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
	handler := handlers.NewkeyoutHandler()
	cfg.Handlers = []rp.Handler{handler}
	var err error
	for _, peer := range m.rpConnections {
		pcfg := rp.PeerConfig{PublicKey: peer.rosenpassPubKey}
		strPort := strings.Split(peer.rosenpassAddr, ":")[1]
		peerAddr := fmt.Sprintf("%s:%s", peer.wireGuardIP, strPort)
		if pcfg.Endpoint, err = net.ResolveUDPAddr("udp", peerAddr); err != nil {
			return cfg, fmt.Errorf("failed to resolve peer endpoint address: %w", err)
		}
		cfg.Peers = append(cfg.Peers, pcfg)
		_ = handler.AddPeerKeyoutFile(pcfg.PID(), fmt.Sprintf("/tmp/rosenpass/%s", peerAddr))
	}
	return cfg, nil
}

func (m *Manager) OnDisconnected(peerKey string, wgIP string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if _, ok := m.rpConnections[peerKey]; !ok {
		// if we didn't have this peer yet, just skip
		return
	}

	delete(m.rpConnections, peerKey)

	if len(m.rpConnections) == 0 {
		if m.server != nil {
			err := m.server.Close()
			if err != nil {
				log.Errorf("failed closing local rosenpass server")
			}
			m.server = nil
		}
		return
	}

	err := m.restartServer()
	if err != nil {
		log.Error("failed restarting rosenpass server", err)
	}
}

func (m *Manager) restartServer() error {
	conf, err := m.generateConfig()
	if err != nil {
		return err
	}

	if m.server != nil {
		err = m.server.Close()
		if err != nil {
			return err
		}
	}

	m.server, err = rp.NewUDPServer(conf)
	if err != nil {
		return err
	}

	return m.server.Run()
}

// OnConnected is a handler function that is triggered when a connection to a remote peer establishes
func (m *Manager) OnConnected(remoteWireGuardKey string, remoteRosenpassPubKey []byte, wireGuardIP string, remoteRosenpassAddr string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	rpKeyHash := HashRosenpassKey(remoteRosenpassPubKey)
	log.Debugf("received remote rosenpass key %s, my key %s", rpKeyHash, m.rpKeyHash)
	m.rpConnections[remoteWireGuardKey] = &remotePeer{
		wireGuardPubKey:  remoteWireGuardKey,
		wireGuardIP:      wireGuardIP,
		rosenpassPubKey:  remoteRosenpassPubKey,
		rosenpassKeyHash: rpKeyHash,
		rosenpassAddr:    remoteRosenpassAddr,
	}

	err := m.restartServer()
	if err != nil {
		log.Error("failed restarting rosenpass server", err)
		return
	}

	return
}
