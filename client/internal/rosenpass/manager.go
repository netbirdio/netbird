package rosenpass

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	log "github.com/sirupsen/logrus"
	"log/slog"
	"net"
	"os"
	"sync"

	rp "cunicu.li/go-rosenpass"
)

type rpConn struct {
	key       []byte
	wgIP      string
	peerKey   string
	rpKeyHash string
}

type Manager struct {
	spk           []byte
	ssk           []byte
	rpKeyHash     string
	rpConnections map[string]*rpConn
	server        *rp.Server
	lock          sync.Mutex
}

func NewManager() (*Manager, error) {
	public, secret, err := rp.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	hasher := sha256.New()
	hasher.Write(public)
	rpKeyHash := hex.EncodeToString(hasher.Sum(nil))
	log.Infof("generated new rosenpass key pair with public key %s", rpKeyHash)
	return &Manager{rpKeyHash: rpKeyHash, spk: public, ssk: secret, rpConnections: make(map[string]*rpConn), lock: sync.Mutex{}}, nil
}

func (m *Manager) GetPubKey() []byte {
	hasher := sha256.New()
	hasher.Write(m.spk)
	rpKeyHash := hex.EncodeToString(hasher.Sum(nil))
	log.Infof("getting my rosenpass key %s", rpKeyHash)
	return m.spk
}

func (m *Manager) generateConfig() (rp.Config, error) {
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, opts))
	cfg := rp.Config{Logger: logger}
	udpAddr := &net.UDPAddr{}
	var err error
	if udpAddr, err = net.ResolveUDPAddr("udp", "0.0.0.0:9999"); err != nil {
		return cfg, fmt.Errorf("failed to resolve listen address: %w", err)
	}

	cfg.ListenAddrs = []*net.UDPAddr{udpAddr}
	cfg.PublicKey = m.spk
	cfg.SecretKey = m.ssk

	cfg.Peers = []rp.PeerConfig{}

	for _, peer := range m.rpConnections {
		pcfg := rp.PeerConfig{PublicKey: peer.key}
		peerAddr := fmt.Sprintf("%s:%d", peer.wgIP, 9999)
		if pcfg.Endpoint, err = net.ResolveUDPAddr("udp", peerAddr); err != nil {
			return cfg, fmt.Errorf("failed to resolve peer endpoint address: %w", err)
		}
		cfg.Peers = append(cfg.Peers, pcfg)
	}
	return cfg, nil
}

func (m *Manager) OnConnected(peerKey string, rpPubKey []byte, wgIP string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	hasher := sha256.New()
	hasher.Write(rpPubKey)
	rpKeyHash := hex.EncodeToString(hasher.Sum(nil))
	log.Debugf("received remote rosenpass key %s, my key %s", rpKeyHash, m.rpKeyHash)
	m.rpConnections[peerKey] = &rpConn{
		key:       rpPubKey,
		wgIP:      wgIP,
		peerKey:   peerKey,
		rpKeyHash: rpKeyHash,
	}

	conf, err := m.generateConfig()
	if err != nil {
		return
	}

	if m.server != nil {
		err := m.server.Close()
		if err != nil {
			log.Warn("failed rosenpass server")
		}
	}

	m.server, err = rp.NewUDPServer(conf)
	if err != nil {
		log.Errorf("failed starting rosenpass sever")
	}

	err = m.server.Run()
	if err != nil {
		return
	}

	return
}
