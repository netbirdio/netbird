package rosenpass

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"sync"

	rp "cunicu.li/go-rosenpass"
	"cunicu.li/go-rosenpass/config"
)

type rpConn struct {
	key     []byte
	wgIP    string
	peerKey string
}

type Manager struct {
	spk           []byte
	ssk           []byte
	rpConnections map[string]*rpConn
	server        *rp.Server
	lock          sync.Mutex
}

func NewManager() (*Manager, error) {
	public, secret, err := rp.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return &Manager{spk: public, ssk: secret, rpConnections: make(map[string]*rpConn), lock: sync.Mutex{}}, nil
}

func (m *Manager) GetPubKey() []byte {
	return m.spk
}

func (m *Manager) GenerateKeyPair() error {
	spk, ssk, err := rp.GenerateKeyPair()
	if err != nil {
		return err
	}

	m.spk = spk
	m.ssk = ssk

	return nil
}

func (m *Manager) generateConfig() (*rp.Config, error) {

	cfg := config.File{}
	cfg.SecretKey = string(m.ssk)
	cfg.PublicKey = string(m.spk)

	// own local host and port to listen for handshake
	cfg.ListenAddrs = []string{"0.0.0.0:9999"}

	// Checks
	if cfg.PublicKey == "" {
		return nil, errors.New("missing public key for rosenpass")
	} else if cfg.SecretKey == "" {
		return nil, errors.New("missing secret key for rosenpass")
	}

	for _, peer := range m.rpConnections {
		var pc config.PeerSection
		pc.PublicKey = "peer.key"
		endpoint := fmt.Sprintf("%s:%d", peer.wgIP, 9999)
		pc.Endpoint = &endpoint
		outFile := fmt.Sprintf("/tmp/%s", peer.wgIP)
		pc.KeyOut = &outFile
	}

	toConfig, err := cfg.ToConfig()
	if err != nil {
		return nil, err
	}
	return &toConfig, nil
}

func (m *Manager) OnConnected(peerKey string, rpPubKey []byte, wgIP string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	// lookup rp PubKey
	// lookup rp Endpoint (== wireguard endpoint)
	// pass file or channel for pre shared key to update p2p wireguard connection
	// generate new RP config
	// update rosenpass server with new config (or restart)
	m.rpConnections[peerKey] = &rpConn{
		key:     rpPubKey,
		wgIP:    wgIP,
		peerKey: peerKey,
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

	m.server, err = rp.NewUDPServer(*conf)
	if err != nil {
		log.Errorf("failed starting rosenpass sever")
	}

	return
}
