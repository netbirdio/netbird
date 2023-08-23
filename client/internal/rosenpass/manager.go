package rosenpass

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"net"
	"sync"

	rp "cunicu.li/go-rosenpass"
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

func (m *Manager) generateConfig() (rp.Config, error) {
	cfg := rp.Config{}
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
