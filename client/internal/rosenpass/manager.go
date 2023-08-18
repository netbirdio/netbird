package rosenpass

import (
	"errors"
	"fmt"

	rp "cunicu.li/go-rosenpass"
	"cunicu.li/go-rosenpass/config"
)

type rpConn struct {
	key     string
	wgIP    string
	peerKey string
}

type Manager struct {
	spk           []byte
	ssk           []byte
	rpConnections map[string]*rpConn
}

func NewManager() *Manager {
	return &Manager{}
}

func (m *Manager) GetPubKey() string {
	return string(m.spk)
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

func (m *Manager) generateConfig() (cfg config.File, err error) {

	cfg = config.File{}
	cfg.SecretKey = string(m.ssk)
	cfg.PublicKey = string(m.spk)

	// own local host and port to listen for handshake
	cfg.ListenAddrs = []string{"0.0.0.0:9999"}

	// Checks
	if cfg.PublicKey == "" {
		return cfg, errors.New("missing public key for rosenpass")
	} else if cfg.SecretKey == "" {
		return cfg, errors.New("missing secret key for rosenpass")
	}

	for _, peer := range m.rpConnections {
		var pc config.PeerSection
		pc.PublicKey = peer.key
		endpoint := fmt.Sprintf("%s:%d", peer.wgIP, 9999)
		pc.Endpoint = &endpoint
		outFile := fmt.Sprintf("/tmp/%s", peer.wgIP)
		pc.KeyOut = &outFile
	}

	return cfg, nil
}

func (m *Manager) OnConnected(peerKey, rpPubKey, wgIP string) {
	// lookup rp PubKey
	// lookup rp Endpoint (== wireguard endpoint)
	// pass file or channel for pre shared key to update p2p wireguard connection
	// generate new RP config
	// update rosenpass server with new config (or restart)
	m.rpConnections[rpPubKey] = &rpConn{
		key:     rpPubKey,
		wgIP:    wgIP,
		peerKey: peerKey,
	}

	conf, err := m.generateConfig()
	if err != nil {
		return
	}

}
