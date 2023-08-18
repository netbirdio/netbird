package rosenpass

import (
	"errors"
	"fmt"

	rp "cunicu.li/go-rosenpass"
	"cunicu.li/go-rosenpass/config"

	"github.com/netbirdio/netbird/management/proto"
)

type Manager struct {
	spk []byte
	ssk []byte
}

func NewManager() *Manager {
	return &Manager{}
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

func (m *Manager) generateConfig(peers []*proto.RemotePeerConfig) (cfg config.File, err error) {

	cfg := config.File{}
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

	for _, peer := range peers {
		var pc config.PeerSection
		allowedIP := peer.GetAllowedIps()
		pc.PublicKey =
		// pc.PresharedKey =
		pc.Endpoint = &allowedIP[0]
		pc.KeyOut =

		cfg.Peers = append(cfg.Peers, pc)
	}

	return cfg, nil
}

func (m *Manager) onConnected(peerID string) {
	// lookup rp PubKey
	// lookup rp Endpoint (== wireguard endpoint)
	// generate new RP config
	// pass file or channel for pre shared key to update p2p wireguard connection
	// update rosenpass server with new config (or restart)
}
