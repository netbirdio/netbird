//go:build js

package internal

import (
	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
)

// createICEConfig creates ICE configuration for WASM environment.
func (e *Engine) createICEConfig() icemaker.Config {
	cfg := icemaker.Config{
		StunTurn:             &e.stunTurn,
		InterfaceBlackList:   e.config.IFaceBlackList,
		DisableIPv6Discovery: e.config.DisableIPv6Discovery,
		NATExternalIPs:       e.parseNATExternalIPMappings(),
	}

	if e.udpMux != nil {
		cfg.UDPMux = e.udpMux.UDPMuxDefault
		cfg.UDPMuxSrflx = e.udpMux
	}

	return cfg
}
