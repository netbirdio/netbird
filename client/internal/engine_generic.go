//go:build !js

package internal

import (
	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
)

// createICEConfig creates ICE configuration for non-WASM environments
func (e *Engine) createICEConfig() icemaker.Config {
	return icemaker.Config{
		StunTurn:             &e.stunTurn,
		InterfaceBlackList:   e.config.IFaceBlackList,
		DisableIPv6Discovery: e.config.DisableIPv6Discovery,
		UDPMux:               e.udpMux.UDPMuxDefault,
		UDPMuxSrflx:          e.udpMux,
		NATExternalIPs:       e.parseNATExternalIPMappings(),
	}
}
