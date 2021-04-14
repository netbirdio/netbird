package wiretrustee

import "golang.zx2c4.com/wireguard/wgctrl/wgtypes"

type Config struct {
	// Wireguard private key of local peer
	PrivateKey wgtypes.Key
	// configured remote peers (Wireguard public keys)
	Peers string
	// host:port of the signal server
	SignalAddr string
}
