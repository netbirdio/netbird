package cmd

type Config struct {
	// Wireguard private key of local peer
	PrivateKey string
	// configured remote peers (Wireguard public keys)
	Peers    string
	StunURL  string
	TurnURL  string
	TurnUser string
	TurnPwd  string
	// host:port of the signal server
	SignalAddr string
	WgAddr     string
	WgIface    string
}
