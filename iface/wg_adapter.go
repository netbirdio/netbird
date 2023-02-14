package iface

type WGAdapter interface {
	ConfigureInterface(address string, privateKey string, port int) error
	UpdateAddr(address string) error
	AddPeer(peerKey, allowedIP, preSharedKey, endPoint string) error
	RemovePeer(peerKey string) error
}
