package ebpf

type PeerValue struct {
	DestIP   uint32 // IPv4 address in network byte order
	DestPort uint16 // Port in network byte order
	DstID    uint16 // Destination ID
	DstMAC   [6]byte
	SrcMAC   [6]byte
}
