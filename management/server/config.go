package server

type ConfigProto int

const (
	UDP ConfigProto = iota + 1
	TCP
	TCP_WITH_TLS
	UDP_WITH_TLS
)

type Config struct {
	Stuns   []*Host
	Turns   []*Host
	Signal  *Host
	DataDir string
}

type Host struct {
	Proto    ConfigProto
	Host     string
	Port     int32
	Username string
	Password []byte
}
