package dns

import (
	"github.com/miekg/dns"
)

const (
	defaultPort = 53
)

type service interface {
	Listen() error
	Stop()
	RegisterMux(domain string, handler dns.Handler)
	DeregisterMux(key string)
	RuntimePort() int
	RuntimeIP() string
}
