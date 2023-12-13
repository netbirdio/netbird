package uspproxy

import (
	"context"
	"net"

	"github.com/armon/go-socks5"
	log "github.com/sirupsen/logrus"
)

type Dialer interface {
	Dial(ctx context.Context, network, addr string) (net.Conn, error)
}

// Proxy todo close server
type Proxy struct {
	server *socks5.Server
}

func NewSocks5(dialer Dialer) (*Proxy, error) {
	conf := &socks5.Config{
		Dial: dialer.Dial,
	}
	server, err := socks5.New(conf)
	if err != nil {
		log.Debugf("failed to init socks5 proxy: %s", err)
		return nil, err
	}

	return &Proxy{
		server: server,
	}, nil
}

func (s *Proxy) ListenAndServe(addr string) error {
	go func() {
		err := s.server.ListenAndServe("tcp", addr)
		if err != nil {
			log.Debugf("failed to start socks5 proxy: %s", err)
		}
	}()
	return nil
}
