package netstack

import (
	"net"

	"github.com/things-go/go-socks5"

	log "github.com/sirupsen/logrus"
)

const (
	DefaultSocks5Port = 1080
)

// Proxy todo close server
type Proxy struct {
	server *socks5.Server

	listener net.Listener
	closed   bool
}

func NewSocks5(dialer Dialer) (*Proxy, error) {
	server := socks5.NewServer(
		socks5.WithDial(dialer.Dial),
	)

	return &Proxy{
		server: server,
	}, nil
}

func (s *Proxy) ListenAndServe(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Errorf("failed to create listener for socks5 proxy: %s", err)
		return err
	}
	s.listener = listener

	for {
		conn, err := listener.Accept()
		if err != nil {
			if s.closed {
				return nil
			}
			return err
		}

		go func() {
			if err := s.server.ServeConn(conn); err != nil {
				log.Errorf("failed to serve a connection: %s", err)
			}
		}()
	}
}

func (s *Proxy) Close() error {
	if s.listener == nil {
		return nil
	}

	s.closed = true
	return s.listener.Close()
}
