package peer

import (
	log "github.com/sirupsen/logrus"
	"net"
)

type Proxy struct {
	conn   net.Conn
	remote string
}

func NewProxy(conn net.Conn, remote string) *Proxy {
	return &Proxy{conn: conn, remote: remote}
}

func (p *Proxy) Stop() {

}

func (p *Proxy) Start() {

	go func() {
		buf := make([]byte, 1500)
		for {
			_, err := p.conn.Read(buf)
			log.Infof("sent ping")
			if err != nil {
				log.Errorf("error while reading remote %s proxy %v", p.remote, err)
				return
			}
			log.Infof("received %s from %s", string(buf), p.remote)
		}
	}()

	go func() {
		for {
			_, err := p.conn.Write([]byte("hello"))
			log.Infof("sent ping")
			if err != nil {
				log.Errorf("error while writing to remote %s proxy %v", p.remote, err)
				return
			}
		}

	}()

}
