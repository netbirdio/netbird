package peer

import (
	log "github.com/sirupsen/logrus"
	"net"
	"time"
)

type WireguardProxy struct {
	conn   net.Conn
	remote string
}

func NewWireguardProxy(remote string) *WireguardProxy {
	return &WireguardProxy{remote: remote}
}

func (p *WireguardProxy) Stop() {

}

func (p *WireguardProxy) Start(remoteConn net.Conn) {
	p.conn = remoteConn
	go func() {
		buf := make([]byte, 1500)
		for {
			n, err := p.conn.Read(buf)
			log.Infof("sent ping")
			if err != nil {
				log.Errorf("error while reading remote %s proxy %v", p.remote, err)
				return
			}
			log.Infof("received %s from %s", string(buf[:n]), p.remote)
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
			time.Sleep(5 * time.Second)
		}

	}()

}
