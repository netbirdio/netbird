package proxy

import (
	"context"
	log "github.com/sirupsen/logrus"
	"net"
	"time"
)

// DummyProxy just sends pings to the RemoteKey peer and reads responses
type DummyProxy struct {
	conn   net.Conn
	remote string
	ctx    context.Context
	cancel context.CancelFunc
}

func NewDummyProxy(remote string) *DummyProxy {
	p := &DummyProxy{remote: remote}
	p.ctx, p.cancel = context.WithCancel(context.Background())
	return p
}

func (p *DummyProxy) Close() error {
	p.cancel()
	return nil
}

func (p *DummyProxy) Start(remoteConn net.Conn) error {
	p.conn = remoteConn
	go func() {
		buf := make([]byte, 1500)
		for {
			select {
			case <-p.ctx.Done():
				return
			default:
				n, err := p.conn.Read(buf)
				if err != nil {
					log.Errorf("error while reading RemoteKey %s proxy %v", p.remote, err)
					return
				}
				log.Debugf("received %s from %s", string(buf[:n]), p.remote)
			}

		}
	}()

	go func() {
		for {
			select {
			case <-p.ctx.Done():
				return
			default:
				_, err := p.conn.Write([]byte("hello"))
				log.Debugf("sent ping to %s", p.remote)
				if err != nil {
					log.Errorf("error while writing to RemoteKey %s proxy %v", p.remote, err)
					return
				}
				time.Sleep(5 * time.Second)
			}
		}

	}()

	return nil
}
