package udp

import (
	"net"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/server/listener"
)

type Listener struct {
	address    string
	conns      map[string]*UDPConn
	onAcceptFn func(conn net.Conn)

	listener *net.UDPConn

	wg   sync.WaitGroup
	quit chan struct{}
	lock sync.Mutex
}

func NewListener(address string) listener.Listener {
	return &Listener{
		address: address,
		conns:   make(map[string]*UDPConn),
	}
}

func (l *Listener) Listen(onAcceptFn func(conn net.Conn)) error {
	l.lock.Lock()

	l.onAcceptFn = onAcceptFn
	l.quit = make(chan struct{})

	addr, err := net.ResolveUDPAddr("udp", l.address)
	if err != nil {
		log.Errorf("invalid listen address '%s': %s", l.address, err)
		l.lock.Unlock()
		return err
	}

	li, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("%s", err)
		l.lock.Unlock()
		return err
	}
	log.Debugf("udp server is listening on address: %s", addr.String())
	l.listener = li
	l.wg.Add(1)
	go l.readLoop()

	l.lock.Unlock()
	<-l.quit
	return nil
}

func (l *Listener) Close() error {
	l.lock.Lock()
	defer l.lock.Unlock()

	log.Infof("closing UDP server")
	if l.listener == nil {
		return nil
	}

	close(l.quit)
	err := l.listener.Close()
	l.wg.Wait()
	l.listener = nil
	return err
}

func (l *Listener) readLoop() {
	defer l.wg.Done()

	for {
		buf := make([]byte, 1500)
		n, addr, err := l.listener.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-l.quit:
				return
			default:
				log.Errorf("failed to accept connection: %s", err)
				continue
			}
		}

		pConn, ok := l.conns[addr.String()]
		if ok {
			pConn.onNewMsg(buf[:n])
			continue
		}

		pConn = NewConn(l.listener, addr)
		log.Infof("new connection from: %s", pConn.RemoteAddr())
		l.conns[addr.String()] = pConn
		go l.onAcceptFn(pConn)
		pConn.onNewMsg(buf[:n])
	}
}
