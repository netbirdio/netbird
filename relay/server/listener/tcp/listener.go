package tcp

import (
	"net"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/server/listener"
)

// Listener
// Is it just demo code. It does not work in real life environment because the TCP is a streaming protocol, and
// it does not handle framing.
type Listener struct {
	address string

	onAcceptFn func(conn net.Conn)
	wg         sync.WaitGroup
	quit       chan struct{}
	listener   net.Listener
	lock       sync.Mutex
}

func NewListener(address string) listener.Listener {
	return &Listener{
		address: address,
	}
}

func (l *Listener) Listen(onAcceptFn func(conn net.Conn)) error {
	l.lock.Lock()

	l.onAcceptFn = onAcceptFn
	l.quit = make(chan struct{})

	li, err := net.Listen("tcp", l.address)
	if err != nil {
		log.Errorf("failed to listen on address: %s, %s", l.address, err)
		l.lock.Unlock()
		return err
	}
	log.Debugf("TCP server is listening on address: %s", l.address)
	l.listener = li
	l.wg.Add(1)
	go l.acceptLoop()

	l.lock.Unlock()
	<-l.quit
	return nil
}

// Close todo: prevent multiple call (do not close two times the channel)
func (l *Listener) Close() error {
	l.lock.Lock()
	defer l.lock.Unlock()

	close(l.quit)
	err := l.listener.Close()
	l.wg.Wait()
	return err
}

func (l *Listener) acceptLoop() {
	defer l.wg.Done()

	for {
		conn, err := l.listener.Accept()
		if err != nil {
			select {
			case <-l.quit:
				return
			default:
				log.Errorf("failed to accept connection: %s", err)
				continue
			}
		}
		go l.onAcceptFn(conn)
	}
}
