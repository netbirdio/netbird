package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"

	"github.com/hashicorp/go-multierror"
	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/relay/protocol"
	relaylistener "github.com/netbirdio/netbird/relay/server/listener"
	nbRelay "github.com/netbirdio/netbird/shared/relay"
)

const (
	Proto protocol.Protocol = "quic"

	envSockets = "NB_RELAY_QUIC_SOCKETS"

	maxSockets = 16
)

type Listener struct {
	// Address is the address to listen on
	Address string
	// TLSConfig is the TLS configuration for the server
	TLSConfig *tls.Config

	sockets []*socket
}

func (l *Listener) Bind() error {
	quicCfg := &quic.Config{
		EnableDatagrams:   true,
		InitialPacketSize: nbRelay.QUICInitialPacketSize,
	}

	count := socketCount()
	sockets := make([]*socket, 0, count)
	ready := false
	defer func() {
		if ready {
			return
		}
		for _, s := range sockets {
			if err := s.Close(); err != nil {
				log.Debugf("failed to close QUIC socket: %v", err)
			}
		}
	}()

	address := l.Address
	for range count {
		s, err := newSocket(address, l.TLSConfig, quicCfg, count > 1)
		if err != nil {
			return err
		}
		sockets = append(sockets, s)
		address = s.LocalAddr.String()
	}

	ready = true
	l.sockets = sockets
	log.Infof("QUIC server listening on address: %s, sockets: %d", l.Address, len(sockets))
	return nil
}

func (l *Listener) Serve(acceptFn func(conn relaylistener.Conn)) error {
	if len(l.sockets) == 0 {
		return errors.New("listener is not bound")
	}

	var wg sync.WaitGroup
	for _, s := range l.sockets {
		wg.Add(1)
		go func(s *socket) {
			defer wg.Done()
			s.Serve(acceptFn)
		}(s)
	}
	wg.Wait()
	return nil
}

func (l *Listener) Protocol() protocol.Protocol {
	return Proto
}

func (l *Listener) Shutdown(ctx context.Context) error {
	if len(l.sockets) == 0 {
		return nil
	}

	log.Infof("stopping QUIC listener")
	var merr *multierror.Error
	for _, s := range l.sockets {
		if err := s.Close(); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("listener shutdown failed: %w", err))
		}
	}
	if err := nberrors.FormatErrorOrNil(merr); err != nil {
		return err
	}
	log.Infof("QUIC listener stopped")
	return nil
}

func socketCount() int {
	if !canShareUDPPort {
		return 1
	}

	count := min(maxSockets, runtime.GOMAXPROCS(0))
	val := os.Getenv(envSockets)
	if val == "" {
		return count
	}
	requested, err := strconv.Atoi(val)
	if err != nil || requested < 1 {
		log.Warnf("failed to parse %s: %q is not a positive number", envSockets, val)
		return count
	}
	return min(maxSockets, requested)
}
