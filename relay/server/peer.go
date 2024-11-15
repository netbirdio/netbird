package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/healthcheck"
	"github.com/netbirdio/netbird/relay/messages"
	"github.com/netbirdio/netbird/relay/metrics"
)

const (
	bufferSize = 8820

	errCloseConn = "failed to close connection to peer: %s"
)

// Peer represents a peer connection
type Peer struct {
	metrics *metrics.Metrics
	log     *log.Entry
	idS     string
	idB     []byte
	conn    net.Conn
	connMu  sync.RWMutex
	store   *Store
}

// NewPeer creates a new Peer instance and prepare custom logging
func NewPeer(metrics *metrics.Metrics, id []byte, conn net.Conn, store *Store) *Peer {
	stringID := messages.HashIDToString(id)
	return &Peer{
		metrics: metrics,
		log:     log.WithField("peer_id", stringID),
		idS:     stringID,
		idB:     id,
		conn:    conn,
		store:   store,
	}
}

// Work reads data from the connection
// It manages the protocol (healthcheck, transport, close). Read the message and determine the message type and handle
// the message accordingly.
func (p *Peer) Work() {
	defer func() {
		if err := p.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			p.log.Errorf(errCloseConn, err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hc := healthcheck.NewSender(p.log)
	go hc.StartHealthCheck(ctx)
	go p.handleHealthcheckEvents(ctx, hc)

	buf := make([]byte, bufferSize)
	for {
		n, err := p.conn.Read(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				p.log.Errorf("failed to read message: %s", err)
			}
			return
		}

		if n == 0 {
			p.log.Errorf("received empty message")
			return
		}

		msg := buf[:n]

		_, err = messages.ValidateVersion(msg)
		if err != nil {
			p.log.Warnf("failed to validate protocol version: %s", err)
			return
		}

		msgType, err := messages.DetermineClientMessageType(msg[messages.SizeOfVersionByte:])
		if err != nil {
			p.log.Errorf("failed to determine message type: %s", err)
			return
		}

		p.handleMsgType(ctx, msgType, hc, n, msg)
	}
}

func (p *Peer) handleMsgType(ctx context.Context, msgType messages.MsgType, hc *healthcheck.Sender, n int, msg []byte) {
	switch msgType {
	case messages.MsgTypeHealthCheck:
		hc.OnHCResponse()
	case messages.MsgTypeTransport:
		p.metrics.TransferBytesRecv.Add(ctx, int64(n))
		p.metrics.PeerActivity(p.String())
		p.handleTransportMsg(msg)
	case messages.MsgTypeClose:
		p.log.Infof("peer exited gracefully")
		if err := p.conn.Close(); err != nil {
			log.Errorf(errCloseConn, err)
		}
	default:
		p.log.Warnf("received unexpected message type: %s", msgType)
	}
}

// Write writes data to the connection
func (p *Peer) Write(b []byte) (int, error) {
	p.connMu.RLock()
	defer p.connMu.RUnlock()
	return p.conn.Write(b)
}

// CloseGracefully closes the connection with the peer gracefully. Send a close message to the client and close the
// connection.
func (p *Peer) CloseGracefully(ctx context.Context) {
	p.connMu.Lock()
	defer p.connMu.Unlock()
	err := p.writeWithTimeout(ctx, messages.MarshalCloseMsg())
	if err != nil {
		p.log.Errorf("failed to send close message to peer: %s", p.String())
	}

	if err := p.conn.Close(); err != nil {
		p.log.Errorf(errCloseConn, err)
	}
}

func (p *Peer) Close() {
	p.connMu.Lock()
	defer p.connMu.Unlock()

	if err := p.conn.Close(); err != nil {
		p.log.Errorf(errCloseConn, err)
	}
}

// String returns the peer ID
func (p *Peer) String() string {
	return p.idS
}

func (p *Peer) writeWithTimeout(ctx context.Context, buf []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	writeDone := make(chan struct{})
	var err error
	go func() {
		_, err = p.conn.Write(buf)
		close(writeDone)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-writeDone:
		return err
	}
}

func (p *Peer) handleHealthcheckEvents(ctx context.Context, hc *healthcheck.Sender) {
	for {
		select {
		case <-hc.HealthCheck:
			_, err := p.Write(messages.MarshalHealthcheck())
			if err != nil {
				p.log.Errorf("failed to send healthcheck message: %s", err)
				return
			}
		case <-hc.Timeout:
			p.log.Errorf("peer healthcheck timeout")
			err := p.conn.Close()
			if err != nil {
				p.log.Errorf("failed to close connection to peer: %s", err)
			}
			p.log.Info("peer connection closed due healthcheck timeout")
			return
		case <-ctx.Done():
			return
		}
	}
}

func (p *Peer) handleTransportMsg(msg []byte) {
	peerID, err := messages.UnmarshalTransportID(msg[messages.SizeOfProtoHeader:])
	if err != nil {
		p.log.Errorf("failed to unmarshal transport message: %s", err)
		return
	}

	stringPeerID := messages.HashIDToString(peerID)
	dp, ok := p.store.Peer(stringPeerID)
	if !ok {
		p.log.Debugf("peer not found: %s", stringPeerID)
		return
	}

	err = messages.UpdateTransportMsg(msg[messages.SizeOfProtoHeader:], p.idB)
	if err != nil {
		p.log.Errorf("failed to update transport message: %s", err)
		return
	}

	n, err := dp.Write(msg)
	if err != nil {
		p.log.Errorf("failed to write transport message to: %s", dp.String())
		return
	}
	p.metrics.TransferBytesSent.Add(context.Background(), int64(n))
}
