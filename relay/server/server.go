package server

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/messages"
	"github.com/netbirdio/netbird/relay/server/listener"
	"github.com/netbirdio/netbird/relay/server/listener/udp"
	ws "github.com/netbirdio/netbird/relay/server/listener/wsnhooyr"
)

type Server struct {
	store   *Store
	storeMu sync.RWMutex

	UDPListener listener.Listener
	WSListener  listener.Listener
}

func NewServer() *Server {
	return &Server{
		store:   NewStore(),
		storeMu: sync.RWMutex{},
	}
}

func (r *Server) Listen(address string) error {
	wg := sync.WaitGroup{}
	wg.Add(2)

	r.WSListener = ws.NewListener(address)
	var wslErr error
	go func() {
		defer wg.Done()
		wslErr = r.WSListener.Listen(r.accept)
		if wslErr != nil {
			log.Errorf("failed to bind ws server: %s", wslErr)
		}
	}()

	r.UDPListener = udp.NewListener(address)
	var udpLErr error
	go func() {
		defer wg.Done()
		udpLErr = r.UDPListener.Listen(r.accept)
		if udpLErr != nil {
			log.Errorf("failed to bind ws server: %s", udpLErr)
		}
	}()

	err := errors.Join(wslErr, udpLErr)
	return err
}

func (r *Server) Close() error {
	var wErr error
	if r.WSListener != nil {
		wErr = r.WSListener.Close()
	}

	var uErr error
	if r.UDPListener != nil {
		uErr = r.UDPListener.Close()
	}

	r.sendCloseMsgs()

	r.WSListener.WaitForExitAcceptedConns()

	err := errors.Join(wErr, uErr)
	return err
}

func (r *Server) accept(conn net.Conn) {
	peer, err := handShake(conn)
	if err != nil {
		log.Errorf("failed to handshake wiht %s: %s", conn.RemoteAddr(), err)
		cErr := conn.Close()
		if cErr != nil {
			log.Errorf("failed to close connection, %s: %s", conn.RemoteAddr(), cErr)
		}
		return
	}
	peer.Log.Infof("peer connected from: %s", conn.RemoteAddr())

	r.store.AddPeer(peer)
	defer func() {
		r.store.DeletePeer(peer)
		peer.Log.Infof("relay connection closed")
	}()

	for {
		buf := make([]byte, 1500) // todo: optimize buffer size
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				peer.Log.Errorf("failed to read message: %s", err)
			}
			return
		}

		msgType, err := messages.DetermineClientMsgType(buf[:n])
		if err != nil {
			peer.Log.Errorf("failed to determine message type: %s", err)
			return
		}
		switch msgType {
		case messages.MsgTypeTransport:
			msg := buf[:n]
			peerID, err := messages.UnmarshalTransportID(msg)
			if err != nil {
				peer.Log.Errorf("failed to unmarshal transport message: %s", err)
				continue
			}
			go func() {
				stringPeerID := messages.HashIDToString(peerID)
				dp, ok := r.store.Peer(stringPeerID)
				if !ok {
					peer.Log.Errorf("peer not found: %s", stringPeerID)
					return
				}
				err := messages.UpdateTransportMsg(msg, peer.ID())
				if err != nil {
					peer.Log.Errorf("failed to update transport message: %s", err)
					return
				}
				_, err = dp.conn.Write(msg)
				if err != nil {
					peer.Log.Errorf("failed to write transport message to: %s", dp.String())
				}
				return
			}()
		case messages.MsgClose:
			peer.Log.Infof("peer disconnected gracefully")
			_ = conn.Close()
			return
		}
	}
}

func (r *Server) sendCloseMsgs() {
	msg := messages.MarshalCloseMsg()

	r.storeMu.Lock()
	log.Debugf("sending close messages to %d peers", len(r.store.peers))
	for _, p := range r.store.peers {
		_, err := p.conn.Write(msg)
		if err != nil {
			log.Errorf("failed to send close message to peer: %s", p.String())
		}

		err = p.conn.Close()
		if err != nil {
			log.Errorf("failed to close connection to peer: %s", err)
		}
	}
	r.storeMu.Unlock()
}

func handShake(conn net.Conn) (*Peer, error) {
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		log.Errorf("failed to read message: %s", err)
		return nil, err
	}
	msgType, err := messages.DetermineClientMsgType(buf[:n])
	if err != nil {
		return nil, err
	}
	if msgType != messages.MsgTypeHello {
		tErr := fmt.Errorf("invalid message type")
		log.Errorf("failed to handshake: %s", tErr)
		return nil, tErr
	}
	peerId, err := messages.UnmarshalHelloMsg(buf[:n])
	if err != nil {
		log.Errorf("failed to handshake: %s", err)
		return nil, err
	}
	p := NewPeer(peerId, conn)

	msg := messages.MarshalHelloResponse()
	_, err = conn.Write(msg)
	return p, err
}
