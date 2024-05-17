package server

import (
	"fmt"
	"io"
	"net"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/messages"
	"github.com/netbirdio/netbird/relay/server/listener"
	"github.com/netbirdio/netbird/relay/server/listener/ws"
)

// Server
// todo:
// authentication: provide JWT token via RPC call. The MGM server can forward the token to the agents.
// connection timeout handling
// implement HA (High Availability) mode
type Server struct {
	store *Store

	listener listener.Listener
}

func NewServer() *Server {
	return &Server{
		store: NewStore(),
	}
}

func (r *Server) Listen(address string) error {
	r.listener = ws.NewListener(address)
	return r.listener.Listen(r.accept)
}

func (r *Server) Close() error {
	if r.listener == nil {
		return nil
	}
	return r.listener.Close()
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
	peer.Log.Debugf("on new connection: %s", conn.RemoteAddr())

	r.store.AddPeer(peer)
	defer func() {
		peer.Log.Debugf("teardown connection")
		r.store.DeletePeer(peer)
	}()

	buf := make([]byte, 65535) // todo: optimize buffer size
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				peer.Log.Errorf("failed to read message: %s", err)
			}
			return
		}

		msgType, err := messages.DetermineClientMsgType(buf[:n])
		if err != nil {
			log.Errorf("failed to determine message type: %s", err)
			return
		}
		switch msgType {
		case messages.MsgTypeBindNewChannel:
			dstPeerId, err := messages.UnmarshalBindNewChannel(buf[:n])
			if err != nil {
				log.Errorf("failed to unmarshal bind new channel message: %s", err)
				continue
			}

			channelID := r.store.Link(peer, dstPeerId)

			msg := messages.MarshalBindResponseMsg(channelID, dstPeerId)
			_, err = conn.Write(msg)
			if err != nil {
				peer.Log.Errorf("failed to response to bind request: %s", err)
				continue
			}
			peer.Log.Debugf("bind new channel with '%s', channelID: %d", dstPeerId, channelID)
		case messages.MsgTypeTransport:
			msg := buf[:n]
			channelId, err := messages.UnmarshalTransportID(msg)
			if err != nil {
				peer.Log.Errorf("failed to unmarshal transport message: %s", err)
				continue
			}

			foreignChannelID, remoteConn, err := peer.ConnByChannelID(channelId)
			if err != nil {
				peer.Log.Errorf("failed to transport message from peer '%s' to '%d': %s", peer.ID(), channelId, err)
				continue
			}

			err = transportTo(remoteConn, foreignChannelID, msg)
			if err != nil {
				peer.Log.Errorf("failed to transport message from peer '%s' to '%d': %s", peer.ID(), channelId, err)
				continue
			}
		}
	}
}

func transportTo(conn net.Conn, channelID uint16, msg []byte) error {
	err := messages.UpdateTransportMsg(msg, channelID)
	if err != nil {
		return err
	}
	_, err = conn.Write(msg)
	return err
}

func handShake(conn net.Conn) (*Peer, error) {
	buf := make([]byte, 65535) // todo: reduce the buffer size
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
	return p, nil
}