package server

import (
	"context"
	"fmt"
	"github.com/netbirdio/netbird/signal/peer"
	"github.com/netbirdio/netbird/signal/proto"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"io"
)

// Server an instance of a Signal server
type Server struct {
	registry *peer.Registry
	proto.UnimplementedSignalExchangeServer
}

// NewServer creates a new Signal server
func NewServer() *Server {
	return &Server{
		registry: peer.NewRegistry(),
	}
}

// Send forwards a message to the signal peer
func (s *Server) Send(ctx context.Context, msg *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {

	if !s.registry.IsPeerRegistered(msg.Key) {
		return nil, fmt.Errorf("peer %s is not registered", msg.Key)
	}

	if dstPeer, found := s.registry.Get(msg.RemoteKey); found {
		//forward the message to the target peer
		err := dstPeer.Stream.Send(msg)
		if err != nil {
			log.Errorf("error while forwarding message from peer [%s] to peer [%s] %v", msg.Key, msg.RemoteKey, err)
			//todo respond to the sender?
		}
	} else {
		log.Debugf("message from peer [%s] can't be forwarded to peer [%s] because destination peer is not connected", msg.Key, msg.RemoteKey)
		//todo respond to the sender?
	}
	return &proto.EncryptedMessage{}, nil
}

// ConnectStream connects to the exchange stream
func (s *Server) ConnectStream(stream proto.SignalExchange_ConnectStreamServer) error {

	p, err := s.connectPeer(stream)
	if err != nil {
		return err
	}

	defer func() {
		log.Infof("peer disconnected [%s] [streamID %d] ", p.Id, p.StreamID)
		s.registry.Deregister(p)
	}()

	//needed to confirm that the peer has been registered so that the client can proceed
	header := metadata.Pairs(proto.HeaderRegistered, "1")
	err = stream.SendHeader(header)
	if err != nil {
		return err
	}

	log.Infof("peer connected [%s] [streamID %d] ", p.Id, p.StreamID)

	for {
		//read incoming messages
		msg, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		log.Debugf("received a new message from peer [%s] to peer [%s]", p.Id, msg.RemoteKey)
		// lookup the target peer where the message is going to
		if dstPeer, found := s.registry.Get(msg.RemoteKey); found {
			//forward the message to the target peer
			err := dstPeer.Stream.Send(msg)
			if err != nil {
				log.Errorf("error while forwarding message from peer [%s] to peer [%s] %v", p.Id, msg.RemoteKey, err)
				//todo respond to the sender?
			}
		} else {
			log.Debugf("message from peer [%s] can't be forwarded to peer [%s] because destination peer is not connected", p.Id, msg.RemoteKey)
			//todo respond to the sender?
		}
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

// Handles initial Peer connection.
// Each connection must provide an Id header.
// At this moment the connecting Peer will be registered in the peer.Registry
func (s Server) connectPeer(stream proto.SignalExchange_ConnectStreamServer) (*peer.Peer, error) {
	if meta, hasMeta := metadata.FromIncomingContext(stream.Context()); hasMeta {
		if id, found := meta[proto.HeaderId]; found {
			p := peer.NewPeer(id[0], stream)
			s.registry.Register(p)
			return p, nil
		} else {
			return nil, status.Errorf(codes.FailedPrecondition, "missing connection header: "+proto.HeaderId)
		}
	} else {
		return nil, status.Errorf(codes.FailedPrecondition, "missing connection stream meta")
	}
}
