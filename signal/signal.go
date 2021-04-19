package signal

import (
	"context"
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/signal/peer"
	"github.com/wiretrustee/wiretrustee/signal/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"io"
	"net"
)

var (
	port = flag.Int("port", 10000, "The server port")
)

type SignalExchangeServer struct {
	registry *peer.Registry
}

func NewServer() *SignalExchangeServer {
	return &SignalExchangeServer{
		registry: peer.NewRegistry(),
	}
}

func (s *SignalExchangeServer) Connect(ctx context.Context, msg *proto.Message) (*proto.Message, error) {

	if _, found := s.registry.Peers[msg.Key]; found {
		return &proto.Message{}, nil
	}

	if dstPeer, found := s.registry.Peers[msg.RemoteKey]; found {
		//forward the message to the target peer
		err := dstPeer.Stream.Send(msg)
		if err != nil {
			log.Errorf("error while forwarding message from peer [%s] to peer [%s]", msg.Key, msg.RemoteKey)
			//todo respond to the sender?
		}
	} else {
		log.Warnf("message from peer [%s] can't be forwarded to peer [%s] because destination peer is not connected", msg.Key, msg.RemoteKey)
		//todo respond to the sender?
	}
	return &proto.Message{}, nil
}

func (s *SignalExchangeServer) ConnectStream(stream proto.SignalExchange_ConnectStreamServer) error {
	p, err := s.connectPeer(stream)
	if err != nil {
		return err
	}

	log.Infof("peer [%s] has successfully connected", p.Id)

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		log.Debugf("received a new message from peer [%s] to peer [%s]", p.Id, msg.RemoteKey)
		// lookup the target peer where the message is going to
		if dstPeer, found := s.registry.Peers[msg.RemoteKey]; found {
			//forward the message to the target peer
			err := dstPeer.Stream.Send(msg)
			if err != nil {
				log.Errorf("error while forwarding message from peer [%s] to peer [%s]", p.Id, msg.RemoteKey)
				//todo respond to the sender?
			}
		} else {
			log.Warnf("message from peer [%s] can't be forwarded to peer [%s] because destination peer is not connected", p.Id, msg.RemoteKey)
			//todo respond to the sender?
		}

	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

// Handles initial Peer connection.
// Each connection must provide an ID header.
// At this moment the connecting Peer will be registered in the peer.Registry
func (s SignalExchangeServer) connectPeer(stream proto.SignalExchange_ConnectStreamServer) (*peer.Peer, error) {
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

func main() {
	flag.Parse()

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	proto.RegisterSignalExchangeServer(grpcServer, NewServer())
	log.Printf("started server: localhost:%v", *port)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
