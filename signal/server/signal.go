package server

import (
	"context"
	"fmt"
	"io"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/signal/metrics"
	"github.com/netbirdio/netbird/signal/peer"
	"github.com/netbirdio/netbird/signal/proto"
)

const (
	labelType              = "type"
	labelTypeError         = "error"
	labelTypeNotConnected  = "not_connected"
	labelTypeNotRegistered = "not_registered"

	labelError             = "error"
	labelErrorMissingId    = "missing_id"
	labelErrorMissingMeta  = "missing_meta"
	labelErrorFailedHeader = "failed_header"
)

// Server an instance of a Signal server
type Server struct {
	registry *peer.Registry
	proto.UnimplementedSignalExchangeServer

	metrics *metrics.AppMetrics
}

// NewServer creates a new Signal server
func NewServer(meter metric.Meter) (*Server, error) {
	appMetrics, err := metrics.NewAppMetrics(meter)
	if err != nil {
		return nil, fmt.Errorf("creating app metrics: %v", err)
	}

	s := &Server{
		registry: peer.NewRegistry(appMetrics),
		metrics:  appMetrics,
	}

	return s, nil
}

// Send forwards a message to the signal peer
func (s *Server) Send(ctx context.Context, msg *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	if !s.registry.IsPeerRegistered(msg.Key) {
		s.metrics.MessageForwardFailures.Add(ctx, 1, metric.WithAttributes(attribute.String(labelType, labelTypeNotRegistered)))

		return nil, fmt.Errorf("peer %s is not registered", msg.Key)
	}

	if dstPeer, found := s.registry.Get(msg.RemoteKey); found {
		//forward the message to the target peer
		if err := dstPeer.Stream.Send(msg); err != nil {
			log.Errorf("error while forwarding message from peer [%s] to peer [%s] %v", msg.Key, msg.RemoteKey, err)
			//todo respond to the sender?

			s.metrics.MessageForwardFailures.Add(ctx, 1, metric.WithAttributes(attribute.String(labelType, labelTypeError)))
		} else {
			s.metrics.MessagesForwarded.Add(context.Background(), 1)
		}
	} else {
		log.Debugf("message from peer [%s] can't be forwarded to peer [%s] because destination peer is not connected", msg.Key, msg.RemoteKey)
		//todo respond to the sender?

		s.metrics.MessageForwardFailures.Add(ctx, 1, metric.WithAttributes(attribute.String(labelType, labelTypeNotConnected)))
	}
	return &proto.EncryptedMessage{}, nil
}

// ConnectStream connects to the exchange stream
func (s *Server) ConnectStream(stream proto.SignalExchange_ConnectStreamServer) error {
	p, err := s.connectPeer(stream)
	if err != nil {
		return err
	}

	startRegister := time.Now()

	s.metrics.ActivePeers.Add(stream.Context(), 1)

	defer func() {
		log.Infof("peer disconnected [%s] [streamID %d] ", p.Id, p.StreamID)
		s.registry.Deregister(p)

		s.metrics.PeerConnectionDuration.Record(stream.Context(), int64(time.Since(startRegister).Seconds()))
		s.metrics.ActivePeers.Add(context.Background(), -1)
	}()

	//needed to confirm that the peer has been registered so that the client can proceed
	header := metadata.Pairs(proto.HeaderRegistered, "1")
	err = stream.SendHeader(header)
	if err != nil {
		s.metrics.RegistrationFailures.Add(stream.Context(), 1, metric.WithAttributes(attribute.String(labelError, labelErrorFailedHeader)))
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
		start := time.Now()

		log.Debugf("received a new message from peer [%s] to peer [%s]", p.Id, msg.RemoteKey)

		// lookup the target peer where the message is going to
		if dstPeer, found := s.registry.Get(msg.RemoteKey); found {
			//forward the message to the target peer
			if err := dstPeer.Stream.Send(msg); err != nil {
				log.Errorf("error while forwarding message from peer [%s] to peer [%s] %v", p.Id, msg.RemoteKey, err)
				//todo respond to the sender?

				// in milliseconds
				s.metrics.MessageForwardLatency.Record(stream.Context(), float64(time.Since(start).Nanoseconds())/1e6)
				s.metrics.MessagesForwarded.Add(stream.Context(), 1)
			} else {
				s.metrics.MessageForwardFailures.Add(stream.Context(), 1, metric.WithAttributes(attribute.String(labelType, labelTypeError)))
			}
		} else {
			log.Debugf("message from peer [%s] can't be forwarded to peer [%s] because destination peer is not connected", p.Id, msg.RemoteKey)
			//todo respond to the sender?

			s.metrics.MessageForwardFailures.Add(stream.Context(), 1, metric.WithAttributes(attribute.String(labelType, labelTypeNotConnected)))
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
			s.metrics.RegistrationFailures.Add(stream.Context(), 1, metric.WithAttributes(attribute.String(labelError, labelErrorMissingId)))
			return nil, status.Errorf(codes.FailedPrecondition, "missing connection header: "+proto.HeaderId)
		}
	} else {
		s.metrics.RegistrationFailures.Add(stream.Context(), 1, metric.WithAttributes(attribute.String(labelError, labelErrorMissingMeta)))
		return nil, status.Errorf(codes.FailedPrecondition, "missing connection stream meta")
	}
}
