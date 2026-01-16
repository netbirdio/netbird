package grpc

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	pb "github.com/netbirdio/netbird/proxy/pkg/grpc/proto"
)

// StreamHandler handles incoming messages from control service
type StreamHandler interface {
	HandleControlEvent(ctx context.Context, event *pb.ControlEvent) error
	HandleControlCommand(ctx context.Context, command *pb.ControlCommand) error
	HandleControlConfig(ctx context.Context, config *pb.ControlConfig) error
	HandleExposedServiceEvent(ctx context.Context, event *pb.ExposedServiceEvent) error
}

// Server represents the gRPC server running on the proxy
type Server struct {
	pb.UnimplementedProxyServiceServer

	listenAddr string
	grpcServer *grpc.Server
	handler    StreamHandler

	mu        sync.RWMutex
	streams   map[string]*StreamContext
	isRunning bool
}

// StreamContext holds the context for each active stream
type StreamContext struct {
	stream    pb.ProxyService_StreamServer
	sendChan  chan *pb.ProxyMessage
	ctx       context.Context
	cancel    context.CancelFunc
	controlID string // ID of the connected control service
}

// Config holds gRPC server configuration
type Config struct {
	ListenAddr string
	Handler    StreamHandler
}

// NewServer creates a new gRPC server
func NewServer(config Config) *Server {
	return &Server{
		listenAddr: config.ListenAddr,
		handler:    config.Handler,
		streams:    make(map[string]*StreamContext),
	}
}

// Start starts the gRPC server
func (s *Server) Start() error {
	s.mu.Lock()
	if s.isRunning {
		s.mu.Unlock()
		return fmt.Errorf("gRPC server already running")
	}
	s.isRunning = true
	s.mu.Unlock()

	lis, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		s.mu.Lock()
		s.isRunning = false
		s.mu.Unlock()
		return fmt.Errorf("failed to listen: %w", err)
	}

	s.grpcServer = grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)

	pb.RegisterProxyServiceServer(s.grpcServer, s)

	log.Infof("gRPC server listening on %s", s.listenAddr)

	if err := s.grpcServer.Serve(lis); err != nil {
		s.mu.Lock()
		s.isRunning = false
		s.mu.Unlock()
		return fmt.Errorf("failed to serve: %w", err)
	}

	return nil
}

// Stop gracefully stops the gRPC server
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	if !s.isRunning {
		s.mu.Unlock()
		return fmt.Errorf("gRPC server not running")
	}
	s.mu.Unlock()

	log.Info("Stopping gRPC server...")

	s.mu.Lock()
	for _, streamCtx := range s.streams {
		streamCtx.cancel()
		close(streamCtx.sendChan)
	}
	s.streams = make(map[string]*StreamContext)
	s.mu.Unlock()

	stopped := make(chan struct{})
	go func() {
		s.grpcServer.GracefulStop()
		close(stopped)
	}()

	select {
	case <-stopped:
		log.Info("gRPC server stopped gracefully")
	case <-ctx.Done():
		log.Warn("gRPC server graceful stop timeout, forcing stop")
		s.grpcServer.Stop()
	}

	s.mu.Lock()
	s.isRunning = false
	s.mu.Unlock()

	return nil
}

// Stream implements the bidirectional streaming RPC
// The control service connects as client, proxy is server
// Control service sends ControlMessage, Proxy sends ProxyMessage
func (s *Server) Stream(stream pb.ProxyService_StreamServer) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	controlID := fmt.Sprintf("control-%d", time.Now().Unix())

	streamCtx := &StreamContext{
		stream:    stream,
		sendChan:  make(chan *pb.ProxyMessage, 100),
		ctx:       ctx,
		cancel:    cancel,
		controlID: controlID,
	}

	s.mu.Lock()
	s.streams[controlID] = streamCtx
	s.mu.Unlock()

	log.Infof("Control service connected: %s", controlID)

	sendDone := make(chan error, 1)
	go s.sendLoop(streamCtx, sendDone)

	recvDone := make(chan error, 1)
	go s.receiveLoop(streamCtx, recvDone)

	select {
	case err := <-sendDone:
		log.Infof("Control service %s send loop ended: %v", controlID, err)
		return err
	case err := <-recvDone:
		log.Infof("Control service %s receive loop ended: %v", controlID, err)
		return err
	case <-ctx.Done():
		log.Infof("Control service %s context done: %v", controlID, ctx.Err())
		return ctx.Err()
	}
}

// sendLoop handles sending ProxyMessages to the control service
func (s *Server) sendLoop(streamCtx *StreamContext, done chan<- error) {
	for {
		select {
		case msg, ok := <-streamCtx.sendChan:
			if !ok {
				done <- nil
				return
			}

			if err := streamCtx.stream.Send(msg); err != nil {
				log.Errorf("Failed to send message to control service: %v", err)
				done <- err
				return
			}

		case <-streamCtx.ctx.Done():
			done <- streamCtx.ctx.Err()
			return
		}
	}
}

// receiveLoop handles receiving ControlMessages from the control service
func (s *Server) receiveLoop(streamCtx *StreamContext, done chan<- error) {
	for {
		controlMsg, err := streamCtx.stream.Recv()
		if err != nil {
			log.Debugf("Stream receive error: %v", err)
			done <- err
			return
		}

		switch m := controlMsg.Message.(type) {
		case *pb.ControlMessage_Event:
			if s.handler != nil {
				if err := s.handler.HandleControlEvent(streamCtx.ctx, m.Event); err != nil {
					log.Errorf("Failed to handle control event: %v", err)
				}
			}

		case *pb.ControlMessage_Command:
			if s.handler != nil {
				if err := s.handler.HandleControlCommand(streamCtx.ctx, m.Command); err != nil {
					log.Errorf("Failed to handle control command: %v", err)
				}
			}

		case *pb.ControlMessage_Config:
			if s.handler != nil {
				if err := s.handler.HandleControlConfig(streamCtx.ctx, m.Config); err != nil {
					log.Errorf("Failed to handle control config: %v", err)
				}
			}

		case *pb.ControlMessage_ExposedService:
			if s.handler != nil {
				if err := s.handler.HandleExposedServiceEvent(streamCtx.ctx, m.ExposedService); err != nil {
					log.Errorf("Failed to handle exposed service event: %v", err)
				}
			}

		default:
			log.Warnf("Received unknown control message type: %T", m)
		}
	}
}

// SendProxyMessage sends a ProxyMessage to all connected control services
func (s *Server) SendProxyMessage(msg *pb.ProxyMessage) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, streamCtx := range s.streams {
		select {
		case streamCtx.sendChan <- msg:
		default:
			log.Warn("Send channel full, dropping message")
		}
	}
}

// GetActiveStreams returns the number of active streams
func (s *Server) GetActiveStreams() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.streams)
}
