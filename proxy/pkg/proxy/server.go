package proxy

import (
	"context"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/proxy/internal/reverseproxy"
	grpcpkg "github.com/netbirdio/netbird/proxy/pkg/grpc"
	pb "github.com/netbirdio/netbird/proxy/pkg/grpc/proto"
)

// Server represents the reverse proxy server with integrated gRPC control server
type Server struct {
	config     Config
	grpcServer *grpcpkg.Server
	caddyProxy *reverseproxy.CaddyProxy

	mu          sync.RWMutex
	isRunning   bool
	grpcRunning bool

	shutdownCtx context.Context
	cancelFunc  context.CancelFunc

	// Statistics for gRPC reporting
	stats *Stats

	// Track exposed services and their peer configs
	exposedServices map[string]*ExposedServiceConfig
}

// Stats holds proxy statistics
type Stats struct {
	mu            sync.RWMutex
	totalRequests uint64
	activeConns   uint64
	bytesSent     uint64
	bytesReceived uint64
}

// ExposedServiceConfig holds the configuration for an exposed service
type ExposedServiceConfig struct {
	ServiceID      string
	PeerConfig     *PeerConfig
	UpstreamConfig *UpstreamConfig
}

// PeerConfig holds WireGuard peer configuration
type PeerConfig struct {
	PeerID     string
	PublicKey  string
	AllowedIPs []string
	Endpoint   string
	TunnelIP   string // The WireGuard tunnel IP to route traffic to
}

// UpstreamConfig holds reverse proxy upstream configuration
type UpstreamConfig struct {
	Domain       string
	PathMappings map[string]string // path -> port mapping (relative to tunnel IP)
}

// NewServer creates a new reverse proxy server instance
func NewServer(config Config) (*Server, error) {
	// Validate config
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	shutdownCtx, cancelFunc := context.WithCancel(context.Background())

	server := &Server{
		config:          config,
		isRunning:       false,
		grpcRunning:     false,
		shutdownCtx:     shutdownCtx,
		cancelFunc:      cancelFunc,
		stats:           &Stats{},
		exposedServices: make(map[string]*ExposedServiceConfig),
	}

	// Create Caddy reverse proxy with request callback
	caddyConfig := reverseproxy.Config{
		ListenAddress: ":54321", // Use port 54321 for local testing
		EnableHTTPS:   false,    // TODO: Add HTTPS support
		RequestDataCallback: func(data *reverseproxy.RequestData) {
			// This is where access log data arrives - SET BREAKPOINT HERE
			log.WithFields(log.Fields{
				"service_id":    data.ServiceID,
				"method":        data.Method,
				"path":          data.Path,
				"response_code": data.ResponseCode,
				"duration_ms":   data.DurationMs,
				"source_ip":     data.SourceIP,
			}).Info("Access log received")

			// TODO: Send via gRPC to control service
			// This would send pb.ProxyRequestData via the gRPC stream
		},
	}
	caddyProxy, err := reverseproxy.New(caddyConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Caddy proxy: %w", err)
	}
	server.caddyProxy = caddyProxy

	// Create gRPC server if enabled
	if config.EnableGRPC && config.GRPCListenAddress != "" {
		grpcConfig := grpcpkg.Config{
			ListenAddr: config.GRPCListenAddress,
			Handler:    server, // Server implements StreamHandler interface
		}
		server.grpcServer = grpcpkg.NewServer(grpcConfig)
	}

	return server, nil
}

// Start starts the reverse proxy server and optionally the gRPC control server
func (s *Server) Start() error {
	s.mu.Lock()
	if s.isRunning {
		s.mu.Unlock()
		return fmt.Errorf("server is already running")
	}
	s.isRunning = true
	s.mu.Unlock()

	log.Infof("Starting Caddy reverse proxy server on %s", s.config.ListenAddress)

	// Start Caddy proxy
	if err := s.caddyProxy.Start(); err != nil {
		s.mu.Lock()
		s.isRunning = false
		s.mu.Unlock()
		return fmt.Errorf("failed to start Caddy proxy: %w", err)
	}

	// Start gRPC server if configured
	if s.grpcServer != nil {
		s.mu.Lock()
		s.grpcRunning = true
		s.mu.Unlock()

		go func() {
			log.Infof("Starting gRPC control server on %s", s.config.GRPCListenAddress)
			if err := s.grpcServer.Start(); err != nil {
				log.Errorf("gRPC server error: %v", err)
				s.mu.Lock()
				s.grpcRunning = false
				s.mu.Unlock()
			}
		}()

		// Send started event
		time.Sleep(100 * time.Millisecond) // Give gRPC server time to start
		s.sendProxyEvent(pb.ProxyEvent_STARTED, "Proxy server started")
	}

	if err := s.caddyProxy.AddRoute(
		&reverseproxy.RouteConfig{
			ID:           "test",
			Domain:       "test.netbird.io",
			PathMappings: map[string]string{"/": "localhost:8080"},
		}); err != nil {
		log.Warn("Failed to add test route: ", err)
	}

	// Block forever - Caddy runs in background
	<-s.shutdownCtx.Done()
	return nil
}

// Stop gracefully shuts down both Caddy and gRPC servers
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	if !s.isRunning {
		s.mu.Unlock()
		return fmt.Errorf("server is not running")
	}
	s.mu.Unlock()

	log.Info("Shutting down servers gracefully...")

	// If no context provided, use the server's shutdown timeout
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), s.config.ShutdownTimeout)
		defer cancel()
	}

	// Send stopped event before shutdown
	if s.grpcServer != nil && s.grpcRunning {
		s.sendProxyEvent(pb.ProxyEvent_STOPPED, "Proxy server shutting down")
	}

	var caddyErr, grpcErr error

	// Shutdown gRPC server first
	if s.grpcServer != nil && s.grpcRunning {
		if err := s.grpcServer.Stop(ctx); err != nil {
			grpcErr = fmt.Errorf("gRPC server shutdown failed: %w", err)
			log.Error(grpcErr)
		}
		s.mu.Lock()
		s.grpcRunning = false
		s.mu.Unlock()
	}

	// Shutdown Caddy proxy
	if err := s.caddyProxy.Stop(ctx); err != nil {
		caddyErr = fmt.Errorf("Caddy proxy shutdown failed: %w", err)
		log.Error(caddyErr)
	}

	s.mu.Lock()
	s.isRunning = false
	s.mu.Unlock()

	if caddyErr != nil {
		return caddyErr
	}
	if grpcErr != nil {
		return grpcErr
	}

	log.Info("All servers stopped successfully")
	return nil
}

// IsRunning returns whether the server is currently running
func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isRunning
}

// GetConfig returns a copy of the server configuration
func (s *Server) GetConfig() Config {
	return s.config
}

// GetStats returns a copy of current statistics
func (s *Server) GetStats() *pb.ProxyStats {
	s.stats.mu.RLock()
	defer s.stats.mu.RUnlock()

	return &pb.ProxyStats{
		Timestamp:         timestamppb.Now(),
		TotalRequests:     s.stats.totalRequests,
		ActiveConnections: s.stats.activeConns,
		BytesSent:         s.stats.bytesSent,
		BytesReceived:     s.stats.bytesReceived,
	}
}

// StreamHandler interface implementation

// HandleControlEvent handles incoming control events
// This is where ExposedService events will be routed
func (s *Server) HandleControlEvent(ctx context.Context, event *pb.ControlEvent) error {
	log.WithFields(log.Fields{
		"event_id": event.EventId,
		"message":  event.Message,
	}).Info("Received control event")

	// TODO: Parse event type and route to appropriate handler
	// if event.Type == "ExposedServiceCreated" {
	//     return s.handleExposedServiceCreated(ctx, event)
	// } else if event.Type == "ExposedServiceUpdated" {
	//     return s.handleExposedServiceUpdated(ctx, event)
	// } else if event.Type == "ExposedServiceRemoved" {
	//     return s.handleExposedServiceRemoved(ctx, event)
	// }

	return nil
}

// HandleControlCommand handles incoming control commands
func (s *Server) HandleControlCommand(ctx context.Context, command *pb.ControlCommand) error {
	log.WithFields(log.Fields{
		"command_id": command.CommandId,
		"type":       command.Type.String(),
	}).Info("Received control command")

	switch command.Type {
	case pb.ControlCommand_GET_STATS:
		// Stats are automatically sent, just log
		log.Debug("Stats requested via command")
	case pb.ControlCommand_RELOAD_CONFIG:
		log.Info("Config reload requested (not implemented yet)")
	case pb.ControlCommand_ENABLE_DEBUG:
		log.SetLevel(log.DebugLevel)
		log.Info("Debug logging enabled")
	case pb.ControlCommand_DISABLE_DEBUG:
		log.SetLevel(log.InfoLevel)
		log.Info("Debug logging disabled")
	case pb.ControlCommand_SHUTDOWN:
		log.Warn("Shutdown command received")
		go func() {
			time.Sleep(1 * time.Second)
			s.cancelFunc() // Trigger graceful shutdown
		}()
	}

	return nil
}

// HandleControlConfig handles incoming configuration updates
func (s *Server) HandleControlConfig(ctx context.Context, config *pb.ControlConfig) error {
	log.WithFields(log.Fields{
		"config_version": config.ConfigVersion,
		"settings":       config.Settings,
	}).Info("Received config update")
	return nil
}

// HandleExposedServiceEvent handles exposed service lifecycle events
func (s *Server) HandleExposedServiceEvent(ctx context.Context, event *pb.ExposedServiceEvent) error {
	log.WithFields(log.Fields{
		"service_id": event.ServiceId,
		"type":       event.Type.String(),
	}).Info("Received exposed service event")

	// Convert proto types to internal types
	peerConfig := &PeerConfig{
		PeerID:     event.PeerConfig.PeerId,
		PublicKey:  event.PeerConfig.PublicKey,
		AllowedIPs: event.PeerConfig.AllowedIps,
		Endpoint:   event.PeerConfig.Endpoint,
		TunnelIP:   event.PeerConfig.TunnelIp,
	}

	upstreamConfig := &UpstreamConfig{
		Domain:       event.UpstreamConfig.Domain,
		PathMappings: event.UpstreamConfig.PathMappings,
	}

	// Route to appropriate handler based on event type
	switch event.Type {
	case pb.ExposedServiceEvent_CREATED:
		return s.handleExposedServiceCreated(event.ServiceId, peerConfig, upstreamConfig)

	case pb.ExposedServiceEvent_UPDATED:
		return s.handleExposedServiceUpdated(event.ServiceId, peerConfig, upstreamConfig)

	case pb.ExposedServiceEvent_REMOVED:
		return s.handleExposedServiceRemoved(event.ServiceId)

	default:
		return fmt.Errorf("unknown exposed service event type: %v", event.Type)
	}
}

// Exposed Service Handlers

// handleExposedServiceCreated handles the creation of a new exposed service
func (s *Server) handleExposedServiceCreated(serviceID string, peerConfig *PeerConfig, upstreamConfig *UpstreamConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if service already exists
	if _, exists := s.exposedServices[serviceID]; exists {
		return fmt.Errorf("exposed service %s already exists", serviceID)
	}

	log.WithFields(log.Fields{
		"service_id": serviceID,
		"peer_id":    peerConfig.PeerID,
		"tunnel_ip":  peerConfig.TunnelIP,
		"domain":     upstreamConfig.Domain,
	}).Info("Creating exposed service")

	// TODO: Create WireGuard tunnel for peer
	// 1. Initialize WireGuard interface if not already done
	// 2. Add peer configuration:
	//    - Public key: peerConfig.PublicKey
	//    - Endpoint: peerConfig.Endpoint
	//    - Allowed IPs: peerConfig.AllowedIPs
	//    - Persistent keepalive: 25 seconds
	// 3. Bring up the WireGuard interface
	// 4. Verify tunnel connectivity to peerConfig.TunnelIP
	// Example pseudo-code:
	//   wgClient.AddPeer(&wireguard.PeerConfig{
	//       PublicKey:           peerConfig.PublicKey,
	//       Endpoint:            peerConfig.Endpoint,
	//       AllowedIPs:          peerConfig.AllowedIPs,
	//       PersistentKeepalive: 25,
	//   })

	// Build path mappings with tunnel IP
	pathMappings := make(map[string]string)
	for path, port := range upstreamConfig.PathMappings {
		// Combine tunnel IP with port
		target := fmt.Sprintf("%s:%s", peerConfig.TunnelIP, port)
		pathMappings[path] = target
	}

	// Add route to Caddy
	route := &reverseproxy.RouteConfig{
		ID:           serviceID,
		Domain:       upstreamConfig.Domain,
		PathMappings: pathMappings,
	}

	if err := s.caddyProxy.AddRoute(route); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}

	// Store service config
	s.exposedServices[serviceID] = &ExposedServiceConfig{
		ServiceID:      serviceID,
		PeerConfig:     peerConfig,
		UpstreamConfig: upstreamConfig,
	}

	log.Infof("Exposed service %s created successfully", serviceID)
	return nil
}

// handleExposedServiceUpdated handles updates to an existing exposed service
func (s *Server) handleExposedServiceUpdated(serviceID string, peerConfig *PeerConfig, upstreamConfig *UpstreamConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if service exists
	if _, exists := s.exposedServices[serviceID]; !exists {
		return fmt.Errorf("exposed service %s not found", serviceID)
	}

	log.WithFields(log.Fields{
		"service_id": serviceID,
		"peer_id":    peerConfig.PeerID,
		"tunnel_ip":  peerConfig.TunnelIP,
		"domain":     upstreamConfig.Domain,
	}).Info("Updating exposed service")

	// TODO: Update WireGuard tunnel if peer config changed

	// Build path mappings with tunnel IP
	pathMappings := make(map[string]string)
	for path, port := range upstreamConfig.PathMappings {
		target := fmt.Sprintf("%s:%s", peerConfig.TunnelIP, port)
		pathMappings[path] = target
	}

	// Update route in Caddy
	route := &reverseproxy.RouteConfig{
		ID:           serviceID,
		Domain:       upstreamConfig.Domain,
		PathMappings: pathMappings,
	}

	if err := s.caddyProxy.UpdateRoute(route); err != nil {
		return fmt.Errorf("failed to update route: %w", err)
	}

	// Update service config
	s.exposedServices[serviceID] = &ExposedServiceConfig{
		ServiceID:      serviceID,
		PeerConfig:     peerConfig,
		UpstreamConfig: upstreamConfig,
	}

	log.Infof("Exposed service %s updated successfully", serviceID)
	return nil
}

// handleExposedServiceRemoved handles the removal of an exposed service
func (s *Server) handleExposedServiceRemoved(serviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if service exists
	if _, exists := s.exposedServices[serviceID]; !exists {
		return fmt.Errorf("exposed service %s not found", serviceID)
	}

	log.WithFields(log.Fields{
		"service_id": serviceID,
	}).Info("Removing exposed service")

	// Remove route from Caddy
	if err := s.caddyProxy.RemoveRoute(serviceID); err != nil {
		return fmt.Errorf("failed to remove route: %w", err)
	}

	// TODO: Remove WireGuard tunnel for peer

	// Remove service config
	delete(s.exposedServices, serviceID)

	log.Infof("Exposed service %s removed successfully", serviceID)
	return nil
}

// ListExposedServices returns a list of all exposed service IDs
func (s *Server) ListExposedServices() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	services := make([]string, 0, len(s.exposedServices))
	for id := range s.exposedServices {
		services = append(services, id)
	}
	return services
}

// GetExposedService returns the configuration for a specific exposed service
func (s *Server) GetExposedService(serviceID string) (*ExposedServiceConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	service, exists := s.exposedServices[serviceID]
	if !exists {
		return nil, fmt.Errorf("exposed service %s not found", serviceID)
	}

	return service, nil
}

// Helper methods

func (s *Server) sendProxyEvent(eventType pb.ProxyEvent_EventType, message string) {
	// This would typically be called to send events
	// The actual sending happens via the gRPC stream
	log.WithFields(log.Fields{
		"type":    eventType.String(),
		"message": message,
	}).Debug("Proxy event")
}

// Stats methods

func (s *Stats) IncrementRequests() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.totalRequests++
}

func (s *Stats) IncrementActiveConns() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeConns++
}

func (s *Stats) DecrementActiveConns() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeConns > 0 {
		s.activeConns--
	}
}

func (s *Stats) AddBytesSent(bytes uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bytesSent += bytes
}

func (s *Stats) AddBytesReceived(bytes uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bytesReceived += bytes
}
