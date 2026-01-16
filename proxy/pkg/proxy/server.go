package proxy

import (
	"context"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/proxy/internal/auth"
	"github.com/netbirdio/netbird/proxy/internal/auth/methods"
	"github.com/netbirdio/netbird/proxy/internal/reverseproxy"
	grpcpkg "github.com/netbirdio/netbird/proxy/pkg/grpc"
	pb "github.com/netbirdio/netbird/shared/management/proto"
)

// Server represents the reverse proxy server with integrated gRPC client
type Server struct {
	config     Config
	grpcClient *grpcpkg.Client
	proxy      *reverseproxy.Proxy

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

	proxy, err := reverseproxy.New(config.ReverseProxy)
	if err != nil {
		return nil, fmt.Errorf("failed to create reverse proxy: %w", err)
	}
	server.proxy = proxy

	if config.ReverseProxy.ManagementURL == "" {
		return nil, fmt.Errorf("management URL is required")
	}

	grpcClient := grpcpkg.NewClient(grpcpkg.ClientConfig{
		ProxyID:              config.ProxyID,
		ManagementURL:        config.ReverseProxy.ManagementURL,
		ServiceUpdateHandler: server.handleServiceUpdate,
	})
	server.grpcClient = grpcClient

	// Set request data callback to send access logs to management
	proxy.SetRequestCallback(func(data reverseproxy.RequestData) {
		accessLog := &pb.ProxyRequestData{
			Timestamp:     timestamppb.Now(),
			ServiceId:     data.ServiceID,
			Host:          data.Host,
			Path:          data.Path,
			DurationMs:    data.DurationMs,
			Method:        data.Method,
			ResponseCode:  data.ResponseCode,
			SourceIp:      data.SourceIP,
			AuthMechanism: data.AuthMechanism,
			UserId:        data.UserID,
			AuthSuccess:   data.AuthSuccess,
		}
		server.grpcClient.SendAccessLog(accessLog)
	})

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

	log.Infof("Starting proxy reverse proxy server on %s", s.config.ReverseProxy.ListenAddress)

	if err := s.proxy.Start(); err != nil {
		s.mu.Lock()
		s.isRunning = false
		s.mu.Unlock()
		return fmt.Errorf("failed to start reverse proxy: %w", err)
	}

	s.mu.Lock()
	s.grpcRunning = true
	s.mu.Unlock()

	if err := s.grpcClient.Start(); err != nil {
		s.mu.Lock()
		s.isRunning = false
		s.grpcRunning = false
		s.mu.Unlock()
		return fmt.Errorf("failed to start gRPC client: %w", err)
	}

	log.Info("Proxy started and connected to management")
	log.Info("Waiting for service configurations from management...")

	<-s.shutdownCtx.Done()
	return nil
}

// Stop gracefully shuts down both proxy and gRPC servers
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

	var proxyErr, grpcErr error

	// Stop gRPC client first
	if s.grpcRunning {
		if err := s.grpcClient.Stop(); err != nil {
			grpcErr = fmt.Errorf("gRPC client shutdown failed: %w", err)
			log.Error(grpcErr)
		}
		s.mu.Lock()
		s.grpcRunning = false
		s.mu.Unlock()
	}

	// Shutdown reverse proxy
	if err := s.proxy.Stop(ctx); err != nil {
		proxyErr = fmt.Errorf("reverse proxy shutdown failed: %w", err)
		log.Error(proxyErr)
	}

	s.mu.Lock()
	s.isRunning = false
	s.mu.Unlock()

	if proxyErr != nil {
		return proxyErr
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

// handleServiceUpdate processes service updates from management
func (s *Server) handleServiceUpdate(update *pb.ServiceUpdate) error {
	log.WithFields(log.Fields{
		"service_id": update.ServiceId,
		"type":       update.Type.String(),
	}).Info("Received service update from management")

	switch update.Type {
	case pb.ServiceUpdate_CREATED:
		if update.Service == nil {
			return fmt.Errorf("service config is nil for CREATED update")
		}
		return s.addServiceFromProto(update.Service)

	case pb.ServiceUpdate_UPDATED:
		if update.Service == nil {
			return fmt.Errorf("service config is nil for UPDATED update")
		}
		return s.updateServiceFromProto(update.Service)

	case pb.ServiceUpdate_REMOVED:
		return s.removeService(update.ServiceId)

	default:
		return fmt.Errorf("unknown service update type: %v", update.Type)
	}
}

// addServiceFromProto adds a service from proto config
func (s *Server) addServiceFromProto(serviceConfig *pb.ExposedServiceConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if service already exists
	if _, exists := s.exposedServices[serviceConfig.Id]; exists {
		log.Warnf("Service %s already exists, updating instead", serviceConfig.Id)
		return s.updateServiceFromProtoLocked(serviceConfig)
	}

	log.WithFields(log.Fields{
		"service_id": serviceConfig.Id,
		"domain":     serviceConfig.Domain,
	}).Info("Adding service from management")

	// Convert proto auth config to internal auth config
	var authConfig *auth.Config
	if serviceConfig.Auth != nil {
		authConfig = convertProtoAuthConfig(serviceConfig.Auth)
	}

	// Add route to proxy
	route := &reverseproxy.RouteConfig{
		ID:           serviceConfig.Id,
		Domain:       serviceConfig.Domain,
		PathMappings: serviceConfig.PathMappings,
		AuthConfig:   authConfig,
		SetupKey:     serviceConfig.SetupKey,
	}

	if err := s.proxy.AddRoute(route); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}

	// Store service config (simplified, no peer config for now)
	s.exposedServices[serviceConfig.Id] = &ExposedServiceConfig{
		ServiceID: serviceConfig.Id,
		UpstreamConfig: &UpstreamConfig{
			Domain:       serviceConfig.Domain,
			PathMappings: serviceConfig.PathMappings,
		},
	}

	log.Infof("Service %s added successfully", serviceConfig.Id)
	return nil
}

// updateServiceFromProto updates an existing service from proto config
func (s *Server) updateServiceFromProto(serviceConfig *pb.ExposedServiceConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.updateServiceFromProtoLocked(serviceConfig)
}

func (s *Server) updateServiceFromProtoLocked(serviceConfig *pb.ExposedServiceConfig) error {
	log.WithFields(log.Fields{
		"service_id": serviceConfig.Id,
		"domain":     serviceConfig.Domain,
	}).Info("Updating service from management")

	// Convert proto auth config to internal auth config
	var authConfig *auth.Config
	if serviceConfig.Auth != nil {
		authConfig = convertProtoAuthConfig(serviceConfig.Auth)
	}

	// Update route in proxy
	route := &reverseproxy.RouteConfig{
		ID:           serviceConfig.Id,
		Domain:       serviceConfig.Domain,
		PathMappings: serviceConfig.PathMappings,
		AuthConfig:   authConfig,
		SetupKey:     serviceConfig.SetupKey,
	}

	if err := s.proxy.UpdateRoute(route); err != nil {
		return fmt.Errorf("failed to update route: %w", err)
	}

	// Update service config
	s.exposedServices[serviceConfig.Id] = &ExposedServiceConfig{
		ServiceID: serviceConfig.Id,
		UpstreamConfig: &UpstreamConfig{
			Domain:       serviceConfig.Domain,
			PathMappings: serviceConfig.PathMappings,
		},
	}

	log.Infof("Service %s updated successfully", serviceConfig.Id)
	return nil
}

// removeService removes a service
func (s *Server) removeService(serviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.WithFields(log.Fields{
		"service_id": serviceID,
	}).Info("Removing service from management")

	// Remove route from proxy
	if err := s.proxy.RemoveRoute(serviceID); err != nil {
		return fmt.Errorf("failed to remove route: %w", err)
	}

	// Remove service config
	delete(s.exposedServices, serviceID)

	log.Infof("Service %s removed successfully", serviceID)
	return nil
}

// convertProtoAuthConfig converts proto auth config to internal auth config
func convertProtoAuthConfig(protoAuth *pb.AuthConfig) *auth.Config {
	authConfig := &auth.Config{}

	switch authType := protoAuth.AuthType.(type) {
	case *pb.AuthConfig_BasicAuth:
		authConfig.BasicAuth = &methods.BasicAuthConfig{
			Username: authType.BasicAuth.Username,
			Password: authType.BasicAuth.Password,
		}
	case *pb.AuthConfig_PinAuth:
		authConfig.PIN = &methods.PINConfig{
			PIN:    authType.PinAuth.Pin,
			Header: authType.PinAuth.Header,
		}
	case *pb.AuthConfig_BearerAuth:
		authConfig.Bearer = &methods.BearerConfig{
			Enabled: authType.BearerAuth.Enabled,
		}
	}

	return authConfig
}

// Exposed Service Handlers (deprecated - keeping for backwards compatibility)

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

	// Add route to proxy
	route := &reverseproxy.RouteConfig{
		ID:           serviceID,
		Domain:       upstreamConfig.Domain,
		PathMappings: pathMappings,
	}

	if err := s.proxy.AddRoute(route); err != nil {
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

	// Update route in proxy
	route := &reverseproxy.RouteConfig{
		ID:           serviceID,
		Domain:       upstreamConfig.Domain,
		PathMappings: pathMappings,
	}

	if err := s.proxy.UpdateRoute(route); err != nil {
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

	// Remove route from proxy
	if err := s.proxy.RemoveRoute(serviceID); err != nil {
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
