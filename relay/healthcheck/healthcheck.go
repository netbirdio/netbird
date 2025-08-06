package healthcheck

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/protocol"
	"github.com/netbirdio/netbird/relay/server/listener/quic"
	"github.com/netbirdio/netbird/relay/server/listener/ws"
)

const (
	statusHealthy   = "healthy"
	statusUnHealthy = "unHealthy"

	path = "/health"

	cacheTTL = 3 * time.Second // Cache TTL for health status
)

type ServiceChecker interface {
	ListenerProtocols() []protocol.Protocol
	ListenAddress() string
}

type HealthStatus struct {
	Status           string              `json:"status"`
	Timestamp        time.Time           `json:"timestamp"`
	Listeners        []protocol.Protocol `json:"listeners"`
	CertificateValid bool                `json:"certificate_valid"`
}

type Config struct {
	ListenAddress  string
	ServiceChecker ServiceChecker
}

type Server struct {
	config     Config
	httpServer *http.Server

	cacheMu     sync.Mutex
	cacheStatus *HealthStatus
}

func NewServer(config Config) (*Server, error) {
	mux := http.NewServeMux()

	if config.ServiceChecker == nil {
		return nil, errors.New("service checker is required")
	}

	server := &Server{
		config: config,
		httpServer: &http.Server{
			Addr:         config.ListenAddress,
			Handler:      mux,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  15 * time.Second,
		},
	}

	mux.HandleFunc(path, server.handleHealthcheck)
	return server, nil
}

func (s *Server) ListenAndServe() error {
	log.Infof("starting healthcheck server on: http://%s%s", dialAddress(s.config.ListenAddress), path)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the healthcheck server
func (s *Server) Shutdown(ctx context.Context) error {
	log.Info("Shutting down healthcheck server")
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) handleHealthcheck(w http.ResponseWriter, _ *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var (
		status *HealthStatus
		ok     bool
	)
	// Cache check
	s.cacheMu.Lock()
	status = s.cacheStatus
	s.cacheMu.Unlock()

	if status != nil && time.Since(status.Timestamp) <= cacheTTL {
		ok = status.Status == statusHealthy
	} else {
		status, ok = s.getHealthStatus(ctx)
		// Update cache
		s.cacheMu.Lock()
		s.cacheStatus = status
		s.cacheMu.Unlock()
	}

	w.Header().Set("Content-Type", "application/json")

	if ok {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	encoder := json.NewEncoder(w)
	if err := encoder.Encode(status); err != nil {
		log.Errorf("Failed to encode healthcheck response: %v", err)
	}
}

func (s *Server) getHealthStatus(ctx context.Context) (*HealthStatus, bool) {
	healthy := true
	status := &HealthStatus{
		Timestamp:        time.Now(),
		Status:           statusHealthy,
		CertificateValid: true,
	}

	listeners, ok := s.validateListeners()
	if !ok {
		status.Status = statusUnHealthy
		healthy = false
	}
	status.Listeners = listeners

	if ok := s.validateCertificate(ctx); !ok {
		status.Status = statusUnHealthy
		status.CertificateValid = false
		healthy = false
	}

	return status, healthy
}

func (s *Server) validateListeners() ([]protocol.Protocol, bool) {
	listeners := s.config.ServiceChecker.ListenerProtocols()
	if len(listeners) == 0 {
		return nil, false
	}
	return listeners, true
}

func (s *Server) validateCertificate(ctx context.Context) bool {
	listenAddress := s.config.ServiceChecker.ListenAddress()
	if listenAddress == "" {
		log.Warn("listen address is empty")
		return false
	}

	dAddr := dialAddress(listenAddress)

	for _, proto := range s.config.ServiceChecker.ListenerProtocols() {
		switch proto {
		case ws.Proto:
			if err := dialWS(ctx, dAddr); err != nil {
				log.Errorf("failed to dial WebSocket listener: %v", err)
				return false
			}
		case quic.Proto:
			if err := dialQUIC(ctx, dAddr); err != nil {
				log.Errorf("failed to dial QUIC listener: %v", err)
				return false
			}
		default:
			log.Warnf("unknown protocol for healthcheck: %s", proto)
			return false
		}
	}
	return true
}

func dialAddress(listenAddress string) string {
	host, port, err := net.SplitHostPort(listenAddress)
	if err != nil {
		return listenAddress // fallback, might be invalid for dialing
	}

	if host == "" || host == "::" || host == "0.0.0.0" {
		host = "0.0.0.0"
	}

	return net.JoinHostPort(host, port)
}
