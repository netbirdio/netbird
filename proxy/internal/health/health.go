// Package health provides health probes for the proxy server.
package health

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/embed"
	"github.com/netbirdio/netbird/proxy/internal/types"
)

const handshakeStaleThreshold = 5 * time.Minute

const (
	maxConcurrentChecks   = 3
	maxClientCheckTimeout = 5 * time.Minute
)

// clientProvider provides access to NetBird clients for health checks.
type clientProvider interface {
	ListClientsForStartup() map[types.AccountID]*embed.Client
}

// Checker tracks health state and provides probe endpoints.
type Checker struct {
	logger   *log.Logger
	provider clientProvider

	mu                  sync.RWMutex
	managementConnected bool
	initialSyncComplete bool
	shuttingDown        bool

	// checkSem limits concurrent client health checks.
	checkSem chan struct{}

	// checkHealth checks the health of a single client.
	// Defaults to checkClientHealth; overridable in tests.
	checkHealth func(*embed.Client) ClientHealth
}

// ClientHealth represents the health status of a single NetBird client.
type ClientHealth struct {
	Healthy             bool   `json:"healthy"`
	ManagementConnected bool   `json:"management_connected"`
	SignalConnected     bool   `json:"signal_connected"`
	RelaysConnected     int    `json:"relays_connected"`
	RelaysTotal         int    `json:"relays_total"`
	PeersTotal          int    `json:"peers_total"`
	PeersConnected      int    `json:"peers_connected"`
	PeersP2P            int    `json:"peers_p2p"`
	PeersRelayed        int    `json:"peers_relayed"`
	PeersDegraded       int    `json:"peers_degraded"`
	Error               string `json:"error,omitempty"`
}

// ProbeResponse represents the JSON response for health probes.
type ProbeResponse struct {
	Status  string                           `json:"status"`
	Checks  map[string]bool                  `json:"checks,omitempty"`
	Clients map[types.AccountID]ClientHealth `json:"clients,omitempty"`
}

// Server runs the health probe HTTP server on a dedicated port.
type Server struct {
	server  *http.Server
	logger  *log.Logger
	checker *Checker
}

// SetManagementConnected updates the management connection state.
func (c *Checker) SetManagementConnected(connected bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.managementConnected = connected
}

// SetInitialSyncComplete marks that the initial mapping sync has completed.
func (c *Checker) SetInitialSyncComplete() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initialSyncComplete = true
}

// SetShuttingDown marks the server as shutting down.
// This causes ReadinessProbe to return false so load balancers stop routing traffic.
func (c *Checker) SetShuttingDown() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.shuttingDown = true
}

// CheckClientsConnected verifies all clients are connected to management/signal/relay.
// Uses the provided context for timeout/cancellation, with a maximum bound of maxClientCheckTimeout.
// Limits concurrent checks via semaphore.
func (c *Checker) CheckClientsConnected(ctx context.Context) (bool, map[types.AccountID]ClientHealth) {
	// Apply upper bound timeout in case parent context has no deadline
	ctx, cancel := context.WithTimeout(ctx, maxClientCheckTimeout)
	defer cancel()

	clients := c.provider.ListClientsForStartup()

	// No clients is not a health issue
	if len(clients) == 0 {
		return true, make(map[types.AccountID]ClientHealth)
	}

	type result struct {
		accountID types.AccountID
		health    ClientHealth
	}

	resultsCh := make(chan result, len(clients))
	var wg sync.WaitGroup

	for accountID, client := range clients {
		wg.Add(1)
		go func(id types.AccountID, cl *embed.Client) {
			defer wg.Done()

			// Acquire semaphore
			select {
			case c.checkSem <- struct{}{}:
				defer func() { <-c.checkSem }()
			case <-ctx.Done():
				resultsCh <- result{id, ClientHealth{Healthy: false, Error: ctx.Err().Error()}}
				return
			}

			resultsCh <- result{id, c.checkHealth(cl)}
		}(accountID, client)
	}

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	results := make(map[types.AccountID]ClientHealth)
	allHealthy := true
	for r := range resultsCh {
		results[r.accountID] = r.health
		if !r.health.Healthy {
			allHealthy = false
		}
	}

	return allHealthy, results
}

// LivenessProbe returns true if the process is alive.
// This should always return true if we can respond.
func (c *Checker) LivenessProbe() bool {
	return true
}

// ReadinessProbe returns true if the server can accept traffic.
func (c *Checker) ReadinessProbe() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.shuttingDown {
		return false
	}
	return c.managementConnected
}

// StartupProbe checks if initial startup is complete.
// Checks management connection, initial sync, and all client health directly.
// Uses the provided context for timeout/cancellation.
func (c *Checker) StartupProbe(ctx context.Context) bool {
	c.mu.RLock()
	mgmt := c.managementConnected
	sync := c.initialSyncComplete
	c.mu.RUnlock()

	if !mgmt || !sync {
		return false
	}

	// Check all clients are connected to management/signal/relay.
	// Returns true when no clients exist (nothing to check).
	allHealthy, _ := c.CheckClientsConnected(ctx)
	return allHealthy
}

// Handler returns an http.Handler for health probe endpoints.
func (c *Checker) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz/live", c.handleLiveness)
	mux.HandleFunc("/healthz/ready", c.handleReadiness)
	mux.HandleFunc("/healthz/startup", c.handleStartup)
	mux.HandleFunc("/healthz", c.handleFull)
	return mux
}

func (c *Checker) handleLiveness(w http.ResponseWriter, r *http.Request) {
	if c.LivenessProbe() {
		c.writeProbeResponse(w, http.StatusOK, "ok", nil, nil)
		return
	}
	c.writeProbeResponse(w, http.StatusServiceUnavailable, "fail", nil, nil)
}

func (c *Checker) handleReadiness(w http.ResponseWriter, r *http.Request) {
	c.mu.RLock()
	checks := map[string]bool{
		"management_connected": c.managementConnected,
	}
	c.mu.RUnlock()

	if c.ReadinessProbe() {
		c.writeProbeResponse(w, http.StatusOK, "ok", checks, nil)
		return
	}
	c.writeProbeResponse(w, http.StatusServiceUnavailable, "fail", checks, nil)
}

func (c *Checker) handleStartup(w http.ResponseWriter, r *http.Request) {
	c.mu.RLock()
	mgmt := c.managementConnected
	syncComplete := c.initialSyncComplete
	c.mu.RUnlock()

	allClientsHealthy, clientHealth := c.CheckClientsConnected(r.Context())

	checks := map[string]bool{
		"management_connected":  mgmt,
		"initial_sync_complete": syncComplete,
		"all_clients_healthy":   allClientsHealthy,
	}

	ready := mgmt && syncComplete && allClientsHealthy
	if ready {
		c.writeProbeResponse(w, http.StatusOK, "ok", checks, clientHealth)
		return
	}
	c.writeProbeResponse(w, http.StatusServiceUnavailable, "fail", checks, clientHealth)
}

func (c *Checker) handleFull(w http.ResponseWriter, r *http.Request) {
	c.mu.RLock()
	mgmt := c.managementConnected
	sync := c.initialSyncComplete
	c.mu.RUnlock()

	allClientsHealthy, clientHealth := c.CheckClientsConnected(r.Context())

	checks := map[string]bool{
		"management_connected":  mgmt,
		"initial_sync_complete": sync,
		"all_clients_healthy":   allClientsHealthy,
	}

	status := "ok"
	statusCode := http.StatusOK
	if !c.ReadinessProbe() {
		status = "fail"
		statusCode = http.StatusServiceUnavailable
	}

	c.writeProbeResponse(w, statusCode, status, checks, clientHealth)
}

func (c *Checker) writeProbeResponse(w http.ResponseWriter, statusCode int, status string, checks map[string]bool, clients map[types.AccountID]ClientHealth) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	resp := ProbeResponse{
		Status:  status,
		Checks:  checks,
		Clients: clients,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		c.logger.Debugf("write health response: %v", err)
	}
}

// ListenAndServe starts the health probe server.
func (s *Server) ListenAndServe() error {
	s.logger.Infof("starting health probe server on %s", s.server.Addr)
	return s.server.ListenAndServe()
}

// Serve starts the health probe server on the given listener.
func (s *Server) Serve(l net.Listener) error {
	s.logger.Infof("starting health probe server on %s", l.Addr())
	return s.server.Serve(l)
}

// Shutdown gracefully shuts down the health probe server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

// NewChecker creates a new health checker.
func NewChecker(logger *log.Logger, provider clientProvider) *Checker {
	if logger == nil {
		logger = log.StandardLogger()
	}
	return &Checker{
		logger:      logger,
		provider:    provider,
		checkSem:    make(chan struct{}, maxConcurrentChecks),
		checkHealth: checkClientHealth,
	}
}

// NewServer creates a new health probe server.
// If metricsHandler is non-nil, it is mounted at /metrics on the same port.
func NewServer(addr string, checker *Checker, logger *log.Logger, metricsHandler http.Handler) *Server {
	if logger == nil {
		logger = log.StandardLogger()
	}

	handler := checker.Handler()
	if metricsHandler != nil {
		mux := http.NewServeMux()
		mux.Handle("/metrics", metricsHandler)
		mux.Handle("/", handler)
		handler = mux
	}

	return &Server{
		server: &http.Server{
			Addr:         addr,
			Handler:      handler,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		logger:  logger,
		checker: checker,
	}
}

func checkClientHealth(client *embed.Client) ClientHealth {
	if client == nil {
		return ClientHealth{
			Healthy: false,
			Error:   "client not initialized",
		}
	}

	status, err := client.Status()
	if err != nil {
		return ClientHealth{
			Healthy: false,
			Error:   err.Error(),
		}
	}

	// Count only rel:// and rels:// relays (not stun/turn)
	var relayCount, relaysConnected int
	for _, relay := range status.Relays {
		if !strings.HasPrefix(relay.URI, "rel://") && !strings.HasPrefix(relay.URI, "rels://") {
			continue
		}
		relayCount++
		if relay.Err == nil {
			relaysConnected++
		}
	}

	// Count peer connection stats
	now := time.Now()
	var peersConnected, peersP2P, peersRelayed, peersDegraded int
	for _, p := range status.Peers {
		if p.ConnStatus != embed.PeerStatusConnected {
			continue
		}
		peersConnected++
		if p.Relayed {
			peersRelayed++
		} else {
			peersP2P++
		}
		if p.LastWireguardHandshake.IsZero() || now.Sub(p.LastWireguardHandshake) > handshakeStaleThreshold {
			peersDegraded++
		}
	}

	// Client is healthy if connected to management, signal, and at least one relay (if any are defined)
	healthy := status.ManagementState.Connected &&
		status.SignalState.Connected &&
		(relayCount == 0 || relaysConnected > 0)

	return ClientHealth{
		Healthy:             healthy,
		ManagementConnected: status.ManagementState.Connected,
		SignalConnected:     status.SignalState.Connected,
		RelaysConnected:     relaysConnected,
		RelaysTotal:         relayCount,
		PeersTotal:          len(status.Peers),
		PeersConnected:      peersConnected,
		PeersP2P:            peersP2P,
		PeersRelayed:        peersRelayed,
		PeersDegraded:       peersDegraded,
	}
}
