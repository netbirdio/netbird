package roundtrip

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/embed"
	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/util"
)

const deviceNamePrefix = "ingress-proxy-"

// backendKey identifies a backend by its host:port from the target URL.
type backendKey = string

var (
	// ErrNoAccountID is returned when a request context is missing the account ID.
	ErrNoAccountID = errors.New("no account ID in request context")
	// ErrNoPeerConnection is returned when no embedded client exists for the account.
	ErrNoPeerConnection = errors.New("no peer connection found")
	// ErrClientStartFailed is returned when the embedded client fails to start.
	ErrClientStartFailed = errors.New("client start failed")
	// ErrTooManyInflight is returned when the per-backend in-flight limit is reached.
	ErrTooManyInflight = errors.New("too many in-flight requests")
)

// domainInfo holds metadata about a registered domain.
type domainInfo struct {
	serviceID string
}

type domainNotification struct {
	domain    domain.Domain
	serviceID string
}

// clientEntry holds an embedded NetBird client and tracks which domains use it.
type clientEntry struct {
	client    *embed.Client
	transport *http.Transport
	domains   map[domain.Domain]domainInfo
	createdAt time.Time
	started   bool
	// Per-backend in-flight limiting keyed by target host:port.
	// TODO: clean up stale entries when backend targets change.
	inflightMu  sync.Mutex
	inflightMap map[backendKey]chan struct{}
	maxInflight int
}

// acquireInflight attempts to acquire an in-flight slot for the given backend.
// It returns a release function that must always be called, and true on success.
func (e *clientEntry) acquireInflight(backend backendKey) (release func(), ok bool) {
	noop := func() {}
	if e.maxInflight <= 0 {
		return noop, true
	}

	e.inflightMu.Lock()
	sem, exists := e.inflightMap[backend]
	if !exists {
		sem = make(chan struct{}, e.maxInflight)
		e.inflightMap[backend] = sem
	}
	e.inflightMu.Unlock()

	select {
	case sem <- struct{}{}:
		return func() { <-sem }, true
	default:
		return noop, false
	}
}

type statusNotifier interface {
	NotifyStatus(ctx context.Context, accountID, serviceID, domain string, connected bool) error
}

type managementClient interface {
	CreateProxyPeer(ctx context.Context, req *proto.CreateProxyPeerRequest, opts ...grpc.CallOption) (*proto.CreateProxyPeerResponse, error)
}

// NetBird provides an http.RoundTripper implementation
// backed by underlying NetBird connections.
// Clients are keyed by AccountID, allowing multiple domains to share the same connection.
type NetBird struct {
	mgmtAddr     string
	proxyID      string
	proxyAddr    string
	wgPort       int
	logger       *log.Logger
	mgmtClient   managementClient
	transportCfg transportConfig

	clientsMux     sync.RWMutex
	clients        map[types.AccountID]*clientEntry
	initLogOnce    sync.Once
	statusNotifier statusNotifier
}

// ClientDebugInfo contains debug information about a client.
type ClientDebugInfo struct {
	AccountID   types.AccountID
	DomainCount int
	Domains     domain.List
	HasClient   bool
	CreatedAt   time.Time
}

// accountIDContextKey is the context key for storing the account ID.
type accountIDContextKey struct{}

// AddPeer registers a domain for an account. If the account doesn't have a client yet,
// one is created by authenticating with the management server using the provided token.
// Multiple domains can share the same client.
func (n *NetBird) AddPeer(ctx context.Context, accountID types.AccountID, d domain.Domain, authToken, serviceID string) error {
	n.clientsMux.Lock()

	entry, exists := n.clients[accountID]
	if exists {
		// Client already exists for this account, just register the domain
		entry.domains[d] = domainInfo{serviceID: serviceID}
		started := entry.started
		n.clientsMux.Unlock()

		n.logger.WithFields(log.Fields{
			"account_id": accountID,
			"domain":     d,
		}).Debug("registered domain with existing client")

		// If client is already started, notify this domain as connected immediately
		if started && n.statusNotifier != nil {
			if err := n.statusNotifier.NotifyStatus(ctx, string(accountID), serviceID, string(d), true); err != nil {
				n.logger.WithFields(log.Fields{
					"account_id": accountID,
					"domain":     d,
				}).WithError(err).Warn("failed to notify status for existing client")
			}
		}
		return nil
	}

	entry, err := n.createClientEntry(ctx, accountID, d, authToken, serviceID)
	if err != nil {
		n.clientsMux.Unlock()
		return err
	}

	n.clients[accountID] = entry
	n.clientsMux.Unlock()

	n.logger.WithFields(log.Fields{
		"account_id": accountID,
		"domain":     d,
	}).Info("created new client for account")

	// Attempt to start the client in the background; if this fails we will
	// retry on the first request via RoundTrip.
	go n.runClientStartup(ctx, accountID, entry.client)

	return nil
}

// createClientEntry generates a WireGuard keypair, authenticates with management,
// and creates an embedded NetBird client. Must be called with clientsMux held.
func (n *NetBird) createClientEntry(ctx context.Context, accountID types.AccountID, d domain.Domain, authToken, serviceID string) (*clientEntry, error) {
	n.logger.WithFields(log.Fields{
		"account_id": accountID,
		"service_id": serviceID,
	}).Debug("generating WireGuard keypair for new peer")

	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate wireguard private key: %w", err)
	}
	publicKey := privateKey.PublicKey()

	n.logger.WithFields(log.Fields{
		"account_id": accountID,
		"service_id": serviceID,
		"public_key": publicKey.String(),
	}).Debug("authenticating new proxy peer with management")

	resp, err := n.mgmtClient.CreateProxyPeer(ctx, &proto.CreateProxyPeerRequest{
		ServiceId:          serviceID,
		AccountId:          string(accountID),
		Token:              authToken,
		WireguardPublicKey: publicKey.String(),
		Cluster:            n.proxyAddr,
	})
	if err != nil {
		return nil, fmt.Errorf("authenticate proxy peer with management: %w", err)
	}
	if resp != nil && !resp.GetSuccess() {
		errMsg := "unknown error"
		if resp.ErrorMessage != nil {
			errMsg = *resp.ErrorMessage
		}
		return nil, fmt.Errorf("proxy peer authentication failed: %s", errMsg)
	}

	n.logger.WithFields(log.Fields{
		"account_id": accountID,
		"service_id": serviceID,
		"public_key": publicKey.String(),
	}).Info("proxy peer authenticated successfully with management")

	n.initLogOnce.Do(func() {
		if err := util.InitLog(log.WarnLevel.String(), util.LogConsole); err != nil {
			n.logger.WithField("account_id", accountID).Warnf("failed to initialize embedded client logging: %v", err)
		}
	})

	// Create embedded NetBird client with the generated private key.
	// The peer has already been created via CreateProxyPeer RPC with the public key.
	client, err := embed.New(embed.Options{
		DeviceName:    deviceNamePrefix + n.proxyID,
		ManagementURL: n.mgmtAddr,
		PrivateKey:    privateKey.String(),
		LogLevel:      log.WarnLevel.String(),
		BlockInbound:  true,
		WireguardPort: &n.wgPort,
	})
	if err != nil {
		return nil, fmt.Errorf("create netbird client: %w", err)
	}

	// Create a transport using the client dialer. We do this instead of using
	// the client's HTTPClient to avoid issues with request validation that do
	// not work with reverse proxied requests.
	return &clientEntry{
		client:  client,
		domains: map[domain.Domain]domainInfo{d: {serviceID: serviceID}},
		transport: &http.Transport{
			DialContext:           client.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          n.transportCfg.maxIdleConns,
			MaxIdleConnsPerHost:   n.transportCfg.maxIdleConnsPerHost,
			MaxConnsPerHost:       n.transportCfg.maxConnsPerHost,
			IdleConnTimeout:       n.transportCfg.idleConnTimeout,
			TLSHandshakeTimeout:   n.transportCfg.tlsHandshakeTimeout,
			ExpectContinueTimeout: n.transportCfg.expectContinueTimeout,
			ResponseHeaderTimeout: n.transportCfg.responseHeaderTimeout,
			WriteBufferSize:       n.transportCfg.writeBufferSize,
			ReadBufferSize:        n.transportCfg.readBufferSize,
			DisableCompression:    n.transportCfg.disableCompression,
		},
		createdAt:   time.Now(),
		started:     false,
		inflightMap: make(map[backendKey]chan struct{}),
		maxInflight: n.transportCfg.maxInflight,
	}, nil
}

// runClientStartup starts the client and notifies registered domains on success.
func (n *NetBird) runClientStartup(ctx context.Context, accountID types.AccountID, client *embed.Client) {
	startCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := client.Start(startCtx); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			n.logger.WithField("account_id", accountID).Warn("netbird client start timed out, will retry on first request")
		} else {
			n.logger.WithField("account_id", accountID).WithError(err).Error("failed to start netbird client")
		}
		return
	}

	// Mark client as started and collect domains to notify outside the lock.
	n.clientsMux.Lock()
	entry, exists := n.clients[accountID]
	if exists {
		entry.started = true
	}
	var domainsToNotify []domainNotification
	if exists {
		for dom, info := range entry.domains {
			domainsToNotify = append(domainsToNotify, domainNotification{domain: dom, serviceID: info.serviceID})
		}
	}
	n.clientsMux.Unlock()

	if n.statusNotifier == nil {
		return
	}
	for _, dn := range domainsToNotify {
		if err := n.statusNotifier.NotifyStatus(ctx, string(accountID), dn.serviceID, string(dn.domain), true); err != nil {
			n.logger.WithFields(log.Fields{
				"account_id": accountID,
				"domain":     dn.domain,
			}).WithError(err).Warn("failed to notify tunnel connection status")
		} else {
			n.logger.WithFields(log.Fields{
				"account_id": accountID,
				"domain":     dn.domain,
			}).Info("notified management about tunnel connection")
		}
	}
}

// RemovePeer unregisters a domain from an account. The client is only stopped
// when no domains are using it anymore.
func (n *NetBird) RemovePeer(ctx context.Context, accountID types.AccountID, d domain.Domain) error {
	n.clientsMux.Lock()

	entry, exists := n.clients[accountID]
	if !exists {
		n.clientsMux.Unlock()
		n.logger.WithField("account_id", accountID).Debug("remove peer: account not found")
		return nil
	}

	// Get domain info before deleting
	domInfo, domainExists := entry.domains[d]
	if !domainExists {
		n.clientsMux.Unlock()
		n.logger.WithFields(log.Fields{
			"account_id": accountID,
			"domain":     d,
		}).Debug("remove peer: domain not registered")
		return nil
	}

	delete(entry.domains, d)

	// If there are still domains using this client, keep it running
	if len(entry.domains) > 0 {
		n.clientsMux.Unlock()

		n.logger.WithFields(log.Fields{
			"account_id":        accountID,
			"domain":            d,
			"remaining_domains": len(entry.domains),
		}).Debug("unregistered domain, client still in use")

		// Notify this domain as disconnected
		if n.statusNotifier != nil {
			if err := n.statusNotifier.NotifyStatus(ctx, string(accountID), domInfo.serviceID, string(d), false); err != nil {
				n.logger.WithFields(log.Fields{
					"account_id": accountID,
					"domain":     d,
				}).WithError(err).Warn("failed to notify tunnel disconnection status")
			}
		}
		return nil
	}

	// No more domains using this client, stop it
	n.logger.WithFields(log.Fields{
		"account_id": accountID,
	}).Info("stopping client, no more domains")

	client := entry.client
	transport := entry.transport
	delete(n.clients, accountID)
	n.clientsMux.Unlock()

	// Notify disconnection before stopping
	if n.statusNotifier != nil {
		if err := n.statusNotifier.NotifyStatus(ctx, string(accountID), domInfo.serviceID, string(d), false); err != nil {
			n.logger.WithFields(log.Fields{
				"account_id": accountID,
				"domain":     d,
			}).WithError(err).Warn("failed to notify tunnel disconnection status")
		}
	}

	transport.CloseIdleConnections()

	if err := client.Stop(ctx); err != nil {
		n.logger.WithFields(log.Fields{
			"account_id": accountID,
		}).WithError(err).Warn("failed to stop netbird client")
	}

	return nil
}

// RoundTrip implements http.RoundTripper. It looks up the client for the account
// specified in the request context and uses it to dial the backend.
func (n *NetBird) RoundTrip(req *http.Request) (*http.Response, error) {
	accountID := AccountIDFromContext(req.Context())
	if accountID == "" {
		return nil, ErrNoAccountID
	}

	// Copy references while holding lock, then unlock early to avoid blocking
	// other requests during the potentially slow RoundTrip.
	n.clientsMux.RLock()
	entry, exists := n.clients[accountID]
	if !exists {
		n.clientsMux.RUnlock()
		return nil, fmt.Errorf("%w for account: %s", ErrNoPeerConnection, accountID)
	}
	client := entry.client
	transport := entry.transport
	n.clientsMux.RUnlock()

	release, ok := entry.acquireInflight(req.URL.Host)
	defer release()
	if !ok {
		return nil, ErrTooManyInflight
	}

	// Attempt to start the client, if the client is already running then
	// it will return an error that we ignore, if this hits a timeout then
	// this request is unprocessable.
	startCtx, cancel := context.WithTimeout(req.Context(), 30*time.Second)
	defer cancel()
	if err := client.Start(startCtx); err != nil {
		if !errors.Is(err, embed.ErrClientAlreadyStarted) {
			return nil, fmt.Errorf("%w: %w", ErrClientStartFailed, err)
		}
	}

	start := time.Now()
	resp, err := transport.RoundTrip(req)
	duration := time.Since(start)

	if err != nil {
		n.logger.Debugf("roundtrip: method=%s host=%s url=%s account=%s duration=%s err=%v",
			req.Method, req.Host, req.URL.String(), accountID, duration.Truncate(time.Millisecond), err)
		return nil, err
	}

	n.logger.Debugf("roundtrip: method=%s host=%s url=%s account=%s status=%d duration=%s",
		req.Method, req.Host, req.URL.String(), accountID, resp.StatusCode, duration.Truncate(time.Millisecond))
	return resp, nil
}

// StopAll stops all clients.
func (n *NetBird) StopAll(ctx context.Context) error {
	n.clientsMux.Lock()
	defer n.clientsMux.Unlock()

	var merr *multierror.Error
	for accountID, entry := range n.clients {
		entry.transport.CloseIdleConnections()
		if err := entry.client.Stop(ctx); err != nil {
			n.logger.WithFields(log.Fields{
				"account_id": accountID,
			}).WithError(err).Warn("failed to stop netbird client during shutdown")
			merr = multierror.Append(merr, err)
		}
	}
	maps.Clear(n.clients)

	return nberrors.FormatErrorOrNil(merr)
}

// HasClient returns true if there is a client for the given account.
func (n *NetBird) HasClient(accountID types.AccountID) bool {
	n.clientsMux.RLock()
	defer n.clientsMux.RUnlock()
	_, exists := n.clients[accountID]
	return exists
}

// DomainCount returns the number of domains registered for the given account.
// Returns 0 if the account has no client.
func (n *NetBird) DomainCount(accountID types.AccountID) int {
	n.clientsMux.RLock()
	defer n.clientsMux.RUnlock()
	entry, exists := n.clients[accountID]
	if !exists {
		return 0
	}
	return len(entry.domains)
}

// ClientCount returns the total number of active clients.
func (n *NetBird) ClientCount() int {
	n.clientsMux.RLock()
	defer n.clientsMux.RUnlock()
	return len(n.clients)
}

// GetClient returns the embed.Client for the given account ID.
func (n *NetBird) GetClient(accountID types.AccountID) (*embed.Client, bool) {
	n.clientsMux.RLock()
	defer n.clientsMux.RUnlock()
	entry, exists := n.clients[accountID]
	if !exists {
		return nil, false
	}
	return entry.client, true
}

// ListClientsForDebug returns information about all clients for debug purposes.
func (n *NetBird) ListClientsForDebug() map[types.AccountID]ClientDebugInfo {
	n.clientsMux.RLock()
	defer n.clientsMux.RUnlock()

	result := make(map[types.AccountID]ClientDebugInfo)
	for accountID, entry := range n.clients {
		domains := make(domain.List, 0, len(entry.domains))
		for d := range entry.domains {
			domains = append(domains, d)
		}
		result[accountID] = ClientDebugInfo{
			AccountID:   accountID,
			DomainCount: len(entry.domains),
			Domains:     domains,
			HasClient:   entry.client != nil,
			CreatedAt:   entry.createdAt,
		}
	}
	return result
}

// ListClientsForStartup returns all embed.Client instances for health checks.
func (n *NetBird) ListClientsForStartup() map[types.AccountID]*embed.Client {
	n.clientsMux.RLock()
	defer n.clientsMux.RUnlock()

	result := make(map[types.AccountID]*embed.Client)
	for accountID, entry := range n.clients {
		if entry.client != nil {
			result[accountID] = entry.client
		}
	}
	return result
}

// NewNetBird creates a new NetBird transport. Set wgPort to 0 for a random
// OS-assigned port. A fixed port only works with single-account deployments;
// multiple accounts will fail to bind the same port.
func NewNetBird(mgmtAddr, proxyID, proxyAddr string, wgPort int, logger *log.Logger, notifier statusNotifier, mgmtClient managementClient) *NetBird {
	if logger == nil {
		logger = log.StandardLogger()
	}
	return &NetBird{
		mgmtAddr:       mgmtAddr,
		proxyID:        proxyID,
		proxyAddr:      proxyAddr,
		wgPort:         wgPort,
		logger:         logger,
		clients:        make(map[types.AccountID]*clientEntry),
		statusNotifier: notifier,
		mgmtClient:     mgmtClient,
		transportCfg:   loadTransportConfig(logger),
	}
}

// WithAccountID adds the account ID to the context.
func WithAccountID(ctx context.Context, accountID types.AccountID) context.Context {
	return context.WithValue(ctx, accountIDContextKey{}, accountID)
}

// AccountIDFromContext retrieves the account ID from the context.
func AccountIDFromContext(ctx context.Context) types.AccountID {
	v := ctx.Value(accountIDContextKey{})
	if v == nil {
		return ""
	}
	accountID, ok := v.(types.AccountID)
	if !ok {
		return ""
	}
	return accountID
}
