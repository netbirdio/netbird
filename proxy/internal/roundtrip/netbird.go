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

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/embed"
	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/util"
)

const deviceNamePrefix = "ingress-proxy-"

// ErrNoAccountID is returned when a request context is missing the account ID.
var ErrNoAccountID = errors.New("no account ID in request context")

// domainInfo holds metadata about a registered domain.
type domainInfo struct {
	reverseProxyID string
}

// clientEntry holds an embedded NetBird client and tracks which domains use it.
type clientEntry struct {
	client    *embed.Client
	transport *http.Transport
	domains   map[domain.Domain]domainInfo
	createdAt time.Time
	started   bool
}

type statusNotifier interface {
	NotifyStatus(ctx context.Context, accountID, reverseProxyID, domain string, connected bool) error
}

// NetBird provides an http.RoundTripper implementation
// backed by underlying NetBird connections.
// Clients are keyed by AccountID, allowing multiple domains to share the same connection.
type NetBird struct {
	mgmtAddr string
	proxyID  string
	logger   *log.Logger

	clientsMux     sync.RWMutex
	clients        map[types.AccountID]*clientEntry
	initLogOnce    sync.Once
	statusNotifier statusNotifier
}

// NewNetBird creates a new NetBird transport.
func NewNetBird(mgmtAddr, proxyID string, logger *log.Logger, notifier statusNotifier) *NetBird {
	if logger == nil {
		logger = log.StandardLogger()
	}
	return &NetBird{
		mgmtAddr:       mgmtAddr,
		proxyID:        proxyID,
		logger:         logger,
		clients:        make(map[types.AccountID]*clientEntry),
		statusNotifier: notifier,
	}
}

// AddPeer registers a domain for an account. If the account doesn't have a client yet,
// one is created using the provided setup key. Multiple domains can share the same client.
func (n *NetBird) AddPeer(ctx context.Context, accountID types.AccountID, d domain.Domain, key, reverseProxyID string) error {
	n.clientsMux.Lock()

	entry, exists := n.clients[accountID]
	if exists {
		// Client already exists for this account, just register the domain
		entry.domains[d] = domainInfo{reverseProxyID: reverseProxyID}
		started := entry.started
		n.clientsMux.Unlock()

		n.logger.WithFields(log.Fields{
			"account_id": accountID,
			"domain":     d,
		}).Debug("registered domain with existing client")

		// If client is already started, notify this domain as connected immediately
		if started && n.statusNotifier != nil {
			if err := n.statusNotifier.NotifyStatus(ctx, string(accountID), reverseProxyID, string(d), true); err != nil {
				n.logger.WithFields(log.Fields{
					"account_id": accountID,
					"domain":     d,
				}).WithError(err).Warn("failed to notify status for existing client")
			}
		}
		return nil
	}

	n.initLogOnce.Do(func() {
		if err := util.InitLog(log.WarnLevel.String(), util.LogConsole); err != nil {
			n.logger.WithField("account_id", accountID).Warnf("failed to initialize embedded client logging: %v", err)
		}
	})

	wgPort := 0
	client, err := embed.New(embed.Options{
		DeviceName:    deviceNamePrefix + n.proxyID,
		ManagementURL: n.mgmtAddr,
		SetupKey:      key,
		LogLevel:      log.WarnLevel.String(),
		BlockInbound:  true,
		WireguardPort: &wgPort,
	})
	if err != nil {
		n.clientsMux.Unlock()
		return fmt.Errorf("create netbird client: %w", err)
	}

	// Create a transport using the client dialer. We do this instead of using
	// the client's HTTPClient to avoid issues with request validation that do
	// not work with reverse proxied requests.
	entry = &clientEntry{
		client:  client,
		domains: map[domain.Domain]domainInfo{d: {reverseProxyID: reverseProxyID}},
		transport: &http.Transport{
			DialContext:           client.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		createdAt: time.Now(),
		started:   false,
	}
	n.clients[accountID] = entry
	n.clientsMux.Unlock()

	n.logger.WithFields(log.Fields{
		"account_id": accountID,
		"domain":     d,
	}).Info("created new client for account")

	// Attempt to start the client in the background, if this fails
	// then it is not ideal, but it isn't the end of the world because
	// we will try to start the client again before we use it.
	go func() {
		startCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := client.Start(startCtx); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				n.logger.WithFields(log.Fields{
					"account_id": accountID,
				}).Debug("netbird client start timed out, will retry on first request")
			} else {
				n.logger.WithFields(log.Fields{
					"account_id": accountID,
				}).WithError(err).Error("failed to start netbird client")
			}
			return
		}

		// Mark client as started and notify all registered domains
		n.clientsMux.Lock()
		entry, exists := n.clients[accountID]
		if exists {
			entry.started = true
		}
		// Copy domain info while holding lock
		var domainsToNotify []struct {
			domain         domain.Domain
			reverseProxyID string
		}
		if exists {
			for dom, info := range entry.domains {
				domainsToNotify = append(domainsToNotify, struct {
					domain         domain.Domain
					reverseProxyID string
				}{domain: dom, reverseProxyID: info.reverseProxyID})
			}
		}
		n.clientsMux.Unlock()

		// Notify all domains that they're connected
		if n.statusNotifier != nil {
			for _, domInfo := range domainsToNotify {
				if err := n.statusNotifier.NotifyStatus(ctx, string(accountID), domInfo.reverseProxyID, string(domInfo.domain), true); err != nil {
					n.logger.WithFields(log.Fields{
						"account_id": accountID,
						"domain":     domInfo.domain,
					}).WithError(err).Warn("failed to notify tunnel connection status")
				} else {
					n.logger.WithFields(log.Fields{
						"account_id": accountID,
						"domain":     domInfo.domain,
					}).Info("notified management about tunnel connection")
				}
			}
		}
	}()

	return nil
}

// RemovePeer unregisters a domain from an account. The client is only stopped
// when no domains are using it anymore.
func (n *NetBird) RemovePeer(ctx context.Context, accountID types.AccountID, d domain.Domain) error {
	n.clientsMux.Lock()

	entry, exists := n.clients[accountID]
	if !exists {
		n.clientsMux.Unlock()
		return nil
	}

	// Get domain info before deleting
	domInfo, domainExists := entry.domains[d]
	if !domainExists {
		n.clientsMux.Unlock()
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
			if err := n.statusNotifier.NotifyStatus(ctx, string(accountID), domInfo.reverseProxyID, string(d), false); err != nil {
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
		if err := n.statusNotifier.NotifyStatus(ctx, string(accountID), domInfo.reverseProxyID, string(d), false); err != nil {
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
		return nil, fmt.Errorf("no peer connection found for account: %s", accountID)
	}
	client := entry.client
	transport := entry.transport
	n.clientsMux.RUnlock()

	// Attempt to start the client, if the client is already running then
	// it will return an error that we ignore, if this hits a timeout then
	// this request is unprocessable.
	startCtx, cancel := context.WithTimeout(req.Context(), 10*time.Second)
	defer cancel()
	if err := client.Start(startCtx); err != nil {
		if !errors.Is(err, embed.ErrClientAlreadyStarted) {
			return nil, fmt.Errorf("start netbird client: %w", err)
		}
	}

	n.logger.WithFields(log.Fields{
		"account_id": accountID,
		"host":       req.Host,
		"url":        req.URL.String(),
		"requestURI": req.RequestURI,
		"method":     req.Method,
	}).Debug("running roundtrip for peer connection")

	return transport.RoundTrip(req)
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

// ClientDebugInfo contains debug information about a client.
type ClientDebugInfo struct {
	AccountID   types.AccountID
	DomainCount int
	Domains     domain.List
	HasClient   bool
	CreatedAt   time.Time
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

// accountIDContextKey is the context key for storing the account ID.
type accountIDContextKey struct{}

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
