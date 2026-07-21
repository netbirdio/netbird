package roundtrip

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/embed"
	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/util"
)

const deviceNamePrefix = "ingress-proxy-"

const clientStopTimeout = 30 * time.Second

const createProxyPeerTimeout = 30 * time.Second

// backendKey identifies a backend by its host:port from the target URL.
type backendKey string

// ServiceKey uniquely identifies a service (HTTP reverse proxy or L4 service)
// that holds a reference to an embedded NetBird client. Callers should use the
// DomainServiceKey and L4ServiceKey constructors to avoid namespace collisions.
type ServiceKey string

// DomainServiceKey returns a ServiceKey for an HTTP domain-based service.
func DomainServiceKey(domain string) ServiceKey {
	return ServiceKey("domain:" + domain)
}

// L4ServiceKey returns a ServiceKey for an L4 service (TCP/UDP/TLS).
func L4ServiceKey(id types.ServiceID) ServiceKey {
	return ServiceKey("l4:" + id)
}

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

// serviceInfo holds metadata about a registered service.
type serviceInfo struct {
	serviceID types.ServiceID
}

type serviceNotification struct {
	key       ServiceKey
	serviceID types.ServiceID
}

// clientEntry holds an embedded NetBird client and tracks which services use it.
type clientEntry struct {
	client    *embed.Client
	transport *http.Transport
	// insecureTransport is a clone of transport with TLS verification disabled,
	// used when per-target skip_tls_verify is set.
	insecureTransport *http.Transport
	services          map[ServiceKey]serviceInfo
	createdAt         time.Time
	started           bool
	// inbound is opaque per-account state owned by the NetBird parent's
	// ReadyHandler. The roundtrip package never inspects this value; it
	// only stores it so RemovePeer / StopAll can hand it back to the
	// matching StopHandler. Nil when no inbound integration is active.
	inbound any
	// Per-backend in-flight limiting keyed by target host:port.
	// TODO: clean up stale entries when backend targets change.
	inflightMu  sync.Mutex
	inflightMap map[backendKey]chan struct{}
	maxInflight int
}

// IdentityForIP resolves a tunnel IP to the peer identity locally known by
// this account's embedded client. Returns (pubKey, fqdn) on success.
// ok=false means the IP is not in the account's roster — callers can use
// that as a fast deny without round-tripping management. The returned
// strings carry only what the embedded peerstore exposes; user identity
// (UserID / Email / Groups) still flows through ValidateTunnelPeer.
func (e *clientEntry) IdentityForIP(ip netip.Addr) (pubKey, fqdn string, ok bool) {
	if e == nil || e.client == nil || !ip.IsValid() {
		return "", "", false
	}
	return e.client.IdentityForIP(ip)
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

// ClientConfig holds configuration for the embedded NetBird client.
type ClientConfig struct {
	MgmtAddr     string
	WGPort       uint16
	PreSharedKey string
	Performance  embed.Performance
	// BlockInbound mirrors embed.Options.BlockInbound. Set to true on the
	// standalone proxy where the embedded client never accepts inbound;
	// set to false on the private/embedded proxy so the engine creates
	// the ACL manager and applies management's per-policy firewall rules
	// (which is what gates per-account inbound listeners on the netstack).
	BlockInbound bool
}

type statusNotifier interface {
	NotifyStatus(ctx context.Context, accountID types.AccountID, serviceID types.ServiceID, connected bool) error
}

type managementClient interface {
	CreateProxyPeer(ctx context.Context, req *proto.CreateProxyPeerRequest, opts ...grpc.CallOption) (*proto.CreateProxyPeerResponse, error)
}

// NetBird provides an http.RoundTripper implementation
// backed by underlying NetBird connections.
// Clients are keyed by AccountID, allowing multiple services to share the same connection.
type NetBird struct {
	ctx          context.Context
	proxyID      string
	proxyAddr    string
	clientCfg    ClientConfig
	logger       *log.Logger
	mgmtClient   managementClient
	transportCfg transportConfig

	clientsMux     sync.RWMutex
	clients        map[types.AccountID]*clientEntry
	lifecycleMu    sync.Map
	initLogOnce    sync.Once
	statusNotifier statusNotifier
	// readyHandler runs after the embedded client for an account reports
	// Ready. The opaque return value is stored on clientEntry and handed
	// back to stopHandler when the entry is torn down. Nil disables the
	// hook entirely (default for the standalone proxy).
	readyHandler func(ctx context.Context, accountID types.AccountID, client *embed.Client) any
	// stopHandler runs when an account's last service is removed (or the
	// transport is shutting down). Receives whatever readyHandler returned.
	stopHandler func(accountID types.AccountID, state any)

	// OnAddPeer, when set, is called after AddPeer completes for a new account
	// (i.e. when a new client was actually created, not when an existing one
	// was reused). The duration covers keygen + gRPC CreateProxyPeer + embed.New.
	OnAddPeer func(d time.Duration, err error)

	// startClient runs the post-create client startup. Nil uses runClientStartup;
	// tests override it to avoid a real embed client.Start.
	startClient func(accountID types.AccountID, client *embed.Client)
}

// ClientDebugInfo contains debug information about a client.
type ClientDebugInfo struct {
	AccountID    types.AccountID
	ServiceCount int
	ServiceKeys  []string
	HasClient    bool
	CreatedAt    time.Time
}

// accountIDContextKey is the context key for storing the account ID.
type accountIDContextKey struct{}

// skipTLSVerifyContextKey is the context key for requesting insecure TLS.
type skipTLSVerifyContextKey struct{}

// AddPeer registers a service for an account. If the account doesn't have a client yet,
// one is created by authenticating with the management server using the provided token.
// Multiple services can share the same client.
func (n *NetBird) AddPeer(ctx context.Context, accountID types.AccountID, key ServiceKey, authToken string, serviceID types.ServiceID) error {
	si := serviceInfo{serviceID: serviceID}

	if n.registerExistingClient(accountID, key, si) {
		return nil
	}

	lifecycle := n.accountLifecycle(accountID)
	lifecycle.Lock()
	transferred := false
	defer func() {
		if !transferred {
			lifecycle.Unlock()
		}
	}()

	if n.registerExistingClient(accountID, key, si) {
		return nil
	}

	createStart := time.Now()
	entry, err := n.createClientEntry(ctx, accountID, key, authToken, si)
	if n.OnAddPeer != nil {
		n.OnAddPeer(time.Since(createStart), err)
	}
	if err != nil {
		return err
	}

	n.clientsMux.Lock()
	n.clients[accountID] = entry
	n.clientsMux.Unlock()

	n.logger.WithFields(log.Fields{
		"account_id":  accountID,
		"service_key": key,
	}).Info("created new client for account")

	transferred = true
	go func() {
		defer lifecycle.Unlock()
		n.startClientStartup(accountID, entry.client)
	}()

	return nil
}

func (n *NetBird) startClientStartup(accountID types.AccountID, client *embed.Client) {
	if n.startClient != nil {
		n.startClient(accountID, client)
		return
	}
	n.runClientStartup(accountID, client)
}

// registerExistingClient registers the service against an already-present
// client for the account and returns true when it did. It notifies management
// of the new service when the client is already started.
func (n *NetBird) registerExistingClient(accountID types.AccountID, key ServiceKey, si serviceInfo) bool {
	n.clientsMux.Lock()
	entry, exists := n.clients[accountID]
	if !exists {
		n.clientsMux.Unlock()
		return false
	}
	entry.services[key] = si
	started := entry.started
	n.clientsMux.Unlock()

	n.logger.WithFields(log.Fields{
		"account_id":  accountID,
		"service_key": key,
	}).Debug("registered service with existing client")

	if started && n.statusNotifier != nil {
		if err := n.statusNotifier.NotifyStatus(context.Background(), accountID, si.serviceID, true); err != nil {
			n.logger.WithFields(log.Fields{
				"account_id":  accountID,
				"service_key": key,
			}).WithError(err).Warn("failed to notify status for existing client")
		}
	}
	return true
}

// accountLifecycle returns the per-account lifecycle mutex, serialising client
// creation against teardown so a slow client.Stop cannot race a new
// client.Start for the same account, without blocking clientsMux.
func (n *NetBird) accountLifecycle(accountID types.AccountID) *sync.Mutex {
	mu, _ := n.lifecycleMu.LoadOrStore(accountID, &sync.Mutex{})
	return mu.(*sync.Mutex)
}

// createClientEntry generates a WireGuard keypair, authenticates with management,
// and creates an embedded NetBird client. Must be called with the account's
// lifecycle mutex held.
func (n *NetBird) createClientEntry(ctx context.Context, accountID types.AccountID, key ServiceKey, authToken string, si serviceInfo) (*clientEntry, error) {
	serviceID := si.serviceID
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

	createCtx, cancel := context.WithTimeout(ctx, createProxyPeerTimeout)
	defer cancel()
	resp, err := n.mgmtClient.CreateProxyPeer(createCtx, &proto.CreateProxyPeerRequest{
		ServiceId:          string(serviceID),
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

	// Embedded client log level: warn by default (quiet in production); set
	// NB_PROXY_CLIENT_LOG_LEVEL (e.g. "trace") to surface the embedded NetBird
	// client's relay / signal / handshake detail for local debugging.
	clientLogLevel := log.WarnLevel.String()
	if v := strings.TrimSpace(os.Getenv("NB_PROXY_CLIENT_LOG_LEVEL")); v != "" {
		if lvl, err := log.ParseLevel(v); err == nil {
			clientLogLevel = lvl.String()
		} else {
			n.logger.Warnf("invalid NB_PROXY_CLIENT_LOG_LEVEL %q, using %q: %v", v, clientLogLevel, err)
		}
	}

	n.initLogOnce.Do(func() {
		if err := util.InitLog(clientLogLevel, util.LogConsole); err != nil {
			n.logger.WithField("account_id", accountID).Warnf("failed to initialize embedded client logging: %v", err)
		}
	})

	// Create embedded NetBird client with the generated private key.
	// The peer has already been created via CreateProxyPeer RPC with the public key.
	wgPort := int(n.clientCfg.WGPort)
	embedOpts := embed.Options{
		DeviceName:    deviceNamePrefix + n.proxyID,
		ManagementURL: n.clientCfg.MgmtAddr,
		PrivateKey:    privateKey.String(),
		LogLevel:      clientLogLevel,
		BlockInbound:  n.clientCfg.BlockInbound,
		// The embedded proxy peer must never be a stepping stone into
		// the proxy host's LAN: it only exists to reach NetBird mesh
		// targets or, when direct_upstream is set, the host network
		// stack via the MultiTransport's direct branch (which bypasses
		// the engine routing entirely).
		BlockLANAccess: true,
		WireguardPort:  &wgPort,
		PreSharedKey:   n.clientCfg.PreSharedKey,
		Performance:    n.clientCfg.Performance,
	}
	logEmbedOptions(n.logger, accountID, serviceID, publicKey.String(), embedOpts)
	client, err := embed.New(embedOpts)
	if err != nil {
		return nil, fmt.Errorf("create netbird client: %w", err)
	}

	// Create a transport using the client dialer. We do this instead of using
	// the client's HTTPClient to avoid issues with request validation that do
	// not work with reverse proxied requests.
	transport := &http.Transport{
		DialContext:           dialWithTimeout(client.DialContext),
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
	}

	insecureTransport := transport.Clone()
	insecureTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec

	return &clientEntry{
		client:            client,
		services:          map[ServiceKey]serviceInfo{key: si},
		transport:         transport,
		insecureTransport: insecureTransport,
		createdAt:         time.Now(),
		started:           false,
		inflightMap:       make(map[backendKey]chan struct{}),
		maxInflight:       n.transportCfg.maxInflight,
	}, nil
}

// runClientStartup starts the client and notifies registered services on
// success. This function runs in a goroutine launched from AddPeer, so it
// must never inherit the caller's request-scoped context — a canceled
// request must not abort the inbound listener bring-up or the management
// status notification. The embedded client.Start gets its own bounded
// startCtx; once Start succeeds, notifyClientReady takes over with a
// fresh context.Background() (see that function for the contract).
func (n *NetBird) runClientStartup(accountID types.AccountID, client *embed.Client) {
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

	n.notifyClientReady(accountID, client)
}

// notifyClientReady marks the account's client as started, fires the
// readyHandler hook, and notifies management of the new tunnel
// connection for every registered service. It is split out of
// runClientStartup so a regression test can drive the post-Start tail
// without needing a live embedded client. The contract that the
// hooks/notifier see context.Background() — never the AddPeer caller's
// ctx — lives here.
func (n *NetBird) notifyClientReady(accountID types.AccountID, client *embed.Client) {
	n.clientsMux.Lock()
	entry, exists := n.clients[accountID]
	if exists {
		entry.started = true
	}
	var toNotify []serviceNotification
	if exists {
		for key, info := range entry.services {
			toNotify = append(toNotify, serviceNotification{key: key, serviceID: info.serviceID})
		}
	}
	readyHandler := n.readyHandler
	n.clientsMux.Unlock()

	if readyHandler != nil {
		state := readyHandler(n.ctx, accountID, client)
		n.clientsMux.Lock()
		if e, ok := n.clients[accountID]; ok {
			e.inbound = state
		} else if state != nil && n.stopHandler != nil {
			// Account was removed while readyHandler ran; tear down the
			// resources it just brought up.
			stop := n.stopHandler
			n.clientsMux.Unlock()
			stop(accountID, state)
			n.clientsMux.Lock()
		}
		n.clientsMux.Unlock()
	}

	if n.statusNotifier == nil {
		return
	}
	for _, sn := range toNotify {
		if err := n.statusNotifier.NotifyStatus(n.ctx, accountID, sn.serviceID, true); err != nil {
			n.logger.WithFields(log.Fields{
				"account_id":  accountID,
				"service_key": sn.key,
			}).WithError(err).Warn("failed to notify tunnel connection status")
		} else {
			n.logger.WithFields(log.Fields{
				"account_id":  accountID,
				"service_key": sn.key,
			}).Info("notified management about tunnel connection")
		}
	}
}

// RemovePeer unregisters a service from an account. The client is only stopped
// when no services are using it anymore.
func (n *NetBird) RemovePeer(ctx context.Context, accountID types.AccountID, key ServiceKey) error {
	lifecycle := n.accountLifecycle(accountID)
	lifecycle.Lock()
	transferred := false
	defer func() {
		if !transferred {
			lifecycle.Unlock()
		}
	}()

	n.clientsMux.Lock()

	entry, exists := n.clients[accountID]
	if !exists {
		n.clientsMux.Unlock()
		n.logger.WithField("account_id", accountID).Debug("remove peer: account not found")
		return nil
	}

	si, svcExists := entry.services[key]
	if !svcExists {
		n.clientsMux.Unlock()
		n.logger.WithFields(log.Fields{
			"account_id":  accountID,
			"service_key": key,
		}).Debug("remove peer: service not registered")
		return nil
	}

	delete(entry.services, key)

	stopClient := len(entry.services) == 0
	if stopClient {
		n.logger.WithField("account_id", accountID).Info("stopping client, no more services")
		delete(n.clients, accountID)
	} else {
		n.logger.WithFields(log.Fields{
			"account_id":         accountID,
			"service_key":        key,
			"remaining_services": len(entry.services),
		}).Debug("unregistered service, client still in use")
	}
	n.clientsMux.Unlock()

	n.notifyDisconnect(ctx, accountID, key, si.serviceID)

	if stopClient {
		transferred = true
		go n.stopClientLocked(accountID, lifecycle, entry)
	}

	return nil
}

// stopClientLocked releases a client's resources off the caller's goroutine so a
// slow client.Stop cannot wedge the mapping receive loop (which calls RemovePeer
// synchronously). It unlocks lifecycle when done so a new client.Start for the
// same account waits for this teardown.
func (n *NetBird) stopClientLocked(accountID types.AccountID, lifecycle *sync.Mutex, entry *clientEntry) {
	defer lifecycle.Unlock()

	if entry.inbound != nil && n.stopHandler != nil {
		n.stopHandler(accountID, entry.inbound)
	}
	if entry.transport != nil {
		entry.transport.CloseIdleConnections()
	}
	if entry.insecureTransport != nil {
		entry.insecureTransport.CloseIdleConnections()
	}
	if entry.client == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), clientStopTimeout)
	defer cancel()
	if err := entry.client.Stop(ctx); err != nil {
		n.logger.WithField("account_id", accountID).WithError(err).Warn("failed to stop netbird client")
	}
}

func (n *NetBird) notifyDisconnect(ctx context.Context, accountID types.AccountID, key ServiceKey, serviceID types.ServiceID) {
	if n.statusNotifier == nil {
		return
	}
	if err := n.statusNotifier.NotifyStatus(ctx, accountID, serviceID, false); err != nil {
		if s, ok := grpcstatus.FromError(err); ok && s.Code() == codes.NotFound {
			n.logger.WithField("service_key", key).Debug("service already removed, skipping disconnect notification")
		} else {
			n.logger.WithFields(log.Fields{
				"account_id":  accountID,
				"service_key": key,
			}).WithError(err).Warn("failed to notify tunnel disconnection status")
		}
	}
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
	if skipTLSVerifyFromContext(req.Context()) {
		transport = entry.insecureTransport
	}
	n.clientsMux.RUnlock()

	release, ok := entry.acquireInflight(backendKey(req.URL.Host))
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

	stopHandler := n.stopHandler
	var merr *multierror.Error
	for accountID, entry := range n.clients {
		if entry.inbound != nil && stopHandler != nil {
			stopHandler(accountID, entry.inbound)
		}
		entry.transport.CloseIdleConnections()
		entry.insecureTransport.CloseIdleConnections()
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

// ServiceCount returns the number of services registered for the given account.
// Returns 0 if the account has no client.
func (n *NetBird) ServiceCount(accountID types.AccountID) int {
	n.clientsMux.RLock()
	defer n.clientsMux.RUnlock()
	entry, exists := n.clients[accountID]
	if !exists {
		return 0
	}
	return len(entry.services)
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

// IdentityForIP resolves a tunnel IP to a peer identity local to the given
// account. Delegates to clientEntry.IdentityForIP. Returns ok=false when
// the account has no client or the IP is not in its peerstore.
func (n *NetBird) IdentityForIP(accountID types.AccountID, ip netip.Addr) (pubKey, fqdn string, ok bool) {
	n.clientsMux.RLock()
	entry, exists := n.clients[accountID]
	n.clientsMux.RUnlock()
	if !exists {
		return "", "", false
	}
	return entry.IdentityForIP(ip)
}

// ListClientsForDebug returns information about all clients for debug purposes.
func (n *NetBird) ListClientsForDebug() map[types.AccountID]ClientDebugInfo {
	n.clientsMux.RLock()
	defer n.clientsMux.RUnlock()

	result := make(map[types.AccountID]ClientDebugInfo)
	for accountID, entry := range n.clients {
		keys := make([]string, 0, len(entry.services))
		for k := range entry.services {
			keys = append(keys, string(k))
		}
		result[accountID] = ClientDebugInfo{
			AccountID:    accountID,
			ServiceCount: len(entry.services),
			ServiceKeys:  keys,
			HasClient:    entry.client != nil,
			CreatedAt:    entry.createdAt,
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

// NewNetBird creates a new NetBird transport. Set clientCfg.WGPort to 0 for a random
// OS-assigned port. A fixed port only works with single-account deployments;
// multiple accounts will fail to bind the same port.
func NewNetBird(ctx context.Context, proxyID, proxyAddr string, clientCfg ClientConfig, logger *log.Logger, notifier statusNotifier, mgmtClient managementClient) *NetBird {
	if logger == nil {
		logger = log.StandardLogger()
	}
	return &NetBird{
		ctx:            ctx,
		proxyID:        proxyID,
		proxyAddr:      proxyAddr,
		clientCfg:      clientCfg,
		logger:         logger,
		clients:        make(map[types.AccountID]*clientEntry),
		statusNotifier: notifier,
		mgmtClient:     mgmtClient,
		transportCfg:   loadTransportConfig(logger),
	}
}

// SetClientLifecycle registers callbacks that run when an embedded
// client becomes ready and when its entry is torn down. The opaque value
// returned by ready is stored on the entry and handed back to stop on
// cleanup. Must be called before AddPeer. A nil pair leaves the
// outbound-only behaviour intact.
func (n *NetBird) SetClientLifecycle(ready func(ctx context.Context, accountID types.AccountID, client *embed.Client) any, stop func(accountID types.AccountID, state any)) {
	n.clientsMux.Lock()
	defer n.clientsMux.Unlock()
	n.readyHandler = ready
	n.stopHandler = stop
}

// dialWithTimeout wraps a DialContext function so that any dial timeout
// stored in the context (via types.WithDialTimeout) is applied only to
// the connection establishment phase, not the full request lifetime.
func dialWithTimeout(dial func(ctx context.Context, network, addr string) (net.Conn, error)) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if d, ok := types.DialTimeoutFromContext(ctx); ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, d)
			defer cancel()
		}
		return dial(ctx, network, addr)
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

// WithSkipTLSVerify marks the context to use an insecure transport that skips
// TLS certificate verification for the backend connection.
func WithSkipTLSVerify(ctx context.Context) context.Context {
	return context.WithValue(ctx, skipTLSVerifyContextKey{}, true)
}

func skipTLSVerifyFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(skipTLSVerifyContextKey{}).(bool)
	return v
}

// directUpstreamContextKey signals that the request should bypass the embedded
// NetBird WireGuard client and dial via the host's network stack instead.
// Set by the reverse-proxy rewrite step when the matched target carries
// PathTarget.DirectUpstream; consumed by MultiTransport.
type directUpstreamContextKey struct{}

// WithDirectUpstream marks the context so MultiTransport routes the request
// through its stdlib transport instead of the embedded NetBird roundtripper.
func WithDirectUpstream(ctx context.Context) context.Context {
	return context.WithValue(ctx, directUpstreamContextKey{}, true)
}

// DirectUpstreamFromContext reports whether the context has been marked to
// bypass the embedded NetBird client.
func DirectUpstreamFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(directUpstreamContextKey{}).(bool)
	return v
}

// logEmbedOptions emits a single structured INFO line summarising every
// operationally meaningful flag handed to embed.New for this per-account
// client. Secrets (PrivateKey, PreSharedKey) are reduced to a "present"
// boolean — never logged verbatim. Use this when an embedded peer
// silently misbehaves: most failure modes (inbound drops, wrong
// management URL, v6 unexpectedly on, userspace flipped, port clash)
// are obvious from these flags before any traffic flows.
func logEmbedOptions(logger *log.Logger, accountID types.AccountID, serviceID types.ServiceID, publicKey string, opts embed.Options) {
	wgPort := 0
	if opts.WireguardPort != nil {
		wgPort = *opts.WireguardPort
	}
	mtu := uint16(0)
	if opts.MTU != nil {
		mtu = *opts.MTU
	}
	perfBuffers := uint32(0)
	if opts.Performance.PreallocatedBuffersPerPool != nil {
		perfBuffers = *opts.Performance.PreallocatedBuffersPerPool
	}
	perfBatch := uint32(0)
	if opts.Performance.MaxBatchSize != nil {
		perfBatch = *opts.Performance.MaxBatchSize
	}
	logger.WithFields(log.Fields{
		"account_id":            accountID,
		"service_id":            serviceID,
		"public_key":            publicKey,
		"device_name":           opts.DeviceName,
		"management_url":        opts.ManagementURL,
		"log_level":             opts.LogLevel,
		"wg_port":               wgPort,
		"mtu":                   mtu,
		"block_inbound":         opts.BlockInbound,
		"block_lan_access":      opts.BlockLANAccess,
		"disable_ipv6":          opts.DisableIPv6,
		"disable_client_routes": opts.DisableClientRoutes,
		"no_userspace":          opts.NoUserspace,
		"config_path_set":       opts.ConfigPath != "",
		"state_path_set":        opts.StatePath != "",
		"private_key_present":   opts.PrivateKey != "",
		"presharedkey_present":  opts.PreSharedKey != "",
		"setup_key_present":     opts.SetupKey != "",
		"jwt_token_present":     opts.JWTToken != "",
		"dns_labels":            opts.DNSLabels,
		"perf_buffers_per_pool": perfBuffers,
		"perf_max_batch_size":   perfBatch,
	}).Info("starting embedded netbird client for account")
}
