package embed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"

	"github.com/sirupsen/logrus"
	wgnetstack "golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	sshcommon "github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/client/system"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

var (
	ErrClientAlreadyStarted = errors.New("client already started")
	ErrClientNotStarted     = errors.New("client not started")
	ErrEngineNotStarted     = errors.New("engine not started")
	ErrConfigNotInitialized = errors.New("config not initialized")
)

// PeerConnStatus is a peer's connection status.
type PeerConnStatus = peer.ConnStatus

const (
	// PeerStatusConnected indicates the peer is in connected state.
	PeerStatusConnected = peer.StatusConnected
)

// Client manages a netbird embedded client instance.
type Client struct {
	deviceName string
	config     *profilemanager.Config
	mu         sync.Mutex
	cancel     context.CancelFunc
	setupKey   string
	jwtToken   string
	connect    *internal.ConnectClient
	recorder   *peer.Status
}

// Options configures a new Client.
type Options struct {
	// DeviceName is this peer's name in the network
	DeviceName string
	// SetupKey is used for authentication
	SetupKey string
	// JWTToken is used for JWT-based authentication
	JWTToken string
	// PrivateKey is used for direct private key authentication
	PrivateKey string
	// ManagementURL overrides the default management server URL
	ManagementURL string
	// PreSharedKey is the pre-shared key for the WireGuard interface
	PreSharedKey string
	// LogOutput is the output destination for logs (defaults to os.Stderr if nil)
	LogOutput io.Writer
	// LogLevel sets the logging level (defaults to info if empty)
	LogLevel string
	// NoUserspace disables the userspace networking mode. Needs admin/root privileges
	NoUserspace bool
	// ConfigPath is the path to the netbird config file. If empty, the config will be stored in memory and not persisted.
	ConfigPath string
	// StatePath is the path to the netbird state file
	StatePath string
	// DisableClientRoutes disables the client routes
	DisableClientRoutes bool
	// BlockInbound blocks all inbound connections from peers
	BlockInbound bool
	// WireguardPort is the port for the WireGuard interface. Use 0 for a random port.
	WireguardPort *int
}

// validateCredentials checks that exactly one credential type is provided
func (opts *Options) validateCredentials() error {
	credentialsProvided := 0
	if opts.SetupKey != "" {
		credentialsProvided++
	}
	if opts.JWTToken != "" {
		credentialsProvided++
	}
	if opts.PrivateKey != "" {
		credentialsProvided++
	}

	if credentialsProvided == 0 {
		return fmt.Errorf("one of SetupKey, JWTToken, or PrivateKey must be provided")
	}
	if credentialsProvided > 1 {
		return fmt.Errorf("only one of SetupKey, JWTToken, or PrivateKey can be specified")
	}

	return nil
}

// New creates a new netbird embedded client.
func New(opts Options) (*Client, error) {
	if err := opts.validateCredentials(); err != nil {
		return nil, err
	}

	if opts.LogOutput != nil {
		logrus.SetOutput(opts.LogOutput)
	}

	if opts.LogLevel != "" {
		level, err := logrus.ParseLevel(opts.LogLevel)
		if err != nil {
			return nil, fmt.Errorf("parse log level: %w", err)
		}
		logrus.SetLevel(level)
	}

	if !opts.NoUserspace {
		if err := os.Setenv(netstack.EnvUseNetstackMode, "true"); err != nil {
			return nil, fmt.Errorf("setenv: %w", err)
		}
		if err := os.Setenv(netstack.EnvSkipProxy, "true"); err != nil {
			return nil, fmt.Errorf("setenv: %w", err)
		}
	}

	if opts.StatePath != "" {
		// TODO: Disable state if path not provided
		if err := os.Setenv("NB_DNS_STATE_FILE", opts.StatePath); err != nil {
			return nil, fmt.Errorf("setenv: %w", err)
		}
	}

	t := true
	var config *profilemanager.Config
	var err error
	input := profilemanager.ConfigInput{
		ConfigPath:          opts.ConfigPath,
		ManagementURL:       opts.ManagementURL,
		PreSharedKey:        &opts.PreSharedKey,
		DisableServerRoutes: &t,
		DisableClientRoutes: &opts.DisableClientRoutes,
		BlockInbound:        &opts.BlockInbound,
		WireguardPort:       opts.WireguardPort,
	}
	if opts.ConfigPath != "" {
		config, err = profilemanager.UpdateOrCreateConfig(input)
	} else {
		config, err = profilemanager.CreateInMemoryConfig(input)
	}
	if err != nil {
		return nil, fmt.Errorf("create config: %w", err)
	}

	if opts.PrivateKey != "" {
		config.PrivateKey = opts.PrivateKey
	}

	return &Client{
		deviceName: opts.DeviceName,
		setupKey:   opts.SetupKey,
		jwtToken:   opts.JWTToken,
		config:     config,
		recorder:   peer.NewRecorder(config.ManagementURL.String()),
	}, nil
}

// Start begins client operation and blocks until the engine has been started successfully or a startup error occurs.
// Pass a context with a deadline to limit the time spent waiting for the engine to start.
func (c *Client) Start(startCtx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.connect != nil {
		return ErrClientAlreadyStarted
	}

	ctx, cancel := context.WithCancel(internal.CtxInitState(context.Background()))
	defer func() {
		if c.connect == nil {
			cancel()
		}
	}()

	// nolint:staticcheck
	ctx = context.WithValue(ctx, system.DeviceNameCtxKey, c.deviceName)

	authClient, err := auth.NewAuth(ctx, c.config.PrivateKey, c.config.ManagementURL, c.config)
	if err != nil {
		return fmt.Errorf("create auth client: %w", err)
	}
	defer authClient.Close()

	if err, _ := authClient.Login(ctx, c.setupKey, c.jwtToken); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	client := internal.NewConnectClient(ctx, c.config, c.recorder, false)
	client.SetSyncResponsePersistence(true)

	// either startup error (permanent backoff err) or nil err (successful engine up)
	// TODO: make after-startup backoff err available
	run := make(chan struct{})
	clientErr := make(chan error, 1)
	go func() {
		if err := client.Run(run, ""); err != nil {
			clientErr <- err
		}
	}()

	select {
	case <-startCtx.Done():
		if stopErr := client.Stop(); stopErr != nil {
			return fmt.Errorf("stop error after context done. Stop error: %w. Context done: %w", stopErr, startCtx.Err())
		}
		return startCtx.Err()
	case err := <-clientErr:
		return fmt.Errorf("startup: %w", err)
	case <-run:
	}

	c.connect = client
	c.cancel = cancel

	return nil
}

// Stop gracefully stops the client.
// Pass a context with a deadline to limit the time spent waiting for the engine to stop.
func (c *Client) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connect == nil {
		return ErrClientNotStarted
	}

	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}

	done := make(chan error, 1)
	connect := c.connect
	go func() {
		done <- connect.Stop()
	}()

	select {
	case <-ctx.Done():
		c.connect = nil
		return ctx.Err()
	case err := <-done:
		c.connect = nil
		if err != nil {
			return fmt.Errorf("stop: %w", err)
		}
		return nil
	}
}

// GetConfig returns a copy of the internal client config.
func (c *Client) GetConfig() (profilemanager.Config, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.config == nil {
		return profilemanager.Config{}, ErrConfigNotInitialized
	}
	return *c.config, nil
}

// Dial dials a network address in the netbird network.
// Not applicable if the userspace networking mode is disabled.
func (c *Client) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	engine, err := c.getEngine()
	if err != nil {
		return nil, err
	}

	nsnet, err := engine.GetNet()
	if err != nil {
		return nil, fmt.Errorf("get net: %w", err)
	}

	return nsnet.DialContext(ctx, network, address)
}

// DialContext dials a network address in the netbird network with context
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return c.Dial(ctx, network, address)
}

// ListenTCP listens on the given address in the netbird network.
// Not applicable if the userspace networking mode is disabled.
func (c *Client) ListenTCP(address string) (net.Listener, error) {
	nsnet, addr, err := c.getNet()
	if err != nil {
		return nil, err
	}

	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("split host port: %w", err)
	}
	listenAddr := fmt.Sprintf("%s:%s", addr, port)

	tcpAddr, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve: %w", err)
	}
	return nsnet.ListenTCP(tcpAddr)
}

// ListenUDP listens on the given address in the netbird network.
// Not applicable if the userspace networking mode is disabled.
func (c *Client) ListenUDP(address string) (net.PacketConn, error) {
	nsnet, addr, err := c.getNet()
	if err != nil {
		return nil, err
	}

	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("split host port: %w", err)
	}
	listenAddr := fmt.Sprintf("%s:%s", addr, port)

	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve: %w", err)
	}

	return nsnet.ListenUDP(udpAddr)
}

// NewHTTPClient returns a configured http.Client that uses the netbird network for requests.
// Not applicable if the userspace networking mode is disabled.
func (c *Client) NewHTTPClient() *http.Client {
	transport := &http.Transport{
		DialContext: c.Dial,
	}

	return &http.Client{
		Transport: transport,
	}
}

// Status returns the current status of the client.
func (c *Client) Status() (peer.FullStatus, error) {
	c.mu.Lock()
	connect := c.connect
	c.mu.Unlock()

	if connect != nil {
		engine := connect.Engine()
		if engine != nil {
			_ = engine.RunHealthProbes(false)
		}
	}

	return c.recorder.GetFullStatus(), nil
}

// GetLatestSyncResponse returns the latest sync response from the management server.
func (c *Client) GetLatestSyncResponse() (*mgmProto.SyncResponse, error) {
	engine, err := c.getEngine()
	if err != nil {
		return nil, err
	}

	syncResp, err := engine.GetLatestSyncResponse()
	if err != nil {
		return nil, fmt.Errorf("get sync response: %w", err)
	}

	return syncResp, nil
}

// SetLogLevel sets the logging level for the client and its components.
func (c *Client) SetLogLevel(levelStr string) error {
	level, err := logrus.ParseLevel(levelStr)
	if err != nil {
		return fmt.Errorf("parse log level: %w", err)
	}

	logrus.SetLevel(level)

	c.mu.Lock()
	connect := c.connect
	c.mu.Unlock()

	if connect != nil {
		connect.SetLogLevel(level)
	}

	return nil
}

// VerifySSHHostKey verifies an SSH host key against stored peer keys.
// Returns nil if the key matches, ErrPeerNotFound if peer is not in network,
// ErrNoStoredKey if peer has no stored key, or an error for verification failures.
func (c *Client) VerifySSHHostKey(peerAddress string, key []byte) error {
	engine, err := c.getEngine()
	if err != nil {
		return err
	}

	storedKey, found := engine.GetPeerSSHKey(peerAddress)
	if !found {
		return sshcommon.ErrPeerNotFound
	}

	return sshcommon.VerifyHostKey(storedKey, key, peerAddress)
}

// getEngine safely retrieves the engine from the client with proper locking.
// Returns ErrClientNotStarted if the client is not started.
// Returns ErrEngineNotStarted if the engine is not available.
func (c *Client) getEngine() (*internal.Engine, error) {
	c.mu.Lock()
	connect := c.connect
	c.mu.Unlock()

	if connect == nil {
		return nil, ErrClientNotStarted
	}

	engine := connect.Engine()
	if engine == nil {
		return nil, ErrEngineNotStarted
	}

	return engine, nil
}

func (c *Client) getNet() (*wgnetstack.Net, netip.Addr, error) {
	engine, err := c.getEngine()
	if err != nil {
		return nil, netip.Addr{}, err
	}

	addr, err := engine.Address()
	if err != nil {
		return nil, netip.Addr{}, fmt.Errorf("engine address: %w", err)
	}

	nsnet, err := engine.GetNet()
	if err != nil {
		return nil, netip.Addr{}, fmt.Errorf("get net: %w", err)
	}

	return nsnet, addr, nil
}
