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
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/system"
)

var ErrClientAlreadyStarted = errors.New("client already started")
var ErrClientNotStarted = errors.New("client not started")

// Client manages a netbird embedded client instance
type Client struct {
	deviceName string
	config     *internal.Config
	mu         sync.Mutex
	cancel     context.CancelFunc
	setupKey   string
	connect    *internal.ConnectClient
}

// Options configures a new Client
type Options struct {
	// DeviceName is this peer's name in the network
	DeviceName string
	// SetupKey is used for authentication
	SetupKey string
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
}

// New creates a new netbird embedded client
func New(opts Options) (*Client, error) {
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
	var config *internal.Config
	var err error
	input := internal.ConfigInput{
		ConfigPath:          opts.ConfigPath,
		ManagementURL:       opts.ManagementURL,
		PreSharedKey:        &opts.PreSharedKey,
		DisableServerRoutes: &t,
		DisableClientRoutes: &opts.DisableClientRoutes,
	}
	if opts.ConfigPath != "" {
		config, err = internal.UpdateOrCreateConfig(input)
	} else {
		config, err = internal.CreateInMemoryConfig(input)
	}
	if err != nil {
		return nil, fmt.Errorf("create config: %w", err)
	}

	return &Client{
		deviceName: opts.DeviceName,
		setupKey:   opts.SetupKey,
		config:     config,
	}, nil
}

// Start begins client operation and blocks until the engine has been started successfully or a startup error occurs.
// Pass a context with a deadline to limit the time spent waiting for the engine to start.
func (c *Client) Start(startCtx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel != nil {
		return ErrClientAlreadyStarted
	}

	ctx := internal.CtxInitState(context.Background())
	// nolint:staticcheck
	ctx = context.WithValue(ctx, system.DeviceNameCtxKey, c.deviceName)
	if err := internal.Login(ctx, c.config, c.setupKey, ""); err != nil {
		return fmt.Errorf("login: %w", err)
	}

	recorder := peer.NewRecorder(c.config.ManagementURL.String())
	client := internal.NewConnectClient(ctx, c.config, recorder)

	// either startup error (permanent backoff err) or nil err (successful engine up)
	// TODO: make after-startup backoff err available
	run := make(chan error, 1)
	go func() {
		if err := client.Run(run); err != nil {
			run <- err
		}
	}()

	select {
	case <-startCtx.Done():
		if stopErr := client.Stop(); stopErr != nil {
			return fmt.Errorf("stop error after context done. Stop error: %w. Context done: %w", stopErr, startCtx.Err())
		}
		return startCtx.Err()
	case err := <-run:
		if err != nil {
			if stopErr := client.Stop(); stopErr != nil {
				return fmt.Errorf("stop error after failed to startup. Stop error: %w. Start error: %w", stopErr, err)
			}
			return fmt.Errorf("startup: %w", err)
		}
	}

	c.connect = client

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

	done := make(chan error, 1)
	go func() {
		done <- c.connect.Stop()
	}()

	select {
	case <-ctx.Done():
		c.cancel = nil
		return ctx.Err()
	case err := <-done:
		c.cancel = nil
		if err != nil {
			return fmt.Errorf("stop: %w", err)
		}
		return nil
	}
}

// Dial dials a network address in the netbird network.
// Not applicable if the userspace networking mode is disabled.
func (c *Client) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	c.mu.Lock()
	connect := c.connect
	if connect == nil {
		c.mu.Unlock()
		return nil, ErrClientNotStarted
	}
	c.mu.Unlock()

	engine := connect.Engine()
	if engine == nil {
		return nil, errors.New("engine not started")
	}

	nsnet, err := engine.GetNet()
	if err != nil {
		return nil, fmt.Errorf("get net: %w", err)
	}

	return nsnet.DialContext(ctx, network, address)
}

// ListenTCP listens on the given address in the netbird network
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

// ListenUDP listens on the given address in the netbird network
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

func (c *Client) getNet() (*wgnetstack.Net, netip.Addr, error) {
	c.mu.Lock()
	connect := c.connect
	if connect == nil {
		c.mu.Unlock()
		return nil, netip.Addr{}, errors.New("client not started")
	}
	c.mu.Unlock()

	engine := connect.Engine()
	if engine == nil {
		return nil, netip.Addr{}, errors.New("engine not started")
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
