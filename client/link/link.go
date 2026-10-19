package link

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	embed "github.com/netbirdio/netbird/client/embed"
)

const (
	// startTimeout bounds the wait for the overlay session to come up.
	startTimeout = 90 * time.Second
	// shutdownTimeout bounds draining in-flight requests and closing the session.
	shutdownTimeout = 10 * time.Second

	// natMapperEnv is the embedded client's switch for UPnP, NAT-PMP and PCP
	// port mapping on the local router.
	natMapperEnv = "NB_DISABLE_NAT_MAPPER"
)

// Run starts the overlay session, serves every configured forward, and blocks
// until the process is signalled or a forward fails.
func Run(ctx context.Context, cfg *Config) error {
	if cfg.Check {
		return printEffectiveConfig(os.Stdout, cfg)
	}

	creds, err := resolveCredentials(ctx, cfg)
	if err != nil {
		return interruptedOr(ctx, err)
	}

	if err := disableNATMapperUnlessSet(); err != nil {
		return err
	}

	client, err := embed.New(embed.Options{
		DeviceName:    cfg.Hostname,
		SetupKey:      creds.setupKey,
		JWTToken:      creds.jwtToken,
		ManagementURL: cfg.ManagementURL,
		ConfigPath:    cfg.ConfigPath(),
		StatePath:     cfg.StatePath(),
		LogLevel:      cfg.LogLevel,
		// nblink only dials out. Refusing inbound connections and host network
		// access keeps the peer from becoming a route into the machine it runs on.
		BlockInbound:   true,
		BlockLANAccess: true,
	})
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	log.Infof("connecting to %s", cfg.ManagementURL)
	if err := startSession(ctx, client.Start, func() { stopClient(client) }); err != nil {
		return interruptedOr(ctx, err)
	}
	logSession(client)

	forwards, err := startForwards(cfg, client.DialContext)
	if err != nil {
		stopClient(client)
		return err
	}

	err = waitForShutdown(ctx, forwards)

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancelShutdown()
	closeForwards(shutdownCtx, forwards)
	stopClient(client)

	return err
}

// disableNATMapperUnlessSet keeps the embedded client from asking the local
// router for a port mapping. An unprivileged forwarder should not change the
// network it runs on, and ICE and the relay connect without it. An operator
// who sets the variable keeps their choice.
func disableNATMapperUnlessSet() error {
	// An operator keeps their choice only when the value is one the consumer
	// can read. Empty and unparseable values reach the consumer as false,
	// which would enable the mapper rather than leave the default in place.
	if val := os.Getenv(natMapperEnv); val != "" {
		if _, err := strconv.ParseBool(val); err == nil {
			return nil
		}
		log.Warnf("failed to parse %s=%q, disabling the NAT mapper", natMapperEnv, val)
	}
	if err := os.Setenv(natMapperEnv, "true"); err != nil {
		return fmt.Errorf("set %s: %w", natMapperEnv, err)
	}
	return nil
}

// startSession runs start under startTimeout and returns as soon as ctx ends,
// even if start has not.
//
// The management dial inside the embedded client does not observe
// cancellation, so waiting for start to return would hold a signal during
// startup until the dial times out. A start that completes after the caller
// gave up is stopped in the background instead of left running.
func startSession(ctx context.Context, start func(context.Context) error, stop func()) error {
	startCtx, cancel := context.WithTimeout(ctx, startTimeout)
	done := make(chan error, 1)
	go func() {
		defer cancel()
		done <- start(startCtx)
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("start client: %w", err)
		}
		return nil
	case <-ctx.Done():
		go func() {
			if err := <-done; err == nil {
				stop()
			}
		}()
		return ctx.Err()
	}
}

// interruptedOr reports a signal during startup or login as a clean shutdown
// rather than a failure, and passes any other error through.
func interruptedOr(ctx context.Context, err error) error {
	select {
	case <-ctx.Done():
		log.Infof("interrupted before the session was up, shutting down")
		return nil
	default:
		return err
	}
}

// startForwards binds every forward before serving any of them, so a clash on
// the last one does not leave the earlier ones running.
func startForwards(cfg *Config, dial DialFunc) ([]*httpForwarder, error) {
	forwards := make([]*httpForwarder, 0, len(cfg.Forwards))
	for _, fwd := range cfg.Forwards {
		f, err := newHTTPForwarder(fwd, dial)
		if err != nil {
			closeForwards(context.Background(), forwards)
			return nil, err
		}
		forwards = append(forwards, f)
	}

	for _, f := range forwards {
		log.Infof("forwarding http://%s to %s over the overlay", f.Addr(), f.forward.Upstream)
	}
	return forwards, nil
}

// waitForShutdown blocks until a signal arrives, the context ends, or a
// forward stops serving.
func waitForShutdown(ctx context.Context, forwards []*httpForwarder) error {
	serveErr := make(chan error, len(forwards))
	for _, f := range forwards {
		go func(f *httpForwarder) {
			if err := f.Serve(); err != nil {
				serveErr <- err
			}
		}(f)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)

	select {
	case err := <-serveErr:
		return err
	case sig := <-stop:
		log.Infof("received %s, shutting down", sig)
		return nil
	case <-ctx.Done():
		// The caller's context also ends on a signal, and select picks either
		// ready case, so this path reports the shutdown too.
		log.Infof("shutting down")
		return nil
	}
}

func closeForwards(ctx context.Context, forwards []*httpForwarder) {
	for _, f := range forwards {
		if err := f.Close(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Warnf("close forward %s: %v", f.forward.Listen, err)
		}
	}
}

func stopClient(client *embed.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := client.Stop(ctx); err != nil && !errors.Is(err, embed.ErrClientNotStarted) {
		log.Warnf("stop client: %v", err)
	}
}

// logSession reports control-plane state once the session is up, so a failure
// to reach an upstream later can be told apart from a session that never
// connected. The peer name and address stay at debug level, where the rest of
// the client keeps identifying details.
func logSession(client *embed.Client) {
	status, err := client.Status()
	if err != nil {
		log.Infof("connected (status unavailable: %v)", err)
		return
	}
	log.Infof("connected, management %t, signal %t, %d peers",
		status.ManagementState.Connected, status.SignalState.Connected, len(status.Peers))
	log.Debugf("peer %s has address %s", status.LocalPeerState.FQDN, status.LocalPeerState.IP)
}

// printEffectiveConfig writes the parsed forwards and exits without touching
// the network, so a container configuration can be checked before deploying it.
func printEffectiveConfig(out io.Writer, cfg *Config) error {
	var b strings.Builder
	fmt.Fprintf(&b, "management-url: %s\n", cfg.ManagementURL)
	fmt.Fprintf(&b, "state-dir: %s\n", orDefault(cfg.StateDir, "(memory)"))
	fmt.Fprintf(&b, "hostname: %s\n", orDefault(cfg.Hostname, "(host default)"))
	fmt.Fprintf(&b, "setup-key: %t\n", cfg.SetupKey != "")
	fmt.Fprintf(&b, "allowed-hosts: %s\n", orDefault(strings.Join(cfg.AllowedHosts, ","), "(none)"))
	fmt.Fprintf(&b, "forwards: %d\n", len(cfg.Forwards))
	for _, f := range cfg.Forwards {
		fmt.Fprintf(&b, "  %s -> %s\n", f.Listen, f.Upstream)
	}
	if _, err := io.WriteString(out, b.String()); err != nil {
		return fmt.Errorf("write configuration: %w", err)
	}
	return nil
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
