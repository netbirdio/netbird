//go:build !ios && !android

package cmd

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/kardianos/service"
	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/internal/daemonaddr"
	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/mdm"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/server"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/util"
)

func validateJSONSocketFlags() error {
	if serviceCmd.PersistentFlags().Changed("json-socket") && !enableJSONSocket {
		return fmt.Errorf("--json-socket requires --enable-json-socket to configure the daemon JSON gateway")
	}
	return nil
}

// daemonServerOptions installs the transport credentials that expose each
// caller's kernel-authenticated identity to the handlers, which is what lets
// the daemon require root/administrator for privileged operations.
//
// The handshake exchanges no bytes, so older CLI and UI binaries still
// interoperate. Callers on a TCP socket carry no identity at all: the daemon
// keeps serving them, and the privileged operations deny them, so a warning is
// logged to make the loss of functionality visible.
func daemonServerOptions(network string) []grpc.ServerOption {
	if network == "tcp" {
		log.Warnf("daemon is listening on TCP (%s): callers carry no verifiable identity over TCP, "+
			"so privileged operations (SSH root login, SSH auth, enabling the SSH server, management URL changes, "+
			"deregistration) will be denied, and the SSH JWT cache is neither filled nor served. "+
			"Use a unix socket, or npipe:// on Windows", daemonAddr)
		return nil
	}

	creds := ipcauth.NewTransportCredentials() //nolint:staticcheck
	if creds == nil {                          //nolint:staticcheck // nil only on platforms without a peer-identity primitive
		log.Warnf("daemon IPC has no peer-identity primitive on %s: privileged operations will be denied "+
			"and the SSH JWT cache is neither filled nor served", runtime.GOOS)
		return nil
	}

	return []grpc.ServerOption{grpc.Creds(creds)}
}

func (p *program) Start(svc service.Service) error {
	// Start should not block. Do the actual work async.
	log.Info("starting NetBird service") //nolint

	if err := validateJSONSocketFlags(); err != nil {
		return err
	}

	// A daemon installed before named-pipe support has the loopback TCP address
	// persisted. Move it to the named pipe so an upgraded daemon can identify
	// its callers instead of silently serving an unauthenticated socket.
	if migrated, ok := daemonaddr.MigrateLegacy(daemonAddr); ok {
		log.Infof("daemon address %q predates named-pipe support, listening on %q so callers can be identified", daemonAddr, migrated)
		daemonAddr = migrated
	}

	network, _, err := parseListenAddress(daemonAddr)
	if err != nil {
		return fmt.Errorf("parse daemon address: %w", err)
	}

	p.authzGate = ipcauth.NewAuthzGate()

	// in any case, even if configuration does not exists we run daemon to serve CLI gRPC API.
	opts := append(daemonServerOptions(network),
		grpc.ChainUnaryInterceptor(p.authzGate.UnaryPolicyInterceptor()),
		grpc.ChainStreamInterceptor(p.authzGate.StreamPolicyInterceptor()),
	)
	p.serv = grpc.NewServer(opts...)

	daemonListener, jsonListener, err := p.listenRestricted()
	if err != nil {
		// Logged as well as returned: the service manager is the only other
		// place this surfaces, and it reports a service that will not start
		// without saying why. Refusing to serve on a host whose lockdown
		// cannot be applied is deliberate, so the reason has to be findable.
		log.Errorf("failed to apply the daemon socket restriction, not serving: %v", err)
		return err
	}

	// Started only once the sockets exist. Binding them adjusts the process
	// umask for the length of the bind, and a goroutine creating a file in that
	// window would inherit it, so nothing asynchronous may be in flight before
	// this point. Keep any future background work below the listeners too.
	system.UpdateStaticInfoAsync()

	go func() {
		// Fatal here rather than inside serve, so serve's deferred listener
		// closes run before the process exits.
		if err := p.serve(daemonListener, jsonListener); err != nil {
			log.Fatalf("failed to %v", err)
		}
	}()
	return nil
}

// listenRestricted opens the daemon sockets and applies the configured access
// restriction to them before returning, so no caller can reach a socket that is
// still open to everybody. Both listeners are closed again if the restriction
// cannot be applied, and the error is returned rather than handled later, so the
// service manager sees a start that failed instead of one that succeeded and
// then died.
//
// An unreadable MDM source is an error here for the same reason a bad value is:
// on a managed host it may be carrying the restriction, and treating it as
// absent would serve every local account instead.
func (p *program) listenRestricted() (*socketListener, *socketListener, error) {
	// A nil fetcher leaves the platform-native source authoritative, which is
	// what a desktop daemon wants. This runs before the Server exists, so it
	// cannot borrow the Loader the Server owns.
	policy, err := mdm.NewLoader(nil).LoadWithError()
	if err != nil {
		return nil, nil, err
	}

	allowed, source, err := daemonSocketPrincipals(policy)
	if err != nil {
		return nil, nil, err
	}
	if len(allowed) > 0 {
		log.Infof("daemon sockets are restricted to %v by %s", allowed, source)
	}

	daemonListener, jsonListener, err := listenDaemonSockets(allowed)
	if err != nil {
		return nil, nil, err
	}

	if err := restrictListeners(daemonListener, jsonListener, allowed); err != nil {
		closeListeners(daemonListener, jsonListener)
		return nil, nil, err
	}

	return daemonListener, jsonListener, nil
}

// restrictListeners applies the access restriction to both sockets. restrict is
// a no-op for a nil listener, which is what a disabled JSON socket is.
func restrictListeners(daemonListener, jsonListener *socketListener, allowed []string) error {
	if err := daemonListener.restrict("daemon", allowed); err != nil {
		return err
	}
	return jsonListener.restrict("daemon JSON", allowed)
}

func closeListeners(listeners ...*socketListener) {
	for _, l := range listeners {
		if l == nil {
			continue
		}
		if err := l.Close(); err != nil {
			log.Debugf("close daemon listener: %v", err)
		}
	}
}

// listenDaemonSockets opens the daemon control socket and, when it is enabled, the
// JSON gateway socket. The control socket is closed again if the second one fails,
// so a failed start leaves nothing listening. The returned JSON listener is nil
// when the socket is disabled. allowed holds the resolved --allow-group
// principals, empty when both sockets are left open to every local account.
func listenDaemonSockets(allowed []string) (*socketListener, *socketListener, error) {
	daemonListener, err := listenOnAddress(daemonAddr, allowed)
	if err != nil {
		return nil, nil, fmt.Errorf("listen daemon interface: %w", err)
	}

	if !enableJSONSocket {
		removeStaleUnixSocketForAddress(jsonSocket)
		return daemonListener, nil, nil
	}

	jsonListener, err := listenOnAddress(jsonSocket, allowed)
	if err != nil {
		if cerr := daemonListener.Close(); cerr != nil {
			log.Debugf("close daemon listener: %v", cerr)
		}
		return nil, nil, fmt.Errorf("listen daemon JSON interface: %w", err)
	}

	return daemonListener, jsonListener, nil
}

// serve brings up the daemon server on listeners that are already open and
// already restricted, and blocks until it stops. jsonListener is nil when the
// JSON socket is disabled. A returned error means the daemon cannot run at all
// and the caller is expected to exit; the failures it recovers from on its own
// are logged here.
func (p *program) serve(daemonListener, jsonListener *socketListener) error {
	defer daemonListener.Close()
	if jsonListener != nil {
		defer jsonListener.Close()
	}

	serverInstance := server.New(p.ctx, util.FindFirstLogPath(logFiles), configPath, profilesDisabled, updateSettingsDisabled, captureEnabled, networksDisabled)
	p.authzGate.SetState(serverInstance)
	if err := serverInstance.Start(); err != nil {
		return fmt.Errorf("start daemon: %w", err)
	}
	proto.RegisterDaemonServiceServer(p.serv, serverInstance)

	p.serverInstanceMu.Lock()
	p.serverInstance = serverInstance
	p.serverInstanceMu.Unlock()

	if jsonListener == nil {
		log.Debug("daemon JSON socket disabled")
	} else if err := p.startJSONGateway(jsonListener, daemonAddr); err != nil {
		return fmt.Errorf("start daemon JSON server: %w", err)
	}

	log.Printf("started daemon server: %v", daemonListener.address)
	if err := p.serv.Serve(daemonListener.Listener); err != nil {
		log.Errorf("failed to serve daemon requests: %v", err)
	}
	return nil
}

func (p *program) Stop(srv service.Service) error {
	p.serverInstanceMu.Lock()
	if p.serverInstance != nil {
		in := new(proto.DownRequest)
		_, err := p.serverInstance.Down(p.ctx, in)
		if err != nil {
			log.Errorf("failed to stop daemon: %v", err)
		}
	}
	p.serverInstanceMu.Unlock()

	p.cancel()

	p.jsonServMu.Lock()
	jsonServ, jsonClient := p.jsonServ, p.jsonClient
	p.jsonServMu.Unlock()
	if jsonClient != nil {
		if err := jsonClient.Close(); err != nil {
			log.Debugf("close daemon JSON gateway client: %v", err)
		}
	}
	if jsonServ != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		if err := jsonServ.Shutdown(shutdownCtx); err != nil {
			log.Errorf("failed to stop daemon JSON server gracefully: %v", err)
			if err := jsonServ.Close(); err != nil {
				log.Errorf("failed to close daemon JSON server: %v", err)
			}
		}
		shutdownCancel()
	}

	if p.serv != nil {
		p.serv.Stop()
	}

	time.Sleep(time.Second * 2)
	log.Info("stopped NetBird service") //nolint
	return nil
}

// Common setup for service control commands
func setupServiceControlCommand(cmd *cobra.Command, ctx context.Context, cancel context.CancelFunc, consoleLog bool) (service.Service, error) {
	// rootCmd env vars are already applied by PersistentPreRunE.
	SetFlagsFromEnvVars(serviceCmd)

	cmd.SetOut(cmd.OutOrStdout())

	if err := handleRebrand(cmd); err != nil {
		return nil, err
	}

	if consoleLog {
		if err := util.InitLog(logLevel, util.LogConsole); err != nil {
			return nil, fmt.Errorf("init log: %w", err)
		}
	} else {
		if err := util.InitLog(logLevel, logFiles...); err != nil {
			return nil, fmt.Errorf("init log: %w", err)
		}
	}

	cfg, err := newSVCConfig()
	if err != nil {
		return nil, fmt.Errorf("create service config: %w", err)
	}

	s, err := newSVC(newProgram(ctx, cancel), cfg)
	if err != nil {
		return nil, err
	}

	return s, nil
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "runs NetBird as service",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(cmd.Context())

		SetupCloseHandler(ctx, cancel)
		SetupDebugHandler(ctx, nil, nil, nil, util.FindFirstLogPath(logFiles))

		s, err := setupServiceControlCommand(cmd, ctx, cancel, false)
		if err != nil {
			return err
		}
		if err := validateJSONSocketFlags(); err != nil {
			return err
		}

		return s.Run()
	},
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "starts NetBird service",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(cmd.Context())
		s, err := setupServiceControlCommand(cmd, ctx, cancel, false)
		if err != nil {
			return err
		}
		if err := validateJSONSocketFlags(); err != nil {
			return err
		}

		if err := s.Start(); err != nil {
			return fmt.Errorf("start service: %w", err)
		}
		cmd.Println("NetBird service has been started")
		return nil
	},
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "stops NetBird service",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(cmd.Context())
		s, err := setupServiceControlCommand(cmd, ctx, cancel, false)
		if err != nil {
			return err
		}

		if err := s.Stop(); err != nil {
			return fmt.Errorf("stop service: %w", err)
		}
		cmd.Println("NetBird service has been stopped")
		return nil
	},
}

var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "restarts NetBird service",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(cmd.Context())
		s, err := setupServiceControlCommand(cmd, ctx, cancel, false)
		if err != nil {
			return err
		}
		if err := validateJSONSocketFlags(); err != nil {
			return err
		}

		if err := s.Restart(); err != nil {
			return fmt.Errorf("restart service: %w", err)
		}
		cmd.Println("NetBird service has been restarted")
		return nil
	},
}

var svcStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "shows NetBird service status",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(cmd.Context())
		s, err := setupServiceControlCommand(cmd, ctx, cancel, true)
		if err != nil {
			return err
		}

		status, err := s.Status()
		if err != nil {
			return fmt.Errorf("get service status: %w", err)
		}

		var statusText string
		switch status {
		case service.StatusRunning:
			statusText = "Running"
		case service.StatusStopped:
			statusText = "Stopped"
		case service.StatusUnknown:
			statusText = "Unknown"
		default:
			statusText = fmt.Sprintf("Unknown (%d)", status)
		}

		cmd.Printf("NetBird service status: %s\n", statusText)
		return nil
	},
}
