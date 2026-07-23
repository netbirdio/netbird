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

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/server"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/util"
)

// daemonServerOptions installs peer-identity transport credentials and the
// authorization interceptor on the daemon ipc. Identity is only available
// over a Unix socket (SO_PEERCRED) or a Windows named pipe (client token).
// Over TCP, or on platforms without a peer-credential primitive, the daemon
// runs without per-caller authorization and warns (no interceptor, so it does
// not deny everyone).
func daemonServerOptions(network string, interceptor *ipcauth.Interceptor) []grpc.ServerOption {
	creds := ipcauth.NewTransportCredentials()
	if creds == nil {
		log.Warnf("daemon ipc has no peer-identity primitive on %s, per-caller authorization is disabled", runtime.GOOS)
		return nil
	}
	if network == "tcp" {
		log.Warnf("daemon is listening on TCP (%s), peer identity cannot be authenticated over TCP, per-caller authorization is disabled", daemonAddr)
		return nil
	}
	return []grpc.ServerOption{
		grpc.Creds(creds),
		grpc.ChainUnaryInterceptor(interceptor.UnaryServerInterceptor()),
		grpc.ChainStreamInterceptor(interceptor.StreamServerInterceptor()),
	}
}

func validateJSONSocketFlags() error {
	if serviceCmd.PersistentFlags().Changed("json-socket") && !enableJSONSocket {
		return fmt.Errorf("--json-socket requires --enable-json-socket to configure the daemon JSON gateway")
	}
	return nil
}

func (p *program) Start(svc service.Service) error {
	// Start should not block. Do the actual work async.
	log.Info("starting NetBird service") //nolint

	if err := validateJSONSocketFlags(); err != nil {
		return err
	}

	// Collect static system and platform information
	system.UpdateStaticInfoAsync()

	network, _, err := parseListenAddress(daemonAddr)
	if err != nil {
		return fmt.Errorf("parse daemon address: %w", err)
	}

	// Owner-authorization interceptor. The ConfigAdapter is a lazy bridge: the
	// gRPC server is built before the daemon server instance exists, so we set
	// the real policy backend below once serverInstance is created.
	ownerAdapter := &ipcauth.ConfigAdapter{}
	authInterceptor := ipcauth.NewInterceptor(ownerAdapter, ipcauth.NewDefaultGroupResolver())

	// in any case, even if configuration does not exist we run daemon to serve the CLI gRPC API.
	p.serv = grpc.NewServer(daemonServerOptions(network, authInterceptor)...)

	daemonListener, err := listenOnAddress(daemonAddr)
	if err != nil {
		return fmt.Errorf("listen daemon interface: %w", err)
	}

	var jsonListener *socketListener
	if enableJSONSocket {
		jsonListener, err = listenOnAddress(jsonSocket)
		if err != nil {
			_ = daemonListener.Close()
			return fmt.Errorf("listen daemon JSON interface: %w", err)
		}
	} else {
		removeStaleUnixSocketForAddress(jsonSocket)
	}

	go func() {
		defer daemonListener.Close()
		if jsonListener != nil {
			defer jsonListener.Close()
		}

		if err := daemonListener.chmodUnixSocket("daemon"); err != nil {
			log.Error(err)
			return
		}
		if jsonListener != nil {
			if err := jsonListener.chmodUnixSocket("daemon JSON"); err != nil {
				log.Error(err)
				return
			}
		}

		serverInstance := server.New(p.ctx, util.FindFirstLogPath(logFiles), configPath, profilesDisabled, updateSettingsDisabled, captureEnabled, networksDisabled)
		if err := serverInstance.Start(); err != nil {
			log.Fatalf("failed to start daemon: %v", err)
		}
		ownerAdapter.SetBackend(serverInstance)
		proto.RegisterDaemonServiceServer(p.serv, serverInstance)

		p.serverInstanceMu.Lock()
		p.serverInstance = serverInstance
		p.serverInstanceMu.Unlock()

		if jsonListener != nil {
			log.Warnf("JSON gateway (--enable-json-socket) re-dials the daemon locally. The HTTP client's identity is forwarded so per-caller authorization still applies, but restrict access to %s appropriately", jsonSocket)
			if err := p.startJSONGateway(jsonListener, daemonAddr); err != nil {
				log.Fatalf("failed to start daemon JSON server: %v", err)
			}
		} else {
			log.Debug("daemon JSON socket disabled")
		}

		log.Printf("started daemon server: %v", daemonListener.address)
		if err := p.serv.Serve(daemonListener.Listener); err != nil {
			log.Errorf("failed to serve daemon requests: %v", err)
		}
	}()
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
	jsonServ := p.jsonServ
	p.jsonServMu.Unlock()
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
