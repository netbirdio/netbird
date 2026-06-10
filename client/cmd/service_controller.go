//go:build !ios && !android

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/kardianos/service"
	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/server"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/util"
)

func (p *program) Start(svc service.Service) error {
	// Start should not block. Do the actual work async.
	log.Info("starting NetBird service") //nolint

	// Collect static system and platform information
	system.UpdateStaticInfoAsync()

	// in any case, even if configuration does not exists we run daemon to serve CLI gRPC API.
	p.serv = grpc.NewServer()

	split := strings.Split(daemonAddr, "://")
	switch split[0] {
	case "unix":
		// cleanup failed close
		stat, err := os.Stat(split[1])
		if err == nil && !stat.IsDir() {
			if err := os.Remove(split[1]); err != nil {
				log.Debugf("remove socket file: %v", err)
			}
		}
	case "tcp":
	default:
		return fmt.Errorf("unsupported daemon address protocol: %v", split[0])
	}

	listen, err := net.Listen(split[0], split[1])
	if err != nil {
		return fmt.Errorf("listen daemon interface: %w", err)
	}
	go func() {
		defer listen.Close()

		if split[0] == "unix" {
			socketPerm := os.FileMode(0666)
			if socketOwner != "" && !strictSocketDisabled {
				socketPerm = 0660
				gid, err := addGroup("netbird")
				if err != nil {
					log.Errorf("failed setting up group (%d): %v", gid, err)
				}
				user, err := user.Lookup(socketOwner)
				if err != nil {
					log.Errorf("lookup user %q: %v", socketOwner, err)
					return
				}
				uid, err := strconv.ParseInt(user.Uid, 10, 64)
				if err != nil {
					log.Errorf("falied to convert uid (%d) to int: %v", uid, err)
					return
				}
				if err = os.Chown(split[1], int(uid), int(gid)); err != nil {
					log.Errorf("failed setting daemon group (%d) on socket: %v", gid, split[1])
					return
				}
			}
			if socketOwner == "" && !strictSocketDisabled {
				// TODO: handle TOFU
			}
			if err := os.Chmod(split[1], socketPerm); err != nil {
				log.Errorf("failed setting daemon permissions: %v", split[1])
				return
			}
		}

		serverInstance := server.New(p.ctx, util.FindFirstLogPath(logFiles), configPath, profilesDisabled, updateSettingsDisabled, captureEnabled, networksDisabled)
		if err := serverInstance.Start(); err != nil {
			log.Fatalf("failed to start daemon: %v", err)
		}
		proto.RegisterDaemonServiceServer(p.serv, serverInstance)

		p.serverInstanceMu.Lock()
		p.serverInstance = serverInstance
		p.serverInstanceMu.Unlock()

		log.Printf("started daemon server: %v", split[1])
		if err := p.serv.Serve(listen); err != nil {
			log.Errorf("failed to serve daemon requests: %v", err)
		}
	}()
	return nil
}

// addGroup creates a system group if it doesn't already exist and returns the gid.
// Must run as root.
func addGroup(name string) (int, error) {
	if group, err := user.LookupGroup(name); err == nil {
		gid, err := strconv.ParseInt(group.Gid, 10, 64)
		return int(gid), err
	} else if _, ok := err.(user.UnknownGroupError); !ok {
		return -1, fmt.Errorf("lookup group %q: %w", name, err)
	}

	groupadd, err := exec.LookPath("groupadd")
	if err != nil {
		// Fallback for Alpine/BusyBox systems.
		if groupadd, err = exec.LookPath("addgroup"); err != nil {
			return -1, errors.New("neither groupadd nor addgroup found")
		}
	}

	// Use --system for a service/daemon group (no login, low GID).
	out, err := exec.Command(groupadd, "--system", name).CombinedOutput()
	if err != nil {
		return -1, fmt.Errorf("create group %q: %w: %s", name, err, out)
	}
	if group, err := user.LookupGroup(name); err == nil {
		gid, err := strconv.ParseInt(group.Gid, 10, 64)
		return int(gid), err
	}
	return -1, fmt.Errorf("lookup group %q: %w", name, err)
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
