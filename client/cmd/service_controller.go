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
	"sync"
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

		srvListener := listen
		if split[0] == "unix" {
			owner := effectiveSocketOwner()
			switch {
			case strictSocketDisabled:
				// Opt-out (root-only, via service.json): leave it world-writable.
				if err := os.Chmod(split[1], 0666); err != nil {
					log.Errorf("failed setting daemon permissions: %v", split[1])
					return
				}
			case owner != "":
				// Seeded owner (flag, MDM, or persisted TOFU result): restrict
				// before serving so there is no open window.
				u, err := user.Lookup(owner)
				if err != nil {
					log.Errorf("lookup socket owner %q: %v", owner, err)
					return
				}
				uid, err := strconv.Atoi(u.Uid)
				if err != nil {
					log.Errorf("parse uid %q for %q: %v", u.Uid, owner, err)
					return
				}
				if err := restrictSocket(split[1], uid); err != nil {
					log.Errorf("restrict socket to %q: %v", owner, err)
					return
				}
			default:
				// Trust-on-first-use: open the socket now; tofuListener locks it
				// to the first caller's uid on the first connection.
				if err := os.Chmod(split[1], 0666); err != nil {
					log.Errorf("failed setting daemon permissions: %v", split[1])
					return
				}
				srvListener = &tofuListener{Listener: listen, path: split[1], owner: -1}
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
		if err := p.serv.Serve(srvListener); err != nil {
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

// restrictSocket locks the unix socket down to the owner uid plus the netbird
// group (0660). If the group cannot be created or applied, it fails closed to
// owner-only 0600 — it never leaves the socket world-writable.
func restrictSocket(path string, uid int) error {
	gid, err := addGroup("netbird")
	if err != nil {
		log.Errorf("create netbird group, failing closed to owner-only 0600: %v", err)
		return chownChmod(path, uid, -1, 0600)
	}
	if err := chownChmod(path, uid, gid, 0660); err != nil {
		log.Errorf("apply netbird group to socket, failing closed to owner-only 0600: %v", err)
		return chownChmod(path, uid, -1, 0600)
	}
	return nil
}

// chownChmod sets ownership and mode on the socket. A gid of -1 leaves the
// group unchanged.
func chownChmod(path string, uid, gid int, mode os.FileMode) error {
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown socket %s: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod socket %s: %w", path, err)
	}
	return nil
}

// tofuListener implements trust-on-first-use for the daemon control socket.
// The socket starts world-writable; the first caller's uid (read via the
// platform peer-credential mechanism) becomes the owner. On that first
// connection the socket is restricted (see restrictSocket) and the owner is
// persisted so the open window never reopens on later starts. Connections that
// raced in during the open window and are neither the owner nor root are
// dropped. Changing the socket mode does not disturb the already-open
// connection, so the first caller's request is served normally.
type tofuListener struct {
	net.Listener
	path  string
	mu    sync.Mutex
	owner int // -1 until claimed
}

func (l *tofuListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		uid, err := peerUID(c)
		if err != nil {
			log.Errorf("read peer credentials, dropping connection: %v", err)
			_ = c.Close()
			continue
		}

		l.mu.Lock()
		if l.owner == -1 {
			if err := restrictSocket(l.path, uid); err != nil {
				l.mu.Unlock()
				_ = c.Close()
				// Refuse to serve on a socket we could not lock down.
				return nil, fmt.Errorf("restrict socket on first connection: %w", err)
			}
			l.owner = uid
			persistSocketOwner(uid)
			log.Infof("control socket restricted to first caller (uid %d)", uid)
			l.mu.Unlock()
			return c, nil
		}
		owner := l.owner
		l.mu.Unlock()

		// New connects are already gated by the 0660 perms set above; this only
		// drops anything that slipped in during the brief open window.
		if uid != owner && uid != 0 {
			log.Warnf("dropping non-owner connection (uid %d) during socket bootstrap", uid)
			_ = c.Close()
			continue
		}
		return c, nil
	}
}

// effectiveSocketOwner returns the configured socket owner: the --socket-owner
// flag when set, otherwise the owner persisted by a previous TOFU migration.
func effectiveSocketOwner() string {
	if socketOwner != "" {
		return socketOwner
	}
	params, err := loadServiceParams()
	if err != nil {
		log.Errorf("load service params for socket owner: %v", err)
		return ""
	}
	if params != nil {
		return params.SocketOwner
	}
	return ""
}

// persistSocketOwner records the TOFU-selected owner (by username) so the next
// daemon start restricts the socket immediately, with no open window.
func persistSocketOwner(uid int) {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		log.Errorf("resolve uid %d to username for persistence: %v", uid, err)
		return
	}
	params, err := loadServiceParams()
	if err != nil {
		log.Errorf("load service params to persist socket owner: %v", err)
		return
	}
	if params == nil {
		params = currentServiceParams()
	}
	params.SocketOwner = u.Username
	if err := saveServiceParams(params); err != nil {
		log.Errorf("persist socket owner: %v", err)
	}
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
