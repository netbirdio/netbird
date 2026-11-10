//go:build windows || (darwin && !ios)

package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	vncserver "github.com/netbirdio/netbird/client/vnc/server"
)

var (
	vncAgentSocket     string
	vncAgentTargetUID  uint32
	vncAgentTokenStdin bool
)

// maxAgentTokenLine bounds the token read from stdin. The token is a short hex
// string; anything longer is not one.
const maxAgentTokenLine = 1024

func init() {
	vncAgentCmd.Flags().StringVar(&vncAgentSocket, "socket", "", "socket the agent listens on: a Unix-domain socket path on darwin, a named pipe path on Windows (required)")
	vncAgentCmd.Flags().Uint32Var(&vncAgentTargetUID, "target-uid", 0, "uid the agent drops privileges to before listening (darwin only; required there, and must not be 0)")
	// Must match agentTokenStdinFlag in client/vnc/server/agent_ipc.go.
	vncAgentCmd.Flags().BoolVar(&vncAgentTokenStdin, "token-stdin", false, "read the per-spawn token from stdin instead of the environment")
	rootCmd.AddCommand(vncAgentCmd)
}

// vncAgentCmd runs a VNC server inside the user's interactive session,
// listening on a Unix-domain socket (a named pipe on Windows). The NetBird
// service spawns it: on Windows via CreateProcessAsUser into the console
// session, on macOS via launchctl asuser into the Aqua session.
var vncAgentCmd = &cobra.Command{
	Use:    "vnc-agent",
	Short:  "Run VNC capture agent (internal, spawned by service)",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		log.SetReportCaller(true)
		log.SetFormatter(&log.JSONFormatter{})
		log.SetOutput(os.Stderr)

		if vncAgentSocket == "" {
			return fmt.Errorf("--socket is required")
		}

		token, err := readAgentToken()
		if err != nil {
			return err
		}

		// Drop root privileges to the target console user BEFORE creating
		// the listening socket: keeps a post-auth bug in the encoder /
		// input / capture paths confined to the user's own privileges
		// rather than escalating to host root, and makes the daemon's
		// LOCAL_PEERCRED check see the right uid. No-op on Windows, where
		// both processes run as SYSTEM.
		//
		// Called unconditionally: a missing or zero --target-uid is exactly
		// the case the Darwin implementation refuses, and skipping the call
		// for it would leave the agent running as root instead.
		if err := dropAgentPrivileges(vncAgentTargetUID); err != nil {
			return fmt.Errorf("drop privileges to uid %d: %w", vncAgentTargetUID, err)
		}

		// Before the socket exists, not after: the daemon treats the socket
		// appearing as "this agent is ready to serve". Building the capturer
		// and injector can take a while and can fail — on macOS it raises the
		// Screen Recording prompt and waits on the user — so binding first
		// publishes an agent that is not serving yet, and the first connection
		// stalls or fails against it.
		capturer, injector, err := newAgentResources()
		if err != nil {
			return err
		}

		ln, err := vncserver.ListenAgentSocket(vncAgentSocket)
		if err != nil {
			return fmt.Errorf("listen on %s: %w", vncAgentSocket, err)
		}

		ctx := cmd.Context()

		srv := vncserver.New(vncserver.Config{
			Capturer:      capturer,
			Injector:      injector,
			DisableAuth:   true,
			AgentTokenHex: token,
			Listener:      ln,
		})

		if err := srv.Start(ctx, netip.AddrPort{}, netip.Prefix{}); err != nil {
			return fmt.Errorf("start vnc server: %w", err)
		}
		log.Infof("vnc-agent listening on %s, ready", vncAgentSocket)

		<-ctx.Done()
		log.Info("vnc-agent context cancelled, shutting down")
		return srv.Stop()
	},
	SilenceUsage: true,
}

// readAgentToken returns the per-spawn token the service handed over, from
// stdin when --token-stdin is set and from the environment otherwise. Missing
// or empty is an error: the agent must never serve without one.
func readAgentToken() (string, error) {
	if vncAgentTokenStdin {
		line, err := bufio.NewReader(io.LimitReader(os.Stdin, maxAgentTokenLine)).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("read agent token from stdin: %w", err)
		}
		_ = os.Stdin.Close()
		token := strings.TrimSpace(line)
		if token == "" {
			return "", fmt.Errorf("no agent token on stdin; agent requires a token from the service")
		}
		return token, nil
	}

	token := os.Getenv("NB_VNC_AGENT_TOKEN")
	if token == "" {
		return "", fmt.Errorf("NB_VNC_AGENT_TOKEN not set; agent requires a token from the service")
	}
	// Purge the token from env so later reads in this process do not see it.
	if err := os.Unsetenv("NB_VNC_AGENT_TOKEN"); err != nil {
		log.Debugf("unset NB_VNC_AGENT_TOKEN: %v", err)
	}
	return token, nil
}
