//go:build windows || (darwin && !ios)

package cmd

import (
	"fmt"
	"net"
	"net/netip"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	vncserver "github.com/netbirdio/netbird/client/vnc/server"
)

var vncAgentSocket string

func init() {
	vncAgentCmd.Flags().StringVar(&vncAgentSocket, "socket", "", "Unix-domain socket path the agent listens on (required)")
	rootCmd.AddCommand(vncAgentCmd)
}

// vncAgentCmd runs a VNC server inside the user's interactive session,
// listening on a Unix-domain socket. The NetBird service spawns it: on
// Windows via CreateProcessAsUser into the console session, on macOS via
// launchctl asuser into the Aqua session.
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

		token := os.Getenv("NB_VNC_AGENT_TOKEN")
		if token == "" {
			return fmt.Errorf("NB_VNC_AGENT_TOKEN not set; agent requires a token from the service")
		}
		// Purge the token from env so it doesn't leak via /proc/<pid>/environ.
		if err := os.Unsetenv("NB_VNC_AGENT_TOKEN"); err != nil {
			log.Debugf("unset NB_VNC_AGENT_TOKEN: %v", err)
		}

		if err := os.Remove(vncAgentSocket); err != nil && !os.IsNotExist(err) {
			log.Debugf("remove stale socket %s: %v", vncAgentSocket, err)
		}
		ln, err := net.Listen("unix", vncAgentSocket)
		if err != nil {
			return fmt.Errorf("listen on %s: %w", vncAgentSocket, err)
		}
		if err := os.Chmod(vncAgentSocket, 0o600); err != nil {
			log.Debugf("chmod %s: %v", vncAgentSocket, err)
		}

		capturer, injector, err := newAgentResources()
		if err != nil {
			_ = ln.Close()
			return err
		}
		srv := vncserver.New(vncserver.Config{
			Capturer:      capturer,
			Injector:      injector,
			DisableAuth:   true,
			AgentTokenHex: token,
			Listener:      ln,
		})

		if err := srv.Start(cmd.Context(), netip.AddrPort{}, netip.Prefix{}); err != nil {
			return fmt.Errorf("start vnc server: %w", err)
		}
		log.Infof("vnc-agent listening on %s, ready", vncAgentSocket)

		<-cmd.Context().Done()
		log.Info("vnc-agent context cancelled, shutting down")
		return srv.Stop()
	},
	SilenceUsage: true,
}
