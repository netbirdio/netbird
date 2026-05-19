//go:build windows || (darwin && !ios)

package cmd

import (
	"fmt"
	"net/netip"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	vncserver "github.com/netbirdio/netbird/client/vnc/server"
)

var vncAgentPort uint16

func init() {
	vncAgentCmd.Flags().Uint16Var(&vncAgentPort, "port", 15900, "Port for the VNC agent to listen on")
	rootCmd.AddCommand(vncAgentCmd)
}

// vncAgentCmd runs a VNC server inside the user's interactive session,
// listening on localhost. The NetBird service spawns it: on Windows via
// CreateProcessAsUser into the console session, on macOS via
// launchctl asuser into the Aqua session.
var vncAgentCmd = &cobra.Command{
	Use:    "vnc-agent",
	Short:  "Run VNC capture agent (internal, spawned by service)",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		log.SetReportCaller(true)
		log.SetFormatter(&log.JSONFormatter{})
		log.SetOutput(os.Stderr)

		log.Infof("VNC agent starting on 127.0.0.1:%d", vncAgentPort)

		token := os.Getenv("NB_VNC_AGENT_TOKEN")
		if token == "" {
			return fmt.Errorf("NB_VNC_AGENT_TOKEN not set; agent requires a token from the service")
		}

		capturer, injector, err := newAgentResources()
		if err != nil {
			return err
		}
		srv := vncserver.New(capturer, injector)
		srv.SetDisableAuth(true)
		srv.SetAgentToken(token)

		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), vncAgentPort)
		loopback := netip.PrefixFrom(netip.AddrFrom4([4]byte{127, 0, 0, 0}), 8)
		if err := srv.Start(cmd.Context(), addr, loopback); err != nil {
			return fmt.Errorf("start vnc server: %w", err)
		}
		log.Infof("vnc-agent listening on 127.0.0.1:%d, ready", vncAgentPort)

		<-cmd.Context().Done()
		log.Info("vnc-agent context cancelled, shutting down")
		return srv.Stop()
	},
	SilenceUsage: true,
}
