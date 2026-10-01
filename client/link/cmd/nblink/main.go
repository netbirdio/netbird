// Command nblink forwards local listeners into a NetBird network from an
// unprivileged process.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/link"
	"github.com/netbirdio/netbird/util"
	"github.com/netbirdio/netbird/version"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "nblink: %v\n", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nblink",
		Short: "Forward local ports into a NetBird network",
		Long: "nblink runs a NetBird peer in userspace and forwards local listeners\n" +
			"into the network. It needs no TUN device and no elevated privileges,\n" +
			"so it runs on managed machines and in rootless containers.\n\n" +
			"Every flag can also be set through an NB_-prefixed environment variable\n" +
			"of the same name, which is how the container image is configured.",
		Example: "  nblink --forward 'http://8080=https://grafana.internal'\n" +
			"  nblink --forward 'http://127.0.0.1:8080=https://grafana.internal' --setup-key file:/run/secrets/key",
		Version: version.NetbirdVersion(),
		// main prints the error, so cobra must not print it a second time.
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	raw := link.BindFlags(cmd)

	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		link.SetFlagsFromEnvVars(cmd)

		cfg, err := raw.Resolve()
		if err != nil {
			return err
		}

		if err := util.InitLog(cfg.LogLevel, util.LogConsole); err != nil {
			return fmt.Errorf("init log: %w", err)
		}

		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		return link.Run(ctx, cfg)
	}

	return cmd
}
