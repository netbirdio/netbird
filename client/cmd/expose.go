package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/util"
)

var (
	exposePin        string
	exposePassword   string
	exposeUserGroups []string
	exposeDomain     string
	exposeNamePrefix string
	exposeProtocol   string
)

var exposeCmd = &cobra.Command{
	Use:   "expose <port>",
	Short: "Expose a local port via the NetBird reverse proxy",
	Args:  cobra.ExactArgs(1),
	RunE:  exposeFn,
}

func init() {
	exposeCmd.Flags().StringVar(&exposePin, "with-pin", "", "Protect the exposed service with a PIN")
	exposeCmd.Flags().StringVar(&exposePassword, "with-password", "", "Protect the exposed service with a password")
	exposeCmd.Flags().StringSliceVar(&exposeUserGroups, "with-user-groups", nil, "Restrict access to specific user groups")
	exposeCmd.Flags().StringVar(&exposeDomain, "with-custom-domain", "", "Custom domain for the exposed service. Must be configured to your account")
	exposeCmd.Flags().StringVar(&exposeNamePrefix, "with-name-prefix", "", "Prefix for the generated service name")
	exposeCmd.Flags().StringVar(&exposeProtocol, "protocol", "http", "Protocol to use (only 'http' is supported)")
}

func exposeFn(cmd *cobra.Command, args []string) error {
	SetFlagsFromEnvVars(rootCmd)

	if err := util.InitLog(logLevel, util.LogConsole); err != nil {
		log.Errorf("failed initializing log %v", err)
		return err
	}

	port, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid port number: %s", args[0])
	}
	if port == 0 || port > 65535 {
		return fmt.Errorf("invalid port number: must be between 1 and 65535")
	}

	if exposeProtocol != "http" {
		return fmt.Errorf("unsupported protocol %q: only 'http' is supported", exposeProtocol)
	}

	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	conn, err := DialClientGRPCServer(ctx, daemonAddr)
	if err != nil {
		return fmt.Errorf("connect to daemon: %w", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Debugf("failed to close daemon connection: %v", err)
		}
	}()

	client := proto.NewDaemonServiceClient(conn)

	req := &proto.ExposeServiceRequest{
		Port:       uint32(port),
		Protocol:   proto.ExposeProtocol_EXPOSE_HTTP,
		Pin:        exposePin,
		Password:   exposePassword,
		UserGroups: exposeUserGroups,
		Domain:     exposeDomain,
		NamePrefix: exposeNamePrefix,
	}

	stream, err := client.ExposeService(ctx, req)
	if err != nil {
		return fmt.Errorf("expose service: %w", err)
	}

	event, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("receive expose event: %w", err)
	}

	switch e := event.Event.(type) {
	case *proto.ExposeServiceEvent_Ready:
		cmd.Println("Service exposed successfully!")
		cmd.Printf("  Name:     %s\n", e.Ready.ServiceName)
		cmd.Printf("  URL:      %s\n", e.Ready.ServiceUrl)
		cmd.Printf("  Domain:   %s\n", e.Ready.Domain)
		cmd.Printf("  Protocol: %s\n", exposeProtocol)
		cmd.Printf("  Port:     %d\n", port)
		cmd.Println()
		cmd.Println("Press Ctrl+C to stop exposing.")
	case *proto.ExposeServiceEvent_Error:
		return fmt.Errorf("expose failed: %s", e.Error.Message)
	case *proto.ExposeServiceEvent_Stopped:
		return fmt.Errorf("expose stopped: %s", e.Stopped.Reason)
	default:
		return fmt.Errorf("unexpected expose event: %T", event.Event)
	}

	for {
		event, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				cmd.Println("\nService stopped.")
				return nil
			}
			return err
		}

		switch e := event.Event.(type) {
		case *proto.ExposeServiceEvent_Stopped:
			cmd.Printf("\nService stopped: %s\n", e.Stopped.Reason)
			return nil
		case *proto.ExposeServiceEvent_Error:
			return fmt.Errorf("expose error: %s", e.Error.Message)
		default:
			log.Debugf("unexpected expose event: %T", event.Event)
		}
	}
}
