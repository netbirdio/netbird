package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/util"
)

var pinRegexp = regexp.MustCompile(`^\d{6}$`)

var (
	exposePin        string
	exposePassword   string
	exposeUserGroups []string
	exposeDomain     string
	exposeNamePrefix string
	exposeProtocol   string
)

var exposeCmd = &cobra.Command{
	Use:     "expose <port>",
	Short:   "Expose a local port via the NetBird reverse proxy",
	Args:    cobra.ExactArgs(1),
	Example: "netbird expose --with-password safe-pass 8080",
	RunE:    exposeFn,
}

func init() {
	exposeCmd.Flags().StringVar(&exposePin, "with-pin", "", "Protect the exposed service with a 6-digit PIN (e.g. --with-pin 123456)")
	exposeCmd.Flags().StringVar(&exposePassword, "with-password", "", "Protect the exposed service with a password (e.g. --with-password my-secret)")
	exposeCmd.Flags().StringSliceVar(&exposeUserGroups, "with-user-groups", nil, "Restrict access to specific user groups with SSO (e.g. --with-user-groups devops,Backend)")
	exposeCmd.Flags().StringVar(&exposeDomain, "with-custom-domain", "", "Custom domain for the exposed service, must be configured to your account (e.g. --with-custom-domain myapp.example.com)")
	exposeCmd.Flags().StringVar(&exposeNamePrefix, "with-name-prefix", "", "Prefix for the generated service name (e.g. --with-name-prefix my-app)")
	exposeCmd.Flags().StringVar(&exposeProtocol, "protocol", "http", "Protocol to use, http/https is supported (e.g. --protocol http)")
}

func validateExposeFlags(cmd *cobra.Command, portStr string) (uint64, error) {
	port, err := strconv.ParseUint(portStr, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid port number: %s", portStr)
	}
	if port == 0 || port > 65535 {
		return 0, fmt.Errorf("invalid port number: must be between 1 and 65535")
	}

	if !isProtocolValid(exposeProtocol) {
		return 0, fmt.Errorf("unsupported protocol %q: only 'http' or 'https' are supported", exposeProtocol)
	}

	if exposePin != "" && !pinRegexp.MatchString(exposePin) {
		return 0, fmt.Errorf("invalid pin: must be exactly 6 digits")
	}

	if cmd.Flags().Changed("with-password") && exposePassword == "" {
		return 0, fmt.Errorf("password cannot be empty")
	}

	if cmd.Flags().Changed("with-user-groups") && len(exposeUserGroups) == 0 {
		return 0, fmt.Errorf("user groups cannot be empty")
	}

	return port, nil
}

func isProtocolValid(exposeProtocol string) bool {
	return strings.ToLower(exposeProtocol) == "http" || strings.ToLower(exposeProtocol) == "https"
}

func exposeFn(cmd *cobra.Command, args []string) error {
	SetFlagsFromEnvVars(rootCmd)

	if err := util.InitLog(logLevel, util.LogConsole); err != nil {
		log.Errorf("failed initializing log %v", err)
		return err
	}

	cmd.Root().SilenceUsage = false

	port, err := validateExposeFlags(cmd, args[0])
	if err != nil {
		return err
	}

	cmd.Root().SilenceUsage = true

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

	protocol, err := toExposeProtocol(exposeProtocol)
	if err != nil {
		return err
	}

	stream, err := client.ExposeService(ctx, &proto.ExposeServiceRequest{
		Port:       uint32(port),
		Protocol:   protocol,
		Pin:        exposePin,
		Password:   exposePassword,
		UserGroups: exposeUserGroups,
		Domain:     exposeDomain,
		NamePrefix: exposeNamePrefix,
	})
	if err != nil {
		return fmt.Errorf("expose service: %w", err)
	}

	if err := handleExposeReady(cmd, stream, port); err != nil {
		return err
	}

	return waitForExposeEvents(cmd, ctx, stream)
}

func toExposeProtocol(exposeProtocol string) (proto.ExposeProtocol, error) {
	switch strings.ToLower(exposeProtocol) {
	case "http":
		return proto.ExposeProtocol_EXPOSE_HTTP, nil
	case "https":
		return proto.ExposeProtocol_EXPOSE_HTTPS, nil
	default:
		return 0, fmt.Errorf("unsupported protocol %q: only 'http' or 'https' are supported", exposeProtocol)
	}
}

func handleExposeReady(cmd *cobra.Command, stream proto.DaemonService_ExposeServiceClient, port uint64) error {
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
		return nil
	default:
		return fmt.Errorf("unexpected expose event: %T", event.Event)
	}
}

func waitForExposeEvents(cmd *cobra.Command, ctx context.Context, stream proto.DaemonService_ExposeServiceClient) error {
	for {
		_, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				cmd.Println("\nService stopped.")
				//nolint:nilerr
				return nil
			}
			if errors.Is(err, io.EOF) {
				return fmt.Errorf("connection to daemon closed unexpectedly")
			}
			return fmt.Errorf("stream error: %w", err)
		}
	}
}
