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
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/expose"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/util"
)

var pinRegexp = regexp.MustCompile(`^\d{6}$`)

var (
	exposePin          string
	exposePassword     string
	exposeUserGroups   []string
	exposeDomain       string
	exposeNamePrefix   string
	exposeProtocol     string
	exposeExternalPort uint16
)

var exposeCmd = &cobra.Command{
	Use:   "expose <port>",
	Short: "Expose a local port via the NetBird reverse proxy",
	Args:  cobra.ExactArgs(1),
	Example: `  netbird expose --with-password safe-pass 8080
  netbird expose --protocol tcp 5432
  netbird expose --protocol tcp --with-external-port 5433 5432
  netbird expose --protocol tls --with-custom-domain tls.example.com 4443`,
	RunE: exposeFn,
}

func init() {
	exposeCmd.Flags().StringVar(&exposePin, "with-pin", "", "Protect the exposed service with a 6-digit PIN (e.g. --with-pin 123456)")
	exposeCmd.Flags().StringVar(&exposePassword, "with-password", "", "Protect the exposed service with a password (e.g. --with-password my-secret)")
	exposeCmd.Flags().StringSliceVar(&exposeUserGroups, "with-user-groups", nil, "Restrict access to specific user groups with SSO (e.g. --with-user-groups devops,Backend)")
	exposeCmd.Flags().StringVar(&exposeDomain, "with-custom-domain", "", "Custom domain for the exposed service, must be configured to your account (e.g. --with-custom-domain myapp.example.com)")
	exposeCmd.Flags().StringVar(&exposeNamePrefix, "with-name-prefix", "", "Prefix for the generated service name (e.g. --with-name-prefix my-app)")
	exposeCmd.Flags().StringVar(&exposeProtocol, "protocol", "http", "Protocol to use: http, https, tcp, udp, or tls (e.g. --protocol tcp)")
	exposeCmd.Flags().Uint16Var(&exposeExternalPort, "with-external-port", 0, "Public-facing external port on the proxy cluster (defaults to the target port for L4)")
}

// isClusterProtocol returns true for L4/TLS protocols that reject HTTP-style auth flags.
func isClusterProtocol(protocol string) bool {
	switch strings.ToLower(protocol) {
	case "tcp", "udp", "tls":
		return true
	default:
		return false
	}
}

// isPortBasedProtocol returns true for pure port-based protocols (TCP/UDP)
// where domain display doesn't apply. TLS uses SNI so it has a domain.
func isPortBasedProtocol(protocol string) bool {
	switch strings.ToLower(protocol) {
	case "tcp", "udp":
		return true
	default:
		return false
	}
}

// extractPort returns the port portion of a URL like "tcp://host:12345", or
// falls back to the given default formatted as a string.
func extractPort(serviceURL string, fallback uint16) string {
	u := serviceURL
	if idx := strings.Index(u, "://"); idx != -1 {
		u = u[idx+3:]
	}
	if i := strings.LastIndex(u, ":"); i != -1 {
		if p := u[i+1:]; p != "" {
			return p
		}
	}
	return strconv.FormatUint(uint64(fallback), 10)
}

// resolveExternalPort returns the effective external port, defaulting to the target port.
func resolveExternalPort(targetPort uint64) uint16 {
	if exposeExternalPort != 0 {
		return exposeExternalPort
	}
	return uint16(targetPort)
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
		return 0, fmt.Errorf("unsupported protocol %q: must be http, https, tcp, udp, or tls", exposeProtocol)
	}

	if isClusterProtocol(exposeProtocol) {
		if exposePin != "" || exposePassword != "" || len(exposeUserGroups) > 0 {
			return 0, fmt.Errorf("auth flags (--with-pin, --with-password, --with-user-groups) are not supported for %s protocol", exposeProtocol)
		}
	} else if cmd.Flags().Changed("with-external-port") {
		return 0, fmt.Errorf("--with-external-port is not supported for %s protocol", exposeProtocol)
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
	switch strings.ToLower(exposeProtocol) {
	case "http", "https", "tcp", "udp", "tls":
		return true
	default:
		return false
	}
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

	req := &proto.ExposeServiceRequest{
		Port:       uint32(port),
		Protocol:   protocol,
		Pin:        exposePin,
		Password:   exposePassword,
		UserGroups: exposeUserGroups,
		Domain:     exposeDomain,
		NamePrefix: exposeNamePrefix,
	}
	if isClusterProtocol(exposeProtocol) {
		req.ListenPort = uint32(resolveExternalPort(port))
	}

	stream, err := client.ExposeService(ctx, req)
	if err != nil {
		return fmt.Errorf("expose service: %v", status.Convert(err).Message())
	}

	if err := handleExposeReady(cmd, stream, port); err != nil {
		return err
	}

	return waitForExposeEvents(cmd, ctx, stream)
}

func toExposeProtocol(exposeProtocol string) (proto.ExposeProtocol, error) {
	p, err := expose.ParseProtocolType(exposeProtocol)
	if err != nil {
		return 0, fmt.Errorf("invalid protocol: %w", err)
	}

	switch p {
	case expose.ProtocolHTTP:
		return proto.ExposeProtocol_EXPOSE_HTTP, nil
	case expose.ProtocolHTTPS:
		return proto.ExposeProtocol_EXPOSE_HTTPS, nil
	case expose.ProtocolTCP:
		return proto.ExposeProtocol_EXPOSE_TCP, nil
	case expose.ProtocolUDP:
		return proto.ExposeProtocol_EXPOSE_UDP, nil
	case expose.ProtocolTLS:
		return proto.ExposeProtocol_EXPOSE_TLS, nil
	default:
		return 0, fmt.Errorf("unhandled protocol type: %d", p)
	}
}

func handleExposeReady(cmd *cobra.Command, stream proto.DaemonService_ExposeServiceClient, port uint64) error {
	event, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("receive expose event: %v", status.Convert(err).Message())
	}

	ready, ok := event.Event.(*proto.ExposeServiceEvent_Ready)
	if !ok {
		return fmt.Errorf("unexpected expose event: %T", event.Event)
	}
	printExposeReady(cmd, ready.Ready, port)
	return nil
}

func printExposeReady(cmd *cobra.Command, r *proto.ExposeServiceReady, port uint64) {
	cmd.Println("Service exposed successfully!")
	cmd.Printf("  Name:     %s\n", r.ServiceName)
	if r.ServiceUrl != "" {
		cmd.Printf("  URL:      %s\n", r.ServiceUrl)
	}
	if r.Domain != "" && !isPortBasedProtocol(exposeProtocol) {
		cmd.Printf("  Domain:   %s\n", r.Domain)
	}
	cmd.Printf("  Protocol: %s\n", exposeProtocol)
	cmd.Printf("  Internal: %d\n", port)
	if isClusterProtocol(exposeProtocol) {
		cmd.Printf("  External: %s\n", extractPort(r.ServiceUrl, resolveExternalPort(port)))
	}
	if r.PortAutoAssigned && exposeExternalPort != 0 {
		cmd.Printf("\n  Note: requested port %d was reassigned\n", exposeExternalPort)
	}
	cmd.Println()
	cmd.Println("Press Ctrl+C to stop exposing.")
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
