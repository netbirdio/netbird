package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
	rdpclient "github.com/netbirdio/netbird/client/rdp/client"
	rdpserver "github.com/netbirdio/netbird/client/rdp/server"
	nbssh "github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/util"
)

const (
	serverRDPAllowedFlag = "allow-server-rdp"
)

var (
	rdpUsername       string
	rdpHost          string
	rdpNoBrowser     bool
	rdpNoCache       bool
	serverRDPAllowed bool
)

func init() {
	rdpCmd.PersistentFlags().StringVarP(&rdpUsername, "user", "u", "", "Windows username on remote peer")
	rdpCmd.PersistentFlags().BoolVar(&rdpNoBrowser, noBrowserFlag, false, noBrowserDesc)
	rdpCmd.PersistentFlags().BoolVar(&rdpNoCache, "no-cache", false, "Skip cached JWT token and force fresh authentication")

	upCmd.PersistentFlags().BoolVar(&serverRDPAllowed, serverRDPAllowedFlag, false, "Allow RDP passthrough on peer (passwordless RDP via credential provider)")
}

var rdpCmd = &cobra.Command{
	Use:   "rdp [flags] [user@]host",
	Short: "Connect to a NetBird peer via RDP (passwordless)",
	Long: `Connect to a NetBird peer using Remote Desktop Protocol with token-based
passwordless authentication. The target peer must have RDP passthrough enabled.

This command:
  1. Obtains a JWT token via OIDC authentication
  2. Sends the token to the target peer's sideband auth service
  3. If authorized, launches mstsc.exe to connect

Examples:
  netbird rdp peer-hostname
  netbird rdp administrator@peer-hostname
  netbird rdp --user admin peer-hostname`,
	Args: cobra.MinimumNArgs(1),
	RunE: rdpFn,
}

func rdpFn(cmd *cobra.Command, args []string) error {
	SetFlagsFromEnvVars(rootCmd)
	SetFlagsFromEnvVars(cmd)
	cmd.SetOut(cmd.OutOrStdout())

	logOutput := "console"
	if firstLogFile := util.FindFirstLogPath(logFiles); firstLogFile != "" && firstLogFile != defaultLogFile {
		logOutput = firstLogFile
	}
	if err := util.InitLog(logLevel, logOutput); err != nil {
		return fmt.Errorf("init log: %w", err)
	}

	// Parse user@host
	if err := parseRDPHostArg(args[0]); err != nil {
		return err
	}

	ctx := internal.CtxInitState(cmd.Context())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	rdpCtx, cancel := context.WithCancel(ctx)

	errCh := make(chan error, 1)
	go func() {
		if err := runRDP(rdpCtx, cmd); err != nil {
			errCh <- err
		}
		cancel()
	}()

	select {
	case <-sig:
		cancel()
		<-rdpCtx.Done()
		return nil
	case err := <-errCh:
		return err
	case <-rdpCtx.Done():
	}

	return nil
}

func parseRDPHostArg(arg string) error {
	if strings.Contains(arg, "@") {
		parts := strings.SplitN(arg, "@", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return errors.New("invalid user@host format")
		}
		if rdpUsername == "" {
			rdpUsername = parts[0]
		}
		rdpHost = parts[1]
	} else {
		rdpHost = arg
	}

	if rdpUsername == "" {
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
			rdpUsername = sudoUser
		} else if currentUser, err := user.Current(); err == nil {
			rdpUsername = currentUser.Username
		} else {
			rdpUsername = "Administrator"
		}
	}

	return nil
}

func runRDP(ctx context.Context, cmd *cobra.Command) error {
	// Connect to daemon
	grpcAddr := strings.TrimPrefix(daemonAddr, "tcp://")
	grpcConn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("connect to daemon: %w", err)
	}
	defer func() { _ = grpcConn.Close() }()

	daemonClient := proto.NewDaemonServiceClient(grpcConn)

	// Resolve peer IP
	peerIP, err := resolvePeerIP(ctx, daemonClient, rdpHost)
	if err != nil {
		return fmt.Errorf("resolve peer %s: %w", rdpHost, err)
	}

	cmd.Printf("Connecting to %s@%s (%s)...\n", rdpUsername, rdpHost, peerIP)

	// Obtain JWT token
	hint := profilemanager.GetLoginHint()
	var browserOpener func(string) error
	if !rdpNoBrowser {
		browserOpener = util.OpenBrowser
	}

	jwtToken, err := nbssh.RequestJWTToken(ctx, daemonClient, nil, cmd.ErrOrStderr(), !rdpNoCache, hint, browserOpener)
	if err != nil {
		return fmt.Errorf("JWT authentication: %w", err)
	}

	log.Debug("JWT authentication successful")
	cmd.Println("Authenticated. Requesting RDP access...")

	// Generate nonce for replay protection
	nonce, err := rdpserver.GenerateNonce()
	if err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	// Send sideband auth request
	authClient := rdpclient.New()
	authAddr := net.JoinHostPort(peerIP, fmt.Sprintf("%d", rdpserver.DefaultRDPAuthPort))

	resp, err := authClient.RequestAuth(ctx, authAddr, &rdpserver.AuthRequest{
		JWTToken:      jwtToken,
		RequestedUser: rdpUsername,
		ClientPeerIP:  "", // will be filled by the server from the connection
		Nonce:         nonce,
	})
	if err != nil {
		cmd.Printf("Failed to authorize RDP session with %s\n", rdpHost)
		cmd.Printf("\nTroubleshooting:\n")
		cmd.Printf("  1. Check connectivity: netbird status -d\n")
		cmd.Printf("  2. Verify RDP passthrough is enabled on the target peer\n")
		return fmt.Errorf("sideband auth: %w", err)
	}

	if resp.Status != rdpserver.StatusAuthorized {
		return fmt.Errorf("RDP access denied: %s", resp.Reason)
	}

	cmd.Printf("RDP access authorized (session: %s, user: %s)\n", resp.SessionID, resp.OSUser)
	cmd.Printf("Launching Remote Desktop client...\n")

	// Launch mstsc.exe (platform-specific)
	if err := launchRDPClient(peerIP); err != nil {
		return fmt.Errorf("launch RDP client: %w", err)
	}

	return nil
}

// resolvePeerIP resolves a peer hostname/FQDN to its WireGuard IP address
// by querying the daemon for the current peer status.
func resolvePeerIP(ctx context.Context, client proto.DaemonServiceClient, peerAddress string) (string, error) {
	statusResp, err := client.Status(ctx, &proto.StatusRequest{})
	if err != nil {
		return "", fmt.Errorf("get daemon status: %w", err)
	}

	if statusResp.GetFullStatus() == nil {
		return "", errors.New("daemon returned empty status")
	}

	for _, peer := range statusResp.GetFullStatus().GetPeers() {
		if matchesPeer(peer, peerAddress) {
			ip := peer.GetIP()
			if ip == "" {
				continue
			}
			// Strip CIDR suffix if present
			if idx := strings.Index(ip, "/"); idx != -1 {
				ip = ip[:idx]
			}
			return ip, nil
		}
	}

	// If not found as a peer name, try as a direct IP
	if addr, err := net.ResolveIPAddr("ip", peerAddress); err == nil {
		return addr.String(), nil
	}

	return "", fmt.Errorf("peer %q not found in network", peerAddress)
}

func matchesPeer(peer *proto.PeerState, address string) bool {
	address = strings.ToLower(address)

	if strings.EqualFold(peer.GetFqdn(), address) {
		return true
	}

	// Match against FQDN without trailing dot
	fqdn := strings.TrimSuffix(peer.GetFqdn(), ".")
	if strings.EqualFold(fqdn, address) {
		return true
	}

	// Match against short hostname (first part of FQDN)
	if parts := strings.SplitN(fqdn, ".", 2); len(parts) > 0 {
		if strings.EqualFold(parts[0], address) {
			return true
		}
	}

	// Match against IP
	ip := peer.GetIP()
	if idx := strings.Index(ip, "/"); idx != -1 {
		ip = ip[:idx]
	}
	if ip == address {
		return true
	}

	return false
}
