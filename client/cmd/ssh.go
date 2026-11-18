package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/netbirdio/netbird/client/internal"
	sshclient "github.com/netbirdio/netbird/client/ssh/client"
	"github.com/netbirdio/netbird/client/ssh/detection"
	sshproxy "github.com/netbirdio/netbird/client/ssh/proxy"
	sshserver "github.com/netbirdio/netbird/client/ssh/server"
	"github.com/netbirdio/netbird/util"
)

const (
	sshUsernameDesc      = "SSH username"
	sshLoginFlag         = "login"
	sshLoginDeprecation  = "use --user instead"
	hostArgumentRequired = "host argument required"

	serverSSHAllowedFlag           = "allow-server-ssh"
	enableSSHRootFlag              = "enable-ssh-root"
	enableSSHSFTPFlag              = "enable-ssh-sftp"
	enableSSHLocalPortForwardFlag  = "enable-ssh-local-port-forwarding"
	enableSSHRemotePortForwardFlag = "enable-ssh-remote-port-forwarding"
	disableSSHAuthFlag             = "disable-ssh-auth"
	sshJWTCacheTTLFlag             = "ssh-jwt-cache-ttl"
)

var (
	port                  int
	username              string
	host                  string
	hostUser              string
	command               string
	localForwards         []string
	remoteForwards        []string
	strictHostKeyChecking bool
	knownHostsFile        string
	identityFile          string
	skipCachedToken       bool
	requestPTY            bool
	sshNoBrowser          bool
	sshLogin              string
)

var (
	serverSSHAllowed           bool
	enableSSHRoot              bool
	enableSSHSFTP              bool
	enableSSHLocalPortForward  bool
	enableSSHRemotePortForward bool
	disableSSHAuth             bool
	sshJWTCacheTTL             int
)

func init() {
	upCmd.PersistentFlags().BoolVar(&serverSSHAllowed, serverSSHAllowedFlag, false, "Allow SSH server on peer")
	upCmd.PersistentFlags().BoolVar(&enableSSHRoot, enableSSHRootFlag, false, "Enable root login for SSH server")
	upCmd.PersistentFlags().BoolVar(&enableSSHSFTP, enableSSHSFTPFlag, false, "Enable SFTP subsystem for SSH server")
	upCmd.PersistentFlags().BoolVar(&enableSSHLocalPortForward, enableSSHLocalPortForwardFlag, false, "Enable local port forwarding for SSH server")
	upCmd.PersistentFlags().BoolVar(&enableSSHRemotePortForward, enableSSHRemotePortForwardFlag, false, "Enable remote port forwarding for SSH server")
	upCmd.PersistentFlags().BoolVar(&disableSSHAuth, disableSSHAuthFlag, false, "Disable SSH authentication")
	upCmd.PersistentFlags().IntVar(&sshJWTCacheTTL, sshJWTCacheTTLFlag, 0, "SSH JWT token cache TTL in seconds (0=disabled)")

	// Stop at the host so the remote command keeps its own flags.
	sshCmd.Flags().SetInterspersed(false)
	sshCmd.Flags().IntVarP(&port, "port", "p", sshserver.DefaultSSHPort, "Remote SSH port")
	sshCmd.Flags().StringVarP(&username, "user", "u", "", sshUsernameDesc)
	sshCmd.Flags().StringVar(&sshLogin, sshLoginFlag, "", sshUsernameDesc+" (alias for --user)")
	_ = sshCmd.Flags().MarkDeprecated(sshLoginFlag, sshLoginDeprecation)
	sshCmd.Flags().BoolVarP(&requestPTY, "tty", "t", false, "Force pseudo-terminal allocation")
	sshCmd.Flags().BoolVar(&strictHostKeyChecking, "strict-host-key-checking", true, "Enable strict host key checking")
	sshCmd.Flags().StringVarP(&knownHostsFile, "known-hosts", "o", "", "Path to known_hosts file (default: ~/.ssh/known_hosts)")
	sshCmd.Flags().StringVarP(&identityFile, "identity", "i", "", "Path to SSH private key file")
	sshCmd.Flags().BoolVar(&skipCachedToken, "no-cache", false, "Skip cached JWT token and force fresh authentication")
	sshCmd.Flags().BoolVar(&sshNoBrowser, noBrowserFlag, false, noBrowserDesc)
	sshCmd.Flags().StringArrayVarP(&localForwards, "local-forward", "L", nil, "Local port forwarding [bind_address:]port:host:hostport or [bind_address:]port:/path/to/socket. Can be repeated")
	sshCmd.Flags().StringArrayVarP(&remoteForwards, "remote-forward", "R", nil, "Remote port forwarding [bind_address:]port:host:hostport or [bind_address:]port:/path/to/socket. Can be repeated")

	sshCmd.AddCommand(sshSftpCmd)
	sshCmd.AddCommand(sshProxyCmd)
	sshCmd.AddCommand(sshDetectCmd)
}

var sshCmd = &cobra.Command{
	Use:   "ssh [flags] [user@]host [command]",
	Short: "Connect to a NetBird peer via SSH",
	Long: `Connect to a NetBird peer using SSH with support for port forwarding.

Flags go before the host. Everything after the host is the command to run on the peer.

Unlike OpenSSH, -l sets the NetBird log level and -o sets the known_hosts file. Use -u or user@host to set the login name.`,
	Example: `  netbird ssh peer-hostname
  netbird ssh root@peer-hostname
  netbird ssh --user root peer-hostname
  netbird ssh peer-hostname ls -la
  netbird ssh peer-hostname whoami
  netbird ssh -t peer-hostname tmux                  # Force PTY for tmux/screen
  netbird ssh -t peer-hostname sudo -i               # Force PTY for interactive sudo
  netbird ssh -L 8080:localhost:80 peer-hostname     # Local port forwarding
  netbird ssh -R 9090:localhost:3000 peer-hostname   # Remote port forwarding
  netbird ssh -L "*:8080:localhost:80" peer-hostname # Bind to all interfaces
  netbird ssh -L 8080:/tmp/socket peer-hostname      # Unix socket forwarding`,
	Args:    validateSSHArgs,
	RunE:    sshFn,
	Aliases: []string{"ssh"},
}

func sshFn(cmd *cobra.Command, args []string) error {
	cmd.SetOut(cmd.OutOrStdout())

	// Resolved here because the root PersistentPreRunE applies NB_* env vars after
	// argument validation.
	username = resolveSSHUsername()

	logOutput := "console"
	if firstLogFile := util.FindFirstLogPath(logFiles); firstLogFile != "" && firstLogFile != defaultLogFile {
		logOutput = firstLogFile
	}
	if err := util.InitLog(logLevel, logOutput); err != nil {
		return fmt.Errorf("init log: %w", err)
	}

	ctx := internal.CtxInitState(cmd.Context())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	sshctx, cancel := context.WithCancel(ctx)

	errCh := make(chan error, 1)
	go func() {
		if err := runSSH(sshctx, host, cmd); err != nil {
			errCh <- err
		}
		cancel()
	}()

	select {
	case <-sig:
		cancel()
		<-sshctx.Done()
		return nil
	case err := <-errCh:
		return err
	case <-sshctx.Done():
	}

	return nil
}

// getEnvOrDefault checks for environment variables with WT_ and NB_ prefixes
func getEnvOrDefault(flagName, defaultValue string) string {
	if envValue := os.Getenv("WT_" + flagName); envValue != "" {
		return envValue
	}
	if envValue := os.Getenv("NB_" + flagName); envValue != "" {
		return envValue
	}
	return defaultValue
}

// getBoolEnvOrDefault checks for boolean environment variables with WT_ and NB_ prefixes
func getBoolEnvOrDefault(flagName string, defaultValue bool) bool {
	if envValue := os.Getenv("WT_" + flagName); envValue != "" {
		if parsed, err := strconv.ParseBool(envValue); err == nil {
			return parsed
		}
	}
	if envValue := os.Getenv("NB_" + flagName); envValue != "" {
		if parsed, err := strconv.ParseBool(envValue); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// validateSSHArgs parses the host and remote command from the arguments left
// after flag parsing.
func validateSSHArgs(_ *cobra.Command, args []string) error {
	host = ""
	hostUser = ""
	command = ""
	return parseHostnameAndCommand(args)
}

// resolveSSHUsername returns the SSH user from --user, --login, user@host or the
// invoking account, in that order.
func resolveSSHUsername() string {
	switch {
	case username != "":
		return username
	case sshLogin != "":
		return sshLogin
	case hostUser != "":
		return hostUser
	}

	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		return sudoUser
	}
	if currentUser, err := user.Current(); err == nil {
		return currentUser.Username
	}
	return "root"
}

func parseHostnameAndCommand(args []string) error {
	if len(args) < 1 {
		return errors.New(hostArgumentRequired)
	}

	arg := args[0]
	if strings.Contains(arg, "@") {
		parts := strings.SplitN(arg, "@", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return errors.New("invalid user@host format")
		}
		hostUser = parts[0]
		host = parts[1]
	} else {
		host = arg
	}

	// Everything after hostname becomes the command
	if len(args) > 1 {
		command = strings.Join(args[1:], " ")
	}

	return nil
}

func runSSH(ctx context.Context, addr string, cmd *cobra.Command) error {
	target := net.JoinHostPort(strings.Trim(addr, "[]"), strconv.Itoa(port))
	c, err := sshclient.Dial(ctx, target, username, sshclient.DialOptions{
		KnownHostsFile:     knownHostsFile,
		IdentityFile:       identityFile,
		DaemonAddr:         daemonAddr,
		SkipCachedToken:    skipCachedToken,
		InsecureSkipVerify: !strictHostKeyChecking,
		NoBrowser:          sshNoBrowser,
	})

	if err != nil {
		cmd.Printf("Failed to connect to %s@%s\n", username, target)
		cmd.Printf("\nTroubleshooting steps:\n")
		cmd.Printf("  1. Check peer connectivity: netbird status -d\n")
		cmd.Printf("  2. Verify SSH server is enabled on the peer\n")
		cmd.Printf("  3. Ensure correct hostname/IP is used\n")
		return fmt.Errorf("dial %s: %w", target, err)
	}

	sshCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		<-sshCtx.Done()
		if err := c.Close(); err != nil {
			cmd.Printf("Error closing SSH connection: %v\n", err)
		}
	}()

	if err := startPortForwarding(sshCtx, c, cmd); err != nil {
		return fmt.Errorf("start port forwarding: %w", err)
	}

	if command != "" {
		return executeSSHCommand(sshCtx, c, command)
	}
	return openSSHTerminal(sshCtx, c)
}

// executeSSHCommand executes a command over SSH.
func executeSSHCommand(ctx context.Context, c *sshclient.Client, command string) error {
	var err error
	if requestPTY {
		err = c.ExecuteCommandWithPTY(ctx, command)
	} else {
		err = c.ExecuteCommandWithIO(ctx, command)
	}

	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil
		}

		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitStatus())
		}

		var exitMissingErr *ssh.ExitMissingError
		if errors.As(err, &exitMissingErr) {
			log.Debugf("Remote command exited without exit status: %v", err)
			return nil
		}

		return fmt.Errorf("execute command: %w", err)
	}
	return nil
}

// openSSHTerminal opens an interactive SSH terminal.
func openSSHTerminal(ctx context.Context, c *sshclient.Client) error {
	if err := c.OpenTerminal(ctx); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil
		}

		var exitMissingErr *ssh.ExitMissingError
		if errors.As(err, &exitMissingErr) {
			log.Debugf("Remote terminal exited without exit status: %v", err)
			return nil
		}

		return fmt.Errorf("open terminal: %w", err)
	}
	return nil
}

// startPortForwarding starts local and remote port forwarding based on command line flags
func startPortForwarding(ctx context.Context, c *sshclient.Client, cmd *cobra.Command) error {
	for _, forward := range localForwards {
		if err := parseAndStartLocalForward(ctx, c, forward, cmd); err != nil {
			return fmt.Errorf("local port forward %s: %w", forward, err)
		}
	}

	for _, forward := range remoteForwards {
		if err := parseAndStartRemoteForward(ctx, c, forward, cmd); err != nil {
			return fmt.Errorf("remote port forward %s: %w", forward, err)
		}
	}

	return nil
}

// parseAndStartLocalForward parses and starts a local port forward (-L)
func parseAndStartLocalForward(ctx context.Context, c *sshclient.Client, forward string, cmd *cobra.Command) error {
	localAddr, remoteAddr, err := parsePortForwardSpec(forward)
	if err != nil {
		return err
	}

	if err := validateDestinationPort(remoteAddr); err != nil {
		return fmt.Errorf("invalid remote address: %w", err)
	}

	log.Debugf("Local port forwarding: %s -> %s", localAddr, remoteAddr)

	go func() {
		if err := c.LocalPortForward(ctx, localAddr, remoteAddr); err != nil && !errors.Is(err, context.Canceled) {
			cmd.Printf("Local port forward error: %v\n", err)
		}
	}()

	return nil
}

// parseAndStartRemoteForward parses and starts a remote port forward (-R)
func parseAndStartRemoteForward(ctx context.Context, c *sshclient.Client, forward string, cmd *cobra.Command) error {
	remoteAddr, localAddr, err := parsePortForwardSpec(forward)
	if err != nil {
		return err
	}

	if err := validateDestinationPort(localAddr); err != nil {
		return fmt.Errorf("invalid local address: %w", err)
	}

	log.Debugf("Remote port forwarding: %s -> %s", remoteAddr, localAddr)

	go func() {
		if err := c.RemotePortForward(ctx, remoteAddr, localAddr); err != nil && !errors.Is(err, context.Canceled) {
			cmd.Printf("Remote port forward error: %v\n", err)
		}
	}()

	return nil
}

// validateDestinationPort checks that the destination address has a valid port.
// Port 0 is only valid for bind addresses (where the OS picks an available port),
// not for destination addresses where we need to connect.
func validateDestinationPort(addr string) error {
	if strings.HasPrefix(addr, "/") || strings.HasPrefix(addr, "./") {
		return nil
	}

	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("parse address %s: %w", addr, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port %s: %w", portStr, err)
	}

	if port == 0 {
		return fmt.Errorf("port 0 is not valid for destination address")
	}

	if port < 0 || port > 65535 {
		return fmt.Errorf("port %d out of range (1-65535)", port)
	}

	return nil
}

// parsePortForwardSpec parses port forward specifications like "8080:localhost:80" or "[::1]:8080:localhost:80".
// Also supports Unix sockets like "8080:/tmp/socket" or "127.0.0.1:8080:/tmp/socket".
func parsePortForwardSpec(spec string) (string, string, error) {
	// Support formats:
	// port:host:hostport  -> localhost:port -> host:hostport
	// host:port:host:hostport  -> host:port -> host:hostport
	// [host]:port:host:hostport -> [host]:port -> host:hostport
	// port:unix_socket_path -> localhost:port -> unix_socket_path
	// host:port:unix_socket_path -> host:port -> unix_socket_path

	if strings.HasPrefix(spec, "[") && strings.Contains(spec, "]:") {
		return parseIPv6ForwardSpec(spec)
	}

	parts := strings.Split(spec, ":")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid port forward specification: %s (expected format: [local_host:]local_port:remote_target)", spec)
	}

	switch len(parts) {
	case 2:
		return parseTwoPartForwardSpec(parts, spec)
	case 3:
		return parseThreePartForwardSpec(parts)
	case 4:
		return parseFourPartForwardSpec(parts)
	default:
		return "", "", fmt.Errorf("invalid port forward specification: %s", spec)
	}
}

// parseTwoPartForwardSpec handles "port:unix_socket" format.
func parseTwoPartForwardSpec(parts []string, spec string) (string, string, error) {
	if isUnixSocket(parts[1]) {
		localAddr := "localhost:" + parts[0]
		remoteAddr := parts[1]
		return localAddr, remoteAddr, nil
	}
	return "", "", fmt.Errorf("invalid port forward specification: %s (expected format: [local_host:]local_port:remote_host:remote_port or [local_host:]local_port:unix_socket)", spec)
}

// parseThreePartForwardSpec handles "port:host:hostport" or "host:port:unix_socket" formats.
func parseThreePartForwardSpec(parts []string) (string, string, error) {
	if isUnixSocket(parts[2]) {
		localHost := normalizeLocalHost(parts[0])
		localAddr := localHost + ":" + parts[1]
		remoteAddr := parts[2]
		return localAddr, remoteAddr, nil
	}
	localAddr := "localhost:" + parts[0]
	remoteAddr := parts[1] + ":" + parts[2]
	return localAddr, remoteAddr, nil
}

// parseFourPartForwardSpec handles "host:port:host:hostport" format.
func parseFourPartForwardSpec(parts []string) (string, string, error) {
	localHost := normalizeLocalHost(parts[0])
	localAddr := localHost + ":" + parts[1]
	remoteAddr := parts[2] + ":" + parts[3]
	return localAddr, remoteAddr, nil
}

// parseIPv6ForwardSpec handles "[host]:port:host:hostport" format.
func parseIPv6ForwardSpec(spec string) (string, string, error) {
	idx := strings.Index(spec, "]:")
	if idx == -1 {
		return "", "", fmt.Errorf("invalid IPv6 port forward specification: %s", spec)
	}

	ipv6Host := spec[:idx+1]
	remaining := spec[idx+2:]

	parts := strings.Split(remaining, ":")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("invalid IPv6 port forward specification: %s (expected [ipv6]:port:host:hostport)", spec)
	}

	localAddr := ipv6Host + ":" + parts[0]
	remoteAddr := parts[1] + ":" + parts[2]
	return localAddr, remoteAddr, nil
}

// isUnixSocket checks if a path is a Unix socket path.
func isUnixSocket(path string) bool {
	return strings.HasPrefix(path, "/") || strings.HasPrefix(path, "./")
}

// normalizeLocalHost converts "*" to "" for binding to all interfaces (dual-stack).
func normalizeLocalHost(host string) string {
	if host == "*" {
		return ""
	}
	return host
}

var sshProxyCmd = &cobra.Command{
	Use:    "proxy <host> <port>",
	Short:  "Internal SSH proxy for native SSH client integration",
	Long:   "Internal command used by SSH ProxyCommand to handle JWT authentication",
	Hidden: true,
	Args:   cobra.ExactArgs(2),
	RunE:   sshProxyFn,
}

func sshProxyFn(cmd *cobra.Command, args []string) error {
	logOutput := "console"
	if firstLogFile := util.FindFirstLogPath(logFiles); firstLogFile != "" && firstLogFile != defaultLogFile {
		logOutput = firstLogFile
	}

	proxyLogLevel := getEnvOrDefault("LOG_LEVEL", logLevel)
	if err := util.InitLog(proxyLogLevel, logOutput); err != nil {
		return fmt.Errorf("init log: %w", err)
	}

	host := args[0]
	portStr := args[1]

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port: %s", portStr)
	}

	// Check env var for browser setting since this command is invoked via SSH ProxyCommand
	// where command-line flags cannot be passed. Default is to open browser.
	noBrowser := getBoolEnvOrDefault("NO_BROWSER", false)
	var browserOpener func(string) error
	if !noBrowser {
		browserOpener = util.OpenBrowser
	}

	proxy, err := sshproxy.New(daemonAddr, host, port, cmd.ErrOrStderr(), browserOpener)
	if err != nil {
		return fmt.Errorf("create SSH proxy: %w", err)
	}
	defer func() {
		if err := proxy.Close(); err != nil {
			log.Debugf("close SSH proxy: %v", err)
		}
	}()

	if err := proxy.Connect(cmd.Context()); err != nil {
		return fmt.Errorf("SSH proxy: %w", err)
	}

	return nil
}

var sshDetectCmd = &cobra.Command{
	Use:    "detect <host> <port>",
	Short:  "Detect if a host is running NetBird SSH",
	Long:   "Internal command used by SSH Match exec to detect NetBird SSH servers. Exit codes: 0=JWT, 1=no-JWT, 2=regular SSH",
	Hidden: true,
	Args:   cobra.ExactArgs(2),
	RunE:   sshDetectFn,
}

func sshDetectFn(cmd *cobra.Command, args []string) error {
	detectLogLevel := getEnvOrDefault("LOG_LEVEL", logLevel)
	if err := util.InitLog(detectLogLevel, "console"); err != nil {
		os.Exit(detection.ServerTypeRegular.ExitCode())
	}

	host := args[0]
	portStr := args[1]

	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Debugf("invalid port %q: %v", portStr, err)
		os.Exit(detection.ServerTypeRegular.ExitCode())
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), detection.DefaultTimeout)

	dialer := &net.Dialer{}
	serverType, err := detection.DetectSSHServerType(ctx, dialer, host, port)
	if err != nil {
		log.Debugf("SSH server detection failed: %v", err)
		cancel()
		os.Exit(detection.ServerTypeRegular.ExitCode())
	}

	cancel()
	os.Exit(serverType.ExitCode())
	return nil
}
