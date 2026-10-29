package detection

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// ServerIdentifier is the base response for NetBird SSH servers
	ServerIdentifier = "NetBird-SSH-Server"
	// ProxyIdentifier is the base response for NetBird SSH proxy
	ProxyIdentifier = "NetBird-SSH-Proxy"
	// JWTRequiredMarker is appended to responses when JWT is required
	JWTRequiredMarker = "NetBird-JWT-Required"

	// DefaultTimeout is the default timeout for SSH server detection
	DefaultTimeout = 5 * time.Second
)

type ServerType string

const (
	ServerTypeNetBirdJWT   ServerType = "netbird-jwt"
	ServerTypeNetBirdNoJWT ServerType = "netbird-no-jwt"
	ServerTypeRegular      ServerType = "regular"
)

// Dialer provides network connection capabilities
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// RequiresJWT checks if the server type requires JWT authentication
func (s ServerType) RequiresJWT() bool {
	return s == ServerTypeNetBirdJWT
}

// ExitCode returns the exit code for the detect command
func (s ServerType) ExitCode() int {
	switch s {
	case ServerTypeNetBirdJWT:
		return 0
	case ServerTypeNetBirdNoJWT:
		return 1
	case ServerTypeRegular:
		return 2
	default:
		return 2
	}
}

// DetectSSHServerType detects SSH server type using the provided dialer
func DetectSSHServerType(ctx context.Context, dialer Dialer, host string, port int) (ServerType, error) {
	targetAddr := net.JoinHostPort(host, strconv.Itoa(port))

	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return ServerTypeRegular, fmt.Errorf("connect to %s: %w", targetAddr, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return ServerTypeRegular, fmt.Errorf("set read deadline: %w", err)
		}
	}

	reader := bufio.NewReader(conn)
	serverBanner, err := reader.ReadString('\n')
	if err != nil {
		return ServerTypeRegular, fmt.Errorf("read SSH banner: %w", err)
	}

	serverBanner = strings.TrimSpace(serverBanner)
	log.Debugf("SSH server banner: %s", serverBanner)

	if !strings.HasPrefix(serverBanner, "SSH-") {
		log.Debugf("Invalid SSH banner")
		return ServerTypeRegular, nil
	}

	if !strings.Contains(serverBanner, ServerIdentifier) {
		log.Debugf("Server banner does not contain identifier '%s'", ServerIdentifier)
		return ServerTypeRegular, nil
	}

	if strings.Contains(serverBanner, JWTRequiredMarker) {
		return ServerTypeNetBirdJWT, nil
	}

	return ServerTypeNetBirdNoJWT, nil
}
