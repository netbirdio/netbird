package detection

import (
	"bufio"
	"context"
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

	detectionTimeout = 5 * time.Second
)

type ServerType string

const (
	ServerTypeNetBirdJWT   ServerType = "netbird-jwt"
	ServerTypeNetBirdNoJWT ServerType = "netbird-no-jwt"
	ServerTypeRegular      ServerType = "regular"
)

// RequiresJWT checks if the server type requires JWT authentication
func (s ServerType) RequiresJWT() bool {
	return s == ServerTypeNetBirdJWT
}

// DetectSSHServerType detects SSH server type with optional username
func DetectSSHServerType(ctx context.Context, host string, port int) (ServerType, error) {
	targetAddr := net.JoinHostPort(host, strconv.Itoa(port))

	dialer := &net.Dialer{
		Timeout: detectionTimeout,
	}
	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		log.Debugf("SSH connection failed for detection: %v", err)
		return ServerTypeRegular, nil
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(detectionTimeout)); err != nil {
		log.Debugf("set read deadline: %v", err)
		return ServerTypeRegular, nil
	}

	reader := bufio.NewReader(conn)
	serverBanner, err := reader.ReadString('\n')
	if err != nil {
		log.Debugf("read SSH banner: %v", err)
		return ServerTypeRegular, nil
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
