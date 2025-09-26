package detection

import (
	"net"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	// ServerIdentifier is the base response for NetBird SSH servers
	ServerIdentifier = "NetBird-SSH-Server"
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
func DetectSSHServerType(host string, port int, username string) (ServerType, error) {
	if username == "" {
		username = "netbird-detect"
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{},
		// #nosec G106 - InsecureIgnoreHostKey is acceptable for server type detection
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         detectionTimeout,
	}

	targetAddr := net.JoinHostPort(host, strconv.Itoa(port))
	client, err := ssh.Dial("tcp", targetAddr, config)
	if err != nil {
		log.Debugf("SSH connection failed for detection: %v", err)
		return ServerTypeRegular, nil
	}
	defer client.Close()

	ok, response, err := client.SendRequest("netbird-detect", true, nil)
	if err != nil || !ok {
		log.Debugf("Detection request failed: %v", err)
		return ServerTypeRegular, nil
	}

	responseStr := string(response)

	if !strings.Contains(responseStr, ServerIdentifier) {
		return ServerTypeRegular, nil
	}

	if strings.Contains(responseStr, JWTRequiredMarker) {
		return ServerTypeNetBirdJWT, nil
	}

	return ServerTypeNetBirdNoJWT, nil
}
