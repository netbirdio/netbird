package server

import (
	"fmt"
	"net"
	"strconv"

	"github.com/gliderlabs/ssh"
)

// prepareSSHEnv prepares SSH protocol-specific environment variables
// These variables provide information about the SSH connection itself
func prepareSSHEnv(session ssh.Session) []string {
	remoteAddr := session.RemoteAddr()
	localAddr := session.LocalAddr()

	remoteHost, remotePort, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		remoteHost = remoteAddr.String()
		remotePort = "0"
	}

	localHost, localPort, err := net.SplitHostPort(localAddr.String())
	if err != nil {
		localHost = localAddr.String()
		localPort = strconv.Itoa(InternalSSHPort)
	}

	return []string{
		// SSH_CLIENT format: "client_ip client_port server_port"
		fmt.Sprintf("SSH_CLIENT=%s %s %s", remoteHost, remotePort, localPort),
		// SSH_CONNECTION format: "client_ip client_port server_ip server_port"
		fmt.Sprintf("SSH_CONNECTION=%s %s %s %s", remoteHost, remotePort, localHost, localPort),
	}
}
