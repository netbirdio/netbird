//go:build !js

package netstack

import (
	"fmt"
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
)

const EnvUseNetstackMode = "NB_USE_NETSTACK_MODE"

// IsEnabled todo: move these function to cmd layer
func IsEnabled() bool {
	return os.Getenv(EnvUseNetstackMode) == "true"
}

func ListenAddr() string {
	sPort := os.Getenv("NB_SOCKS5_LISTENER_PORT")
	if sPort == "" {
		return listenAddr(DefaultSocks5Port)
	}

	port, err := strconv.Atoi(sPort)
	if err != nil {
		log.Warnf("invalid socks5 listener port, unable to convert it to int, falling back to default: %d", DefaultSocks5Port)
		return listenAddr(DefaultSocks5Port)
	}
	if port < 1 || port > 65535 {
		log.Warnf("invalid socks5 listener port, it should be in the range 1-65535, falling back to default: %d", DefaultSocks5Port)
		return listenAddr(DefaultSocks5Port)
	}

	return listenAddr(port)
}

func listenAddr(port int) string {
	return fmt.Sprintf("0.0.0.0:%d", port)
}
