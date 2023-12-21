package netstack

import (
	"fmt"
	"os"
	"strconv"
)

// todo: move these function to cmd layer
func IsEnabled() bool {
	return os.Getenv("NB_USE_NETSTACK_MODE") == "true"
}

func ListenAddr() string {
	sPort := os.Getenv("NB_SOCK5_LISTENER_PORT")
	port, err := strconv.Atoi(sPort)
	if err != nil {
		return DEFAULT_SOCKS5_ADDR
	}
	if port < 1 || port > 65535 {
		return DEFAULT_SOCKS5_ADDR
	}

	return fmt.Sprintf("0.0.0.0:%d", port)
}
