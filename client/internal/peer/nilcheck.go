package peer

import (
	"net"

	log "github.com/sirupsen/logrus"
)

func remoteConnNil(log *log.Entry, conn net.Conn) bool {
	if conn == nil {
		log.Errorf("ice conn is nil")
		return true
	}

	if conn.RemoteAddr() == nil {
		log.Errorf("ICE remote address is nil")
		return true
	}

	return false
}
