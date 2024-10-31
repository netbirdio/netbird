package peer

import (
	"net"
	"reflect"

	log "github.com/sirupsen/logrus"
)

func nilCheck(log *log.Entry, conn net.Conn) {
	if conn == nil {
		log.Infof("conn is nil")
		return
	}

	if conn.RemoteAddr() == nil {
		log.Infof("conn.RemoteAddr() is nil")
	}

	if reflect.ValueOf(conn.RemoteAddr()).IsNil() {
		log.Infof("value of conn.RemoteAddr() is nil")
	}
}
