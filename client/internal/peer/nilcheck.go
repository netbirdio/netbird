package peer

import (
	"net"
	"reflect"

	"github.com/pion/ice/v3"
	log "github.com/sirupsen/logrus"
)

func nilCheck(log *log.Entry, conn net.Conn) {
	if conn == nil {
		log.Infof("conn is nil")
		return
	}

	if conn.RemoteAddr() == nil {
		log.Infof("conn.RemoteAddr() is nil")
		return
	}

	if reflect.ValueOf(conn.RemoteAddr()).IsNil() {
		log.Infof("value of conn.RemoteAddr() is nil")
		return
	}
}

func agentCheck(log *log.Entry, agent *ice.Agent) {
	if agent == nil {
		log.Errorf("agent is nil")
		return
	}

	pair, err := agent.GetSelectedCandidatePair()
	if err != nil {
		log.Errorf("error getting selected candidate pair: %v", err)
		return
	}

	if pair == nil {
		log.Errorf("pair is nil")
		return
	}

	if pair.Remote == nil {
		log.Errorf("pair.Remote is nil")
		return
	}

	if pair.Remote.Address() == "" {
		log.Errorf("address is empty")
		return
	}
}
