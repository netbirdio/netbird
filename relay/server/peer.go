package server

import (
	"net"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/messages"
)

type Peer struct {
	Log  *log.Entry
	idS  string
	idB  []byte
	conn net.Conn
}

func NewPeer(id []byte, conn net.Conn) *Peer {
	log.Debugf("new peer: %v", id)
	stringID := messages.HashIDToString(id)
	return &Peer{
		Log:  log.WithField("peer_id", stringID),
		idB:  id,
		idS:  stringID,
		conn: conn,
	}
}
func (p *Peer) ID() []byte {
	return p.idB
}

func (p *Peer) String() string {
	return p.idS
}
