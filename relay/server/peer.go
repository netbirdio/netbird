package server

import (
	"fmt"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
)

type Participant struct {
	ChannelID        uint16
	ChannelIDForeign uint16
	ConnForeign      net.Conn
	Peer             *Peer
}

type Peer struct {
	Log  *log.Entry
	id   string
	conn net.Conn

	pendingParticipantByChannelID map[uint16]*Participant
	participantByID               map[uint16]*Participant // used for package transfer
	participantByPeerID           map[string]*Participant // used for channel linking

	lastId     uint16
	lastIdLock sync.Mutex
}

func NewPeer(id string, conn net.Conn) *Peer {
	return &Peer{
		Log:                           log.WithField("peer_id", id),
		id:                            id,
		conn:                          conn,
		pendingParticipantByChannelID: make(map[uint16]*Participant),
		participantByID:               make(map[uint16]*Participant),
		participantByPeerID:           make(map[string]*Participant),
	}
}
func (p *Peer) BindChannel(remotePeerId string) uint16 {
	ch, ok := p.participantByPeerID[remotePeerId]
	if ok {
		return ch.ChannelID
	}

	channelID := p.newChannelID()
	channel := &Participant{
		ChannelID: channelID,
	}
	p.pendingParticipantByChannelID[channelID] = channel
	p.participantByPeerID[remotePeerId] = channel
	return channelID
}

func (p *Peer) UnBindChannel(remotePeerId string) {
	pa, ok := p.participantByPeerID[remotePeerId]
	if !ok {
		return
	}

	p.Log.Debugf("unbind channel with '%s': %d", remotePeerId, pa.ChannelID)
	p.pendingParticipantByChannelID[pa.ChannelID] = pa
	delete(p.participantByID, pa.ChannelID)
}

func (p *Peer) AddParticipant(peer *Peer, remoteChannelID uint16) (uint16, bool) {
	participant, ok := p.participantByPeerID[peer.ID()]
	if !ok {
		return 0, false
	}
	participant.ChannelIDForeign = remoteChannelID
	participant.ConnForeign = peer.conn
	participant.Peer = peer

	delete(p.pendingParticipantByChannelID, participant.ChannelID)
	p.participantByID[participant.ChannelID] = participant
	return participant.ChannelID, true
}

func (p *Peer) DeleteParticipants() {
	for _, participant := range p.participantByID {
		participant.Peer.UnBindChannel(p.id)
	}
}

func (p *Peer) ConnByChannelID(dstID uint16) (uint16, net.Conn, error) {
	ch, ok := p.participantByID[dstID]
	if !ok {
		return 0, nil, fmt.Errorf("destination channel not found")
	}

	return ch.ChannelIDForeign, ch.ConnForeign, nil
}

func (p *Peer) ID() string {
	return p.id
}

func (p *Peer) newChannelID() uint16 {
	p.lastIdLock.Lock()
	defer p.lastIdLock.Unlock()
	for {
		p.lastId++
		if _, ok := p.pendingParticipantByChannelID[p.lastId]; ok {
			continue
		}
		if _, ok := p.participantByID[p.lastId]; ok {
			continue
		}
		return p.lastId
	}
}
