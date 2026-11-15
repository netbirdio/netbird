package server

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"

	"github.com/netbirdio/netbird/relay/messages"
	"github.com/netbirdio/netbird/relay/server/store"
)

type EbpfMgr interface {
	AddPeer(channelID, dstChannelID uint16, dstAddr netip.AddrPort) error
}

type noopEbpfMgr struct{}

func (noopEbpfMgr) AddPeer(channelID, dstChannelID uint16, dstAddr netip.AddrPort) error {
	return nil
}

type channelInfo struct {
	srcChannelID messages.ChannelID
	dstChannelID *messages.ChannelID
	dstAddr      netip.AddrPort
	dstPeer      messages.PeerID
}

type ChannelManager struct {
	ebpfMgr   EbpfMgr
	peerStore *store.Store

	channels  map[messages.PeerID]map[messages.PeerID]*channelInfo
	byChannel map[messages.ChannelID]*channelInfo
}

func NewChannelManager(peerStore *store.Store, ebpfMgr EbpfMgr) *ChannelManager {
	cm := &ChannelManager{
		ebpfMgr:   ebpfMgr,
		peerStore: peerStore,
		channels:  make(map[messages.PeerID]map[messages.PeerID]*channelInfo),
		byChannel: make(map[messages.ChannelID]*channelInfo),
	}
	return cm
}

func (cm *ChannelManager) Add(srcPeer, dstPeer messages.PeerID) messages.ChannelID {
	remotePeer, ok := cm.peerStore.Peer(dstPeer)
	if !ok {
		panic("should not be happen")
	}

	addr := remotePeer.RemoteAddress()

	srcChannels, ok := cm.channels[srcPeer]
	if !ok {
		srcChannels = make(map[messages.PeerID]*channelInfo)
	}

	channel, ok := srcChannels[dstPeer]
	if !ok {
		channel = &channelInfo{
			srcChannelID: newChannelID(),
			dstAddr:      addr,
			dstPeer:      dstPeer,
		}
		cm.byChannel[channel.srcChannelID] = channel
	}

	var reverseChannel *channelInfo
	fullyLinked := false

	if dstChannels, ok := cm.channels[dstPeer]; ok {
		if rc, ok := dstChannels[srcPeer]; ok {
			reverseChannel = rc

			if reverseChannel.dstChannelID == nil {
				reverseChannel.dstChannelID = &channel.srcChannelID
			}
			if channel.dstChannelID == nil && reverseChannel.srcChannelID != (messages.ChannelID{}) {
				channel.dstChannelID = &reverseChannel.srcChannelID
			}

			if channel.dstChannelID != nil && reverseChannel.dstChannelID != nil {
				fullyLinked = true
			}
		}
	}

	srcChannels[dstPeer] = channel
	cm.channels[srcPeer] = srcChannels

	if fullyLinked && reverseChannel != nil {
		_ = cm.ebpfMgr.AddPeer(
			channelIDToUint16(channel.srcChannelID),
			channelIDToUint16(*channel.dstChannelID),
			channel.dstAddr,
		)

		_ = cm.ebpfMgr.AddPeer(
			channelIDToUint16(reverseChannel.srcChannelID),
			channelIDToUint16(*reverseChannel.dstChannelID),
			reverseChannel.dstAddr,
		)
	}

	return channel.srcChannelID
}

func (cm *ChannelManager) Forward(srcChannelID messages.ChannelID, msg []byte) error {
	channel, ok := cm.byChannel[srcChannelID]
	if !ok || channel.dstChannelID == nil {
		return fmt.Errorf("no channel for %v", srcChannelID)
	}

	dstPeer, ok := cm.peerStore.Peer(channel.dstPeer)
	if !ok {
		return fmt.Errorf("dst peer %s not connected", channel.dstPeer)
	}

	out, err := messages.MarshalEbpfTransportMsg(*channel.dstChannelID, msg)
	if err != nil {
		return err
	}

	_, err = dstPeer.Write(out)
	return err
}

func channelIDToUint16(id messages.ChannelID) uint16 {
	return binary.BigEndian.Uint16(id[:])
}

func newChannelID() messages.ChannelID {
	var id messages.ChannelID
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		panic("failed to generate ChannelID: " + err.Error())
	}
	return id
}
