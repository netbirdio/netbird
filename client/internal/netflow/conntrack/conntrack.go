//go:build linux && !android

package conntrack

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	nfct "github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"

	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
)

const defaultChannelSize = 100

// ConnTrack manages kernel-based conntrack events
type ConnTrack struct {
	flowLogger nftypes.FlowLogger
	iface      nftypes.IFaceMapper

	conn *nfct.Conn
	mux  sync.Mutex

	instanceID uuid.UUID
	started    bool
	done       chan struct{}
}

// New creates a new connection tracker that interfaces with the kernel's conntrack system
func New(flowLogger nftypes.FlowLogger, iface nftypes.IFaceMapper) *ConnTrack {
	return &ConnTrack{
		flowLogger: flowLogger,
		iface:      iface,
		instanceID: uuid.New(),
		started:    false,
		done:       make(chan struct{}, 1),
	}
}

// Start begins tracking connections by listening for conntrack events. This method is idempotent.
func (c *ConnTrack) Start() error {
	c.mux.Lock()
	defer c.mux.Unlock()

	if c.started {
		return nil
	}

	log.Info("Starting conntrack event listening")

	conn, err := nfct.Dial(nil)
	if err != nil {
		return fmt.Errorf("dial conntrack: %w", err)
	}
	c.conn = conn

	events := make(chan nfct.Event, defaultChannelSize)
	errChan, err := conn.Listen(events, 1, []netfilter.NetlinkGroup{
		netfilter.GroupCTNew,
		netfilter.GroupCTDestroy,
	})

	if err != nil {
		if err := c.conn.Close(); err != nil {
			log.Errorf("Error closing conntrack connection: %v", err)
		}
		c.conn = nil
		return fmt.Errorf("start conntrack listener: %w", err)
	}

	c.started = true

	go c.receiverRoutine(events, errChan)

	return nil
}

func (c *ConnTrack) receiverRoutine(events chan nfct.Event, errChan chan error) {
	for {
		select {
		case event := <-events:
			c.handleEvent(event)
		case err := <-errChan:
			log.Errorf("Error from conntrack event listener: %v", err)
			if err := c.conn.Close(); err != nil {
				log.Errorf("Error closing conntrack connection: %v", err)
			}
			return
		case <-c.done:
			return
		}
	}
}

// Stop stops the connection tracking. This method is idempotent.
func (c *ConnTrack) Stop() {
	c.mux.Lock()
	defer c.mux.Unlock()

	if !c.started {
		return
	}

	log.Info("Stopping conntrack event listening")

	select {
	case c.done <- struct{}{}:
	default:
	}

	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			log.Errorf("Error closing conntrack connection: %v", err)
		}
		c.conn = nil
	}

	c.started = false
}

// Close stops listening for events and cleans up resources
func (c *ConnTrack) Close() error {
	c.mux.Lock()
	defer c.mux.Unlock()

	if c.started {
		select {
		case c.done <- struct{}{}:
		default:
		}
	}

	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.started = false
		if err != nil {
			return fmt.Errorf("close conntrack: %w", err)
		}
	}

	return nil
}

// handleEvent processes incoming conntrack events
func (c *ConnTrack) handleEvent(event nfct.Event) {
	if event.Flow == nil {
		return
	}

	flow := *event.Flow

	proto := nftypes.Protocol(flow.TupleOrig.Proto.Protocol)
	if proto == nftypes.ProtocolUnknown {
		return
	}
	srcIP := flow.TupleOrig.IP.SourceAddress
	dstIP := flow.TupleOrig.IP.DestinationAddress

	if !c.relevantFlow(srcIP, dstIP) {
		return
	}

	var srcPort, dstPort uint16
	var icmpType, icmpCode uint8

	switch proto {
	case nftypes.TCP, nftypes.UDP, nftypes.SCTP:
		srcPort = flow.TupleOrig.Proto.SourcePort
		dstPort = flow.TupleOrig.Proto.DestinationPort
	case nftypes.ICMP:
		icmpType = flow.TupleOrig.Proto.ICMPType
		icmpCode = flow.TupleOrig.Proto.ICMPCode
	}

	switch event.Type {
	case nfct.EventNew:
		c.handleNewFlow(flow.ID, proto, srcIP, dstIP, srcPort, dstPort, icmpType, icmpCode)

	case nfct.EventDestroy:
		c.handleDestroyFlow(flow.ID, proto, srcIP, dstIP, srcPort, dstPort, icmpType, icmpCode)
	}
}

// relevantFlow checks if the flow is related to the specified interface
func (c *ConnTrack) relevantFlow(srcIP, dstIP netip.Addr) bool {
	// TODO: filter traffic by interface

	wgnet := c.iface.Address().Network
	if !wgnet.Contains(srcIP.AsSlice()) && !wgnet.Contains(dstIP.AsSlice()) {
		return false
	}

	return true
}

func (c *ConnTrack) handleNewFlow(id uint32, proto nftypes.Protocol, srcIP, dstIP netip.Addr, srcPort, dstPort uint16, icmpType, icmpCode uint8) {
	flowID := c.getFlowID(id)
	direction := c.inferDirection(srcIP, dstIP)

	c.sendEvent(nftypes.TypeStart, flowID, direction, proto, srcIP, dstIP, srcPort, dstPort)
	log.Tracef("New %s %s connection: %s:%d -> %s:%d", direction, proto, srcIP, srcPort, dstIP, dstPort)
}

func (c *ConnTrack) handleDestroyFlow(id uint32, proto nftypes.Protocol, srcIP, dstIP netip.Addr, srcPort, dstPort uint16, icmpType, icmpCode uint8) {
	flowID := c.getFlowID(id)
	direction := c.inferDirection(srcIP, dstIP)

	c.sendEvent(nftypes.TypeEnd, flowID, direction, proto, srcIP, dstIP, srcPort, dstPort)
	log.Tracef("Ended %s %s connection: %s:%d -> %s:%d", direction, proto, srcIP, srcPort, dstIP, dstPort)
}

func (c *ConnTrack) sendEvent(
	typ nftypes.Type,
	flowID uuid.UUID,
	direction nftypes.Direction,
	protocol nftypes.Protocol,
	srcIP, dstIP netip.Addr,
	srcPort, dstPort uint16,
) {
	c.flowLogger.StoreEvent(nftypes.EventFields{
		FlowID:     flowID,
		Type:       typ,
		Direction:  direction,
		Protocol:   protocol,
		SourceIP:   srcIP,
		DestIP:     dstIP,
		SourcePort: srcPort,
		DestPort:   dstPort,
	})
}

// getFlowID creates a unique UUID based on the conntrack ID and instance ID
func (c *ConnTrack) getFlowID(conntrackID uint32) uuid.UUID {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], conntrackID)
	return uuid.NewSHA1(c.instanceID, buf[:])
}

func (c *ConnTrack) inferDirection(srcIP, dstIP netip.Addr) nftypes.Direction {
	wgaddr := c.iface.Address().IP
	wgnetwork := c.iface.Address().Network
	switch {
	case wgaddr.Equal(srcIP.AsSlice()):
		return nftypes.Egress
	case wgaddr.Equal(dstIP.AsSlice()):
		return nftypes.Ingress
	case wgnetwork.Contains(srcIP.AsSlice()):
		// netbird network -> resource network
		return nftypes.Ingress
	case wgnetwork.Contains(dstIP.AsSlice()):
		// resource network -> netbird network
		return nftypes.Egress

		// TODO: handle site2site traffic
	}

	return nftypes.DirectionUnknown
}
