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
	nbnet "github.com/netbirdio/netbird/client/net"
)

const defaultChannelSize = 100

// ConnTrack manages kernel-based conntrack events
type ConnTrack struct {
	flowLogger nftypes.FlowLogger
	iface      nftypes.IFaceMapper

	conn *nfct.Conn
	mux  sync.Mutex

	instanceID     uuid.UUID
	started        bool
	done           chan struct{}
	sysctlModified bool
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
func (c *ConnTrack) Start(enableCounters bool) error {
	c.mux.Lock()
	defer c.mux.Unlock()

	if c.started {
		return nil
	}

	log.Info("Starting conntrack event listening")

	if enableCounters {
		c.EnableAccounting()
	}

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

	c.RestoreAccounting()
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

		c.RestoreAccounting()

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

	if event.Type != nfct.EventNew && event.Type != nfct.EventDestroy {
		return
	}

	flow := *event.Flow

	proto := nftypes.Protocol(flow.TupleOrig.Proto.Protocol)
	if proto == nftypes.ProtocolUnknown {
		return
	}
	srcIP := flow.TupleOrig.IP.SourceAddress
	dstIP := flow.TupleOrig.IP.DestinationAddress

	if !c.relevantFlow(flow.Mark, srcIP, dstIP) {
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

	flowID := c.getFlowID(flow.ID)
	direction := c.inferDirection(flow.Mark, srcIP, dstIP)

	eventType := nftypes.TypeStart
	eventStr := "New"

	if event.Type == nfct.EventDestroy {
		eventType = nftypes.TypeEnd
		eventStr = "Ended"
	}

	log.Tracef("%s %s %s connection: %s:%d → %s:%d", eventStr, direction, proto, srcIP, srcPort, dstIP, dstPort)

	c.flowLogger.StoreEvent(nftypes.EventFields{
		FlowID:     flowID,
		Type:       eventType,
		Direction:  direction,
		Protocol:   proto,
		SourceIP:   srcIP,
		DestIP:     dstIP,
		SourcePort: srcPort,
		DestPort:   dstPort,
		ICMPType:   icmpType,
		ICMPCode:   icmpCode,
		RxPackets:  c.mapRxPackets(flow, direction),
		TxPackets:  c.mapTxPackets(flow, direction),
		RxBytes:    c.mapRxBytes(flow, direction),
		TxBytes:    c.mapTxBytes(flow, direction),
	})
}

// relevantFlow checks if the flow is related to the specified interface
func (c *ConnTrack) relevantFlow(mark uint32, srcIP, dstIP netip.Addr) bool {
	if nbnet.IsDataPlaneMark(mark) {
		return true
	}

	// fallback if mark rules are not in place
	wgnet := c.iface.Address().Network
	return wgnet.Contains(srcIP) || wgnet.Contains(dstIP)
}

// mapRxPackets maps packet counts to RX based on flow direction
func (c *ConnTrack) mapRxPackets(flow nfct.Flow, direction nftypes.Direction) uint64 {
	// For Ingress: CountersOrig is from external to us (RX)
	// For Egress: CountersReply is from external to us (RX)
	if direction == nftypes.Ingress {
		return flow.CountersOrig.Packets
	}
	return flow.CountersReply.Packets
}

// mapTxPackets maps packet counts to TX based on flow direction
func (c *ConnTrack) mapTxPackets(flow nfct.Flow, direction nftypes.Direction) uint64 {
	// For Ingress: CountersReply is from us to external (TX)
	// For Egress: CountersOrig is from us to external (TX)
	if direction == nftypes.Ingress {
		return flow.CountersReply.Packets
	}
	return flow.CountersOrig.Packets
}

// mapRxBytes maps byte counts to RX based on flow direction
func (c *ConnTrack) mapRxBytes(flow nfct.Flow, direction nftypes.Direction) uint64 {
	// For Ingress: CountersOrig is from external to us (RX)
	// For Egress: CountersReply is from external to us (RX)
	if direction == nftypes.Ingress {
		return flow.CountersOrig.Bytes
	}
	return flow.CountersReply.Bytes
}

// mapTxBytes maps byte counts to TX based on flow direction
func (c *ConnTrack) mapTxBytes(flow nfct.Flow, direction nftypes.Direction) uint64 {
	// For Ingress: CountersReply is from us to external (TX)
	// For Egress: CountersOrig is from us to external (TX)
	if direction == nftypes.Ingress {
		return flow.CountersReply.Bytes
	}
	return flow.CountersOrig.Bytes
}

// getFlowID creates a unique UUID based on the conntrack ID and instance ID
func (c *ConnTrack) getFlowID(conntrackID uint32) uuid.UUID {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], conntrackID)
	return uuid.NewSHA1(c.instanceID, buf[:])
}

func (c *ConnTrack) inferDirection(mark uint32, srcIP, dstIP netip.Addr) nftypes.Direction {
	switch mark {
	case nbnet.DataPlaneMarkIn:
		return nftypes.Ingress
	case nbnet.DataPlaneMarkOut:
		return nftypes.Egress
	}

	// fallback if marks are not set
	wgaddr := c.iface.Address().IP
	wgnetwork := c.iface.Address().Network
	switch {
	case wgaddr == srcIP:
		return nftypes.Egress
	case wgaddr == dstIP:
		return nftypes.Ingress
	case wgnetwork.Contains(srcIP):
		// netbird network -> resource network
		return nftypes.Ingress
	case wgnetwork.Contains(dstIP):
		// resource network -> netbird network
		return nftypes.Egress
	}

	return nftypes.DirectionUnknown
}
