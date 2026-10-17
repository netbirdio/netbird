//go:build linux && !android

package conntrack

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	nfct "github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"

	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
	nbnet "github.com/netbirdio/netbird/client/net"
)

const (
	defaultChannelSize     = 100
	reconnectInitInterval  = 5 * time.Second
	reconnectMaxInterval   = 5 * time.Minute
	reconnectRandomization = 0.5
)

// listener abstracts a netlink conntrack connection for testability.
type listener interface {
	Listen(evChan chan<- nfct.Event, numWorkers uint8, groups []netfilter.NetlinkGroup) (chan error, error)
	Close() error
}

// ConnTrack manages kernel-based conntrack events
type ConnTrack struct {
	flowLogger nftypes.FlowLogger
	iface      nftypes.IFaceMapper

	mux sync.Mutex
	run *conntrackRun

	dial           func() (listener, error)
	instanceID     uuid.UUID
	sysctlModified bool
}

type conntrackRun struct {
	ctx    context.Context
	cancel context.CancelFunc
	conn   listener
}

// DialFunc is a constructor for netlink conntrack connections.
type DialFunc func() (listener, error)

// Option configures a ConnTrack instance.
type Option func(*ConnTrack)

// WithDialer overrides the default netlink dialer, primarily for testing.
func WithDialer(dial DialFunc) Option {
	return func(c *ConnTrack) {
		c.dial = dial
	}
}

func defaultDial() (listener, error) {
	return nfct.Dial(nil)
}

// New creates a new connection tracker that interfaces with the kernel's conntrack system
func New(flowLogger nftypes.FlowLogger, iface nftypes.IFaceMapper, opts ...Option) *ConnTrack {
	ct := &ConnTrack{
		flowLogger: flowLogger,
		iface:      iface,
		instanceID: uuid.New(),
		dial:       defaultDial,
	}
	for _, opt := range opts {
		opt(ct)
	}
	return ct
}

// Start begins tracking connections by listening for conntrack events. This method is idempotent.
func (c *ConnTrack) Start(enableCounters bool) error {
	c.mux.Lock()
	defer c.mux.Unlock()

	if c.run != nil {
		return nil
	}

	log.Info("Starting conntrack event listening")

	if enableCounters {
		c.EnableAccounting()
	}

	conn, err := c.dial()
	if err != nil {
		c.RestoreAccounting()
		return fmt.Errorf("dial conntrack: %w", err)
	}
	events := make(chan nfct.Event, defaultChannelSize)
	errChan, err := conn.Listen(events, 1, []netfilter.NetlinkGroup{
		netfilter.GroupCTNew,
		netfilter.GroupCTDestroy,
	})

	if err != nil {
		if err := conn.Close(); err != nil {
			log.Errorf("Error closing conntrack connection: %v", err)
		}
		c.RestoreAccounting()
		return fmt.Errorf("start conntrack listener: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	run := &conntrackRun{
		ctx:    ctx,
		cancel: cancel,
		conn:   conn,
	}
	c.run = run

	go c.receiverRoutine(run, events, errChan)

	return nil
}

func (c *ConnTrack) receiverRoutine(run *conntrackRun, events chan nfct.Event, errChan chan error) {
	for {
		select {
		case event := <-events:
			if run.ctx.Err() != nil {
				return
			}
			c.handleEvent(event)
		case err := <-errChan:
			if run.ctx.Err() != nil {
				return
			}
			if events, errChan = c.handleListenerError(run, err); events == nil {
				return
			}
		case <-run.ctx.Done():
			return
		}
	}
}

// handleListenerError closes the failed connection and attempts to reconnect.
// Returns new channels on success, or nil if shutdown was requested.
func (c *ConnTrack) handleListenerError(run *conntrackRun, err error) (chan nfct.Event, chan error) {
	log.Warnf("conntrack event listener failed: %v", err)
	if !c.closeRunConn(run) {
		return nil, nil
	}
	return c.reconnect(run)
}

func (c *ConnTrack) closeRunConn(run *conntrackRun) bool {
	c.mux.Lock()
	if c.run != run {
		c.mux.Unlock()
		return false
	}
	conn := run.conn
	run.conn = nil
	c.mux.Unlock()

	if conn != nil {
		if err := conn.Close(); err != nil {
			log.Debugf("close conntrack connection: %v", err)
		}
	}
	return true
}

// reconnect attempts to re-establish the conntrack netlink listener with exponential backoff.
// Returns new channels on success, or nil if shutdown was requested.
func (c *ConnTrack) reconnect(run *conntrackRun) (chan nfct.Event, chan error) {
	bo := &backoff.ExponentialBackOff{
		InitialInterval:     reconnectInitInterval,
		RandomizationFactor: reconnectRandomization,
		Multiplier:          backoff.DefaultMultiplier,
		MaxInterval:         reconnectMaxInterval,
		MaxElapsedTime:      0, // retry indefinitely
		Clock:               backoff.SystemClock,
	}
	bo.Reset()

	for {
		delay := bo.NextBackOff()
		log.Infof("reconnecting conntrack listener in %s", delay)

		timer := time.NewTimer(delay)
		select {
		case <-run.ctx.Done():
			timer.Stop()
			return nil, nil
		case <-timer.C:
		}

		conn, err := c.dial()
		if err != nil {
			log.Warnf("reconnect conntrack dial: %v", err)
			continue
		}
		if run.ctx.Err() != nil {
			if closeErr := conn.Close(); closeErr != nil {
				log.Debugf("close conntrack connection: %v", closeErr)
			}
			return nil, nil
		}

		events := make(chan nfct.Event, defaultChannelSize)
		errChan, err := conn.Listen(events, 1, []netfilter.NetlinkGroup{
			netfilter.GroupCTNew,
			netfilter.GroupCTDestroy,
		})
		if err != nil {
			log.Warnf("reconnect conntrack listen: %v", err)
			if closeErr := conn.Close(); closeErr != nil {
				log.Debugf("close conntrack connection: %v", closeErr)
			}
			continue
		}

		c.mux.Lock()
		if c.run != run || run.ctx.Err() != nil {
			c.mux.Unlock()
			if closeErr := conn.Close(); closeErr != nil {
				log.Debugf("close conntrack connection: %v", closeErr)
			}
			return nil, nil
		}
		run.conn = conn
		c.mux.Unlock()

		log.Infof("conntrack listener reconnected successfully")

		return events, errChan
	}
}

// Stop stops the connection tracking. This method is idempotent.
func (c *ConnTrack) Stop() {
	conn := c.stopRun()
	if conn == nil {
		return
	}

	log.Info("Stopping conntrack event listening")
	if err := conn.Close(); err != nil {
		log.Errorf("Error closing conntrack connection: %v", err)
	}
}

// Close stops listening for events and cleans up resources
func (c *ConnTrack) Close() error {
	conn := c.stopRun()
	if conn == nil {
		return nil
	}

	if err := conn.Close(); err != nil {
		return fmt.Errorf("close conntrack: %w", err)
	}

	return nil
}

func (c *ConnTrack) stopRun() listener {
	c.mux.Lock()
	defer c.mux.Unlock()

	if c.run == nil {
		return nil
	}

	run := c.run
	c.run = nil
	run.cancel()
	conn := run.conn
	run.conn = nil

	c.RestoreAccounting()
	return conn
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
	case nftypes.ICMP, nftypes.ICMPv6:
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
	addr := c.iface.Address()
	if addr.Network.Contains(srcIP) || addr.Network.Contains(dstIP) {
		return true
	}
	if addr.IPv6Net.IsValid() {
		return addr.IPv6Net.Contains(srcIP) || addr.IPv6Net.Contains(dstIP)
	}
	return false
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
	addr := c.iface.Address()
	switch {
	case addr.IP == srcIP || (addr.IPv6.IsValid() && addr.IPv6 == srcIP):
		return nftypes.Egress
	case addr.IP == dstIP || (addr.IPv6.IsValid() && addr.IPv6 == dstIP):
		return nftypes.Ingress
	case addr.Network.Contains(srcIP) || (addr.IPv6Net.IsValid() && addr.IPv6Net.Contains(srcIP)):
		// netbird network -> resource network
		return nftypes.Ingress
	case addr.Network.Contains(dstIP) || (addr.IPv6Net.IsValid() && addr.IPv6Net.Contains(dstIP)):
		// resource network -> netbird network
		return nftypes.Egress
	}

	return nftypes.DirectionUnknown
}
