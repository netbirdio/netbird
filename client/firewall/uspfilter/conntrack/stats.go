package conntrack

import (
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
)

// Stats represents connection tracking statistics
type Stats struct {
	TotalConnsCreated   atomic.Uint64
	TotalConnsTimedOut  atomic.Uint64
	TotalPacketsDropped atomic.Uint64
	ActiveConns         atomic.Int64

	TCPConns  atomic.Int64
	UDPConns  atomic.Int64
	ICMPConns atomic.Int64

	TCPStateStats struct {
		SynReceived   atomic.Uint64
		Established   atomic.Uint64
		FinWait       atomic.Uint64
		TimeWait      atomic.Uint64
		InvalidStates atomic.Uint64
	}

	PacketStats struct {
		TCPPackets  atomic.Uint64
		UDPPackets  atomic.Uint64
		ICMPPackets atomic.Uint64
	}

	flowMutex sync.RWMutex
	flows     map[ConnKey]*fw.FlowStats
}

// NewStats creates a new Stats instance
func NewStats() *Stats {
	return &Stats{
		flows: make(map[ConnKey]*fw.FlowStats),
	}
}

// TrackNewConnection records a new connection
func (s *Stats) TrackNewConnection(proto uint8, srcIP net.IP, dstIP net.IP, srcPort, dstPort uint16, direction fw.Direction) {
	s.TotalConnsCreated.Add(1)
	s.ActiveConns.Add(1)

	switch proto {
	case 6: // TCP
		s.TCPConns.Add(1)
	case 17: // UDP
		s.UDPConns.Add(1)
	case 1: // ICMP
		s.ICMPConns.Add(1)
	}

	flow := &fw.FlowStats{
		StartTime:  time.Now(),
		LastSeen:   time.Now(),
		Protocol:   proto,
		Direction:  direction,
		SourceIP:   slices.Clone(srcIP),
		DestIP:     slices.Clone(dstIP),
		SourcePort: srcPort,
		DestPort:   dstPort,
	}

	key := makeConnKey(srcIP, dstIP, srcPort, dstPort)
	s.flowMutex.Lock()
	s.flows[key] = flow
	s.flowMutex.Unlock()
}

// TrackConnectionClosed records a connection closure
func (s *Stats) TrackConnectionClosed(proto uint8, timedOut bool, key ConnKey) {
	s.ActiveConns.Add(-1)

	if timedOut {
		s.TotalConnsTimedOut.Add(1)
	}

	switch proto {
	case 6: // TCP
		s.TCPConns.Add(-1)
	case 17: // UDP
		s.UDPConns.Add(-1)
	case 1: // ICMP
		s.ICMPConns.Add(-1)
	}

	s.flowMutex.Lock()
	delete(s.flows, key)
	s.flowMutex.Unlock()
}

// TrackPacket records packet statistics
func (s *Stats) TrackPacket(proto uint8, dropped bool, bytes uint64, isInbound bool, key ConnKey) {
	if dropped {
		s.TotalPacketsDropped.Add(1)
		return
	}

	switch proto {
	case 6: // TCP
		s.PacketStats.TCPPackets.Add(1)
	case 17: // UDP
		s.PacketStats.UDPPackets.Add(1)
	case 1: // ICMP
		s.PacketStats.ICMPPackets.Add(1)
	}

	s.flowMutex.RLock()
	if flow, exists := s.flows[key]; exists {
		if isInbound {
			flow.BytesIn.Add(bytes)
			flow.PacketsIn.Add(1)
		} else {
			flow.BytesOut.Add(bytes)
			flow.PacketsOut.Add(1)
		}
		flow.LastSeen = time.Now()
	}
	s.flowMutex.RUnlock()
}

// TrackTCPState updates TCP state statistics
func (s *Stats) TrackTCPState(newState TCPState) {
	switch newState {
	case TCPStateSynReceived:
		s.TCPStateStats.SynReceived.Add(1)
	case TCPStateEstablished:
		s.TCPStateStats.Established.Add(1)
	case TCPStateFinWait1, TCPStateFinWait2:
		s.TCPStateStats.FinWait.Add(1)
	case TCPStateTimeWait:
		s.TCPStateStats.TimeWait.Add(1)
	default:
		s.TCPStateStats.InvalidStates.Add(1)
	}
}

// GetFlowSnapshot returns a copy of current flow statistics if enabled
func (s *Stats) GetFlowSnapshot() []*fw.FlowStats {
	s.flowMutex.RLock()
	defer s.flowMutex.RUnlock()

	snapshot := make([]*fw.FlowStats, 0, len(s.flows))
	for _, flow := range s.flows {
		snapshot = append(snapshot, flow.Clone())
	}
	return snapshot
}

// CleanupFlows removes flow entries older than the specified duration if enabled
func (s *Stats) CleanupFlows(maxAge time.Duration) {
	threshold := time.Now().Add(-maxAge)

	s.flowMutex.Lock()
	defer s.flowMutex.Unlock()

	for key, flow := range s.flows {
		if flow.LastSeen.Before(threshold) {
			delete(s.flows, key)
		}
	}
}
