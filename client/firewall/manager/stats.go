package manager

import (
	"encoding/json"
	"net"
	"slices"
	"strconv"
	"sync/atomic"
	"time"
)

const (
	DirectionInbound  Direction = 0
	DirectionOutbound Direction = 1
)

type Direction uint8

func (d Direction) String() string {
	switch d {
	case DirectionInbound:
		return "inbound"
	case DirectionOutbound:
		return "outbound"
	default:
		return "unknown"
	}
}

// FlowStats tracks statistics for an individual connection
type FlowStats struct {
	StartTime  time.Time
	LastSeen   time.Time
	BytesIn    atomic.Uint64
	BytesOut   atomic.Uint64
	PacketsIn  atomic.Uint64
	PacketsOut atomic.Uint64
	Protocol   uint8
	Direction  Direction
	SourceIP   net.IP
	DestIP     net.IP
	SourcePort uint16
	DestPort   uint16
}

func (f *FlowStats) Clone() *FlowStats {
	flowCopy := FlowStats{
		StartTime:  f.StartTime,
		LastSeen:   f.LastSeen,
		Protocol:   f.Protocol,
		Direction:  f.Direction,
		SourceIP:   slices.Clone(f.SourceIP),
		DestIP:     slices.Clone(f.DestIP),
		SourcePort: f.SourcePort,
		DestPort:   f.DestPort,
	}
	flowCopy.BytesIn.Store(f.BytesIn.Load())
	flowCopy.BytesOut.Store(f.BytesOut.Load())
	flowCopy.PacketsIn.Store(f.PacketsIn.Load())
	flowCopy.PacketsOut.Store(f.PacketsOut.Load())

	return &flowCopy
}

// MarshalJSON implements json.Marshaler interface
func (f *FlowStats) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		StartTime  time.Time
		LastSeen   time.Time
		BytesIn    uint64
		BytesOut   uint64
		PacketsIn  uint64
		PacketsOut uint64
		Protocol   Protocol
		Direction  string
		SourceIP   net.IP
		DestIP     net.IP
		SourcePort uint16
		DestPort   uint16
	}{
		StartTime:  f.StartTime,
		LastSeen:   f.LastSeen,
		BytesIn:    f.BytesIn.Load(),
		BytesOut:   f.BytesOut.Load(),
		PacketsIn:  f.PacketsIn.Load(),
		PacketsOut: f.PacketsOut.Load(),
		Protocol:   protoFromInt(f.Protocol),
		Direction:  f.Direction.String(),
		SourceIP:   f.SourceIP,
		DestIP:     f.DestIP,
		SourcePort: f.SourcePort,
		DestPort:   f.DestPort,
	})
}

func protoFromInt(p uint8) Protocol {
	switch p {
	case 6:
		return ProtocolTCP
	case 17:
		return ProtocolUDP
	case 1:
		return ProtocolICMP
	default:
		return Protocol(strconv.Itoa(int(p)))
	}
}
