package store

import (
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/netbirdio/netbird/client/internal/netflow/types"
)

func NewMemoryStore() *Memory {
	return &Memory{
		events: make(map[uuid.UUID]*types.Event),
	}
}

type Memory struct {
	mux    sync.Mutex
	events map[uuid.UUID]*types.Event
}

type AggregatingMemory struct {
	Memory
}

func (m *Memory) StoreEvent(event *types.Event) {
	m.mux.Lock()
	defer m.mux.Unlock()
	m.events[event.ID] = event
}

func (m *Memory) Close() {
	m.mux.Lock()
	defer m.mux.Unlock()
	clear(m.events)
}

func (m *Memory) GetEvents() []*types.Event {
	m.mux.Lock()
	defer m.mux.Unlock()
	events := make([]*types.Event, 0, len(m.events))
	for _, event := range m.events {
		events = append(events, event)
	}
	return events
}

func (m *Memory) DeleteEvents(ids []uuid.UUID) {
	m.mux.Lock()
	defer m.mux.Unlock()
	for _, id := range ids {
		delete(m.events, id)
	}
}

func (am *AggregatingMemory) StartAggregationWindow() *AggregatingMemory {
	am.mux.Lock()
	defer am.mux.Unlock()

	toret := AggregatingMemory{Memory: Memory{events: am.Memory.events}}
	am.events = make(map[uuid.UUID]*types.Event)

	return &toret
}

type aggregationKey struct {
	destAddr netip.Addr
	destPort uint16
	protocol uint8
	icmpType uint8
	ts       int64 // used to prevent aggregation on non icmp/udp/tcp events
}

func (am *AggregatingMemory) GetAggregatedEvents() []*types.Event {
	aggregated := make(map[aggregationKey]*types.Event)
	for _, v := range am.events {
		lookupKey := aggregationKey{destAddr: v.DestIP, destPort: v.DestPort, protocol: uint8(v.Protocol), icmpType: v.ICMPCode}
		if aggregatedEvent, ok := aggregated[lookupKey]; ok {
			switch aggregatedEvent.Protocol {
			case types.ICMP, types.ICMPv6, types.UDP, types.TCP:
				aggregatedEvent.RxBytes += v.RxBytes
				aggregatedEvent.RxPackets += v.RxPackets
				aggregatedEvent.TxBytes += v.TxBytes
				aggregatedEvent.TxPackets += v.TxPackets
				if aggregatedEvent.Timestamp.Compare(v.Timestamp) < 0 {
					aggregatedEvent.Timestamp = v.Timestamp
				}
				// do we aggregate icmp by code?
			default:
				// shouldn't get here
			}
		} else {
			switch v.Protocol {
			case types.ICMP, types.ICMPv6, types.TCP, types.UDP:
				aggregated[lookupKey] = v
			default:
				lookupKey.ts = time.Now().UnixNano()
				aggregated[lookupKey] = v
			}
		}
	}

	return slices.Collect(maps.Values(aggregated)) // could return an iterator instead here
}
