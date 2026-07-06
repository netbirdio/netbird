package store

import (
	"maps"
	"math/rand"
	v2 "math/rand/v2"
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
	WindowStart time.Time
	WindowEnd   time.Time
	rnd         *v2.PCG
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

func NewAggregatingMemoryStore() *AggregatingMemory {
	return &AggregatingMemory{WindowStart: time.Now(), Memory: Memory{events: make(map[uuid.UUID]*types.Event)}, rnd: v2.NewPCG(rand.Uint64(), rand.Uint64())}
}

func (am *AggregatingMemory) ResetAggregationWindow() types.FlowEventAggregator {
	am.mux.Lock()
	defer am.mux.Unlock()

	now := time.Now()
	toret := AggregatingMemory{WindowStart: am.WindowStart, WindowEnd: now, Memory: Memory{events: am.events}, rnd: v2.NewPCG(rand.Uint64(), rand.Uint64())}

	am.events = make(map[uuid.UUID]*types.Event)
	am.WindowStart = now

	return &toret
}

type aggregationKey struct {
	srcAddr   netip.Addr
	destAddr  netip.Addr
	destPort  uint16
	direction int
	protocol  uint8
	icmpType  uint8
	unique    uint64 // used to prevent aggregation on non icmp/udp/tcp events
}

func (am *AggregatingMemory) GetAggregatedEvents() []*types.Event {
	am.mux.Lock()
	defer am.mux.Unlock()

	aggregated := make(map[aggregationKey]*types.Event)
	for _, v := range am.events {
		lookupKey := aggregationKey{srcAddr: v.SourceIP, destAddr: v.DestIP, destPort: v.DestPort, direction: int(v.Direction), protocol: uint8(v.Protocol), icmpType: v.ICMPType}
		if _, ok := aggregated[lookupKey]; !ok {
			event := v.Clone()

			switch event.Type {
			case types.TypeStart:
				event.NumOfStarts += 1
			case types.TypeDrop:
				event.NumOfDrops += 1
			case types.TypeEnd:
				event.NumOfEnds += 1
			}
			event.Type = types.TypeUnknown

			// Please note that ICMPCode field isn't propagated by the manager (see flow/proto/flow.pb.go, FlowFields struct)
			// so the field value in an icmp event in the "aggregated" doesn't matter

			event.WindowStart = am.WindowStart
			event.WindowEnd = am.WindowEnd

			if event.Protocol != types.ICMP && event.Protocol != types.ICMPv6 && event.Protocol != types.UDP && event.Protocol != types.TCP {
				lookupKey.unique = am.rnd.Uint64() // to make the lookup key unique so we don't aggregate on it
			}

			aggregated[lookupKey] = event
			continue
		}

		aggregatedEvent := aggregated[lookupKey]
		if aggregatedEvent.Protocol != types.ICMP && aggregatedEvent.Protocol != types.ICMPv6 && aggregatedEvent.Protocol != types.UDP && aggregatedEvent.Protocol != types.TCP {
			continue // we don't aggregate this type of events; shouldn't ever get here
		}

		// track the number of connections, duration?, open and close events?
		aggregatedEvent.RxBytes += v.RxBytes
		aggregatedEvent.RxPackets += v.RxPackets
		aggregatedEvent.TxBytes += v.TxBytes
		aggregatedEvent.TxPackets += v.TxPackets
		switch v.Type {
		case types.TypeStart:
			aggregatedEvent.NumOfStarts += 1
		case types.TypeDrop:
			aggregatedEvent.NumOfDrops += 1
		case types.TypeEnd:
			aggregatedEvent.NumOfEnds += 1
		}
		if aggregatedEvent.Timestamp.Compare(v.Timestamp) > 0 {
			aggregatedEvent.Timestamp = v.Timestamp
			aggregatedEvent.ID = v.ID
			aggregatedEvent.SourcePort = v.SourcePort
		}
		if len(aggregatedEvent.RuleID) == 0 && len(v.RuleID) != 0 {
			aggregatedEvent.RuleID = slices.Clone(v.RuleID)
		}
	}

	return slices.Collect(maps.Values(aggregated)) // could return an iterator instead here
}
