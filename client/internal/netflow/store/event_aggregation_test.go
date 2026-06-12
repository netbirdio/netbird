package store

import (
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netbirdio/netbird/client/internal/netflow/types"
	"github.com/stretchr/testify/assert"
)

var random = rand.New(rand.NewSource(time.Now().UnixNano()))

func TestFlowAggregation(t *testing.T) {
	var protocols = []types.Protocol{types.ICMP, types.ICMPv6, types.TCP, types.UDP}
	var tests = []struct {
		description string
		eventTypes  []types.Type
	}{
		{
			description: "start and stop",
			eventTypes:  []types.Type{types.TypeStart, types.TypeEnd},
		},
		{
			description: "start and drop",
			eventTypes:  []types.Type{types.TypeStart, types.TypeDrop},
		},
		{
			description: "start only",
			eventTypes:  []types.Type{types.TypeStart},
		},
		{
			description: "drop only",
			eventTypes:  []types.Type{types.TypeDrop},
		}}

	for _, protocol := range protocols {
		for _, tt := range tests {
			t.Run(tt.description+" "+protocol.String(), func(t *testing.T) {
				store := NewAggregatingMemoryStore()
				allExpected := make([]*types.Event, 0)

				for i := 0; i < 2; i++ {
					inEvents, expected := generateEvents(tt.eventTypes, protocol, types.Ingress, 0)
					for _, e := range inEvents {
						store.StoreEvent(e)
					}
					allExpected = append(allExpected, expected)
				}

				events := store.GetAggregatedEvents()
				assert.ElementsMatch(t, events, allExpected)
			})
		}
	}
}

func TestIcmpEventAggregation(t *testing.T) {
	var protocols = []types.Protocol{types.ICMP, types.ICMPv6}
	var icmpTypes = []uint8{1, 2, 3}

	var tests = []struct {
		description string
		eventTypes  []types.Type
	}{
		{
			description: "start and stop",
			eventTypes:  []types.Type{types.TypeStart, types.TypeEnd},
		},
		{
			description: "start and drop",
			eventTypes:  []types.Type{types.TypeStart, types.TypeDrop},
		},
		{
			description: "start only",
			eventTypes:  []types.Type{types.TypeStart},
		},
		{
			description: "drop only",
			eventTypes:  []types.Type{types.TypeDrop},
		}}

	for _, protocol := range protocols {
		for _, tt := range tests {
			t.Run(tt.description+" "+protocol.String(), func(t *testing.T) {
				store := NewAggregatingMemoryStore()
				allExpected := make([]*types.Event, 0)
				for _, icmpType := range icmpTypes {
					events, expected := generateEvents(tt.eventTypes, protocol, types.Ingress, icmpType)
					for _, e := range events {
						store.StoreEvent(e)
					}
					allExpected = append(allExpected, expected)
				}
				aggregatedEvents := store.GetAggregatedEvents()
				assert.Len(t, aggregatedEvents, len(allExpected))
				assert.ElementsMatch(t, aggregatedEvents, allExpected)
			})
		}
	}
}

func ipAddr(a string) netip.Addr {
	addr, _ := netip.ParseAddr(a)
	return addr
}

func generateEvents(eventTypes []types.Type, protocol types.Protocol, direction types.Direction, icmpType uint8) ([]*types.Event, *types.Event) {
	var rxPackets, txPackets, rxBytes, txBytes uint64
	inEvents := make([]*types.Event, 0)
	ts := time.Now()
	flowId := uuid.New()
	srcIp := ipAddr("1.1.1.1")
	srcPort := uint16(random.Uint32() >> 16)
	dstIp := ipAddr("2.2.2.2")
	dstPort := uint16(random.Uint32() >> 16)

	for idx, eventType := range eventTypes {
		e := &types.Event{
			ID:        uuid.New(),
			Timestamp: ts.Add(time.Duration(idx) * time.Second),
			EventFields: types.EventFields{
				FlowID:           flowId,
				Type:             eventType,
				Protocol:         protocol,
				RuleID:           []byte("rule-id-1"),
				Direction:        direction,
				SourceIP:         srcIp,
				SourcePort:       srcPort,
				DestIP:           dstIp,
				DestPort:         dstPort,
				SourceResourceID: []byte("source-resource-id"),
				DestResourceID:   []byte("dest-resource-id"),
				RxPackets:        random.Uint64(),
				TxPackets:        random.Uint64(),
				RxBytes:          random.Uint64(),
				TxBytes:          random.Uint64(),
			}}
		rxBytes += e.RxBytes
		txBytes += e.TxBytes
		rxPackets += e.RxPackets
		txPackets += e.TxPackets
		inEvents = append(inEvents, e)
		if protocol == types.ICMP || protocol == types.ICMPv6 {
			e.ICMPType = icmpType
		}
	}

	var start, end, drop uint64
	for _, eventType := range eventTypes {
		switch eventType {
		case types.TypeStart:
			start += 1
		case types.TypeDrop:
			drop += 1
		case types.TypeEnd:
			end += 1
		}
	}
	aggregatedEvent := &types.Event{
		ID:        inEvents[0].ID,
		Timestamp: inEvents[0].Timestamp,
		EventFields: types.EventFields{
			FlowID:           flowId,
			Type:             inEvents[0].Type,
			Protocol:         inEvents[0].Protocol,
			RuleID:           []byte("rule-id-1"),
			Direction:        inEvents[0].Direction,
			SourceIP:         srcIp,
			SourcePort:       srcPort,
			DestIP:           dstIp,
			DestPort:         dstPort,
			SourceResourceID: []byte("source-resource-id"),
			DestResourceID:   []byte("dest-resource-id"),
			RxPackets:        rxPackets,
			TxPackets:        txPackets,
			RxBytes:          rxBytes,
			TxBytes:          txBytes,
			NumOfStarts:      start,
			NumOfEnds:        end,
			NumOfDrops:       drop,
		}}
	if protocol == types.ICMP || protocol == types.ICMPv6 {
		aggregatedEvent.ICMPType = icmpType
	}

	return inEvents, aggregatedEvent
}
