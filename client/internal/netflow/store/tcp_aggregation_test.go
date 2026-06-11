package store

import (
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netbirdio/netbird/client/internal/netflow/types"
	"github.com/stretchr/testify/assert"
)

var pregeneratedUUIDs = func() []uuid.UUID {
	toret := make([]uuid.UUID, 0)
	for range make([]int, 10) {
		toret = append(toret, uuid.New())
	}
	return toret
}()

func TestFlowAggregation(t *testing.T) {
	var protocols = []types.Protocol{types.ICMP, types.ICMPv6, types.TCP, types.UDP}
	var tests = []struct {
		description string
		events      []*types.Event
		expected    []*types.Event
	}{
		{
			description: "start and stop",
			events: []*types.Event{
				{
					ID:        pregeneratedUUIDs[0],
					Timestamp: time.Unix(100, 100),
					EventFields: types.EventFields{
						FlowID:           pregeneratedUUIDs[1],
						Type:             types.TypeStart,
						RuleID:           []byte("rule-id-1"),
						Direction:        types.Egress,
						SourceIP:         ipAddr("1.1.1.1"),
						SourcePort:       1234,
						DestIP:           ipAddr("2.2.2.2"),
						DestPort:         443,
						SourceResourceID: []byte("source-resource-id"),
						DestResourceID:   []byte("dest-resource-id"),
						RxPackets:        10,
						TxPackets:        20,
						RxBytes:          10000,
						TxBytes:          20000,
					}},
				{
					ID:        pregeneratedUUIDs[2],
					Timestamp: time.Unix(100, 100).Add(time.Second),
					EventFields: types.EventFields{
						FlowID:           pregeneratedUUIDs[1],
						Type:             types.TypeEnd,
						RuleID:           []byte("rule-id-1"),
						Direction:        types.Egress,
						SourceIP:         ipAddr("1.1.1.1"),
						SourcePort:       1234,
						DestIP:           ipAddr("2.2.2.2"),
						DestPort:         443,
						SourceResourceID: []byte("source-resource-id"),
						DestResourceID:   []byte("dest-resource-id"),
						RxPackets:        30,
						TxPackets:        40,
						RxBytes:          30000,
						TxBytes:          40000,
					}},
			},
			expected: []*types.Event{
				{
					ID:        pregeneratedUUIDs[0],
					Timestamp: time.Unix(100, 100),
					EventFields: types.EventFields{
						FlowID:           pregeneratedUUIDs[1],
						Type:             types.TypeStart,
						RuleID:           []byte("rule-id-1"),
						Direction:        types.Egress,
						SourceIP:         ipAddr("1.1.1.1"),
						SourcePort:       1234,
						DestIP:           ipAddr("2.2.2.2"),
						DestPort:         443,
						SourceResourceID: []byte("source-resource-id"),
						DestResourceID:   []byte("dest-resource-id"),
						RxPackets:        40,
						TxPackets:        60,
						RxBytes:          40000,
						TxBytes:          60000,
						NumOfStarts:      1,
						NumOfEnds:        1,
						NumOfDrops:       0,
					}},
			},
		},
		{
			description: "start and drop",
			events: []*types.Event{
				{
					ID:        pregeneratedUUIDs[0],
					Timestamp: time.Unix(100, 100),
					EventFields: types.EventFields{
						FlowID:           pregeneratedUUIDs[1],
						Type:             types.TypeStart,
						RuleID:           []byte("rule-id-1"),
						Direction:        types.Egress,
						SourceIP:         ipAddr("1.1.1.1"),
						SourcePort:       1234,
						DestIP:           ipAddr("2.2.2.2"),
						DestPort:         443,
						SourceResourceID: []byte("source-resource-id"),
						DestResourceID:   []byte("dest-resource-id"),
						RxPackets:        10,
						TxPackets:        20,
						RxBytes:          10000,
						TxBytes:          20000,
					}},
				{
					ID:        pregeneratedUUIDs[2],
					Timestamp: time.Unix(100, 100).Add(time.Second),
					EventFields: types.EventFields{
						FlowID:           pregeneratedUUIDs[1],
						Type:             types.TypeDrop,
						RuleID:           []byte("rule-id-1"),
						Direction:        types.Egress,
						SourceIP:         ipAddr("1.1.1.1"),
						SourcePort:       1234,
						DestIP:           ipAddr("2.2.2.2"),
						DestPort:         443,
						SourceResourceID: []byte("source-resource-id"),
						DestResourceID:   []byte("dest-resource-id"),
						RxPackets:        30,
						TxPackets:        40,
						RxBytes:          30000,
						TxBytes:          40000,
					}},
			},
			expected: []*types.Event{
				{
					ID:        pregeneratedUUIDs[0],
					Timestamp: time.Unix(100, 100),
					EventFields: types.EventFields{
						FlowID:           pregeneratedUUIDs[1],
						Type:             types.TypeStart,
						RuleID:           []byte("rule-id-1"),
						Direction:        types.Egress,
						SourceIP:         ipAddr("1.1.1.1"),
						SourcePort:       1234,
						DestIP:           ipAddr("2.2.2.2"),
						DestPort:         443,
						SourceResourceID: []byte("source-resource-id"),
						DestResourceID:   []byte("dest-resource-id"),
						RxPackets:        40,
						TxPackets:        60,
						RxBytes:          40000,
						TxBytes:          60000,
						NumOfStarts:      1,
						NumOfEnds:        0,
						NumOfDrops:       1,
					}},
			},
		},
		{
			description: "start only",
			events: []*types.Event{
				{
					ID:        pregeneratedUUIDs[0],
					Timestamp: time.Unix(100, 100),
					EventFields: types.EventFields{
						FlowID:           pregeneratedUUIDs[1],
						Type:             types.TypeStart,
						RuleID:           []byte("rule-id-1"),
						Direction:        types.Egress,
						SourceIP:         ipAddr("1.1.1.1"),
						SourcePort:       1234,
						DestIP:           ipAddr("2.2.2.2"),
						DestPort:         443,
						SourceResourceID: []byte("source-resource-id"),
						DestResourceID:   []byte("dest-resource-id"),
						RxPackets:        10,
						TxPackets:        20,
						RxBytes:          10000,
						TxBytes:          20000,
					}},
			},
			expected: []*types.Event{
				{
					ID:        pregeneratedUUIDs[0],
					Timestamp: time.Unix(100, 100),
					EventFields: types.EventFields{
						FlowID:           pregeneratedUUIDs[1],
						Type:             types.TypeStart,
						RuleID:           []byte("rule-id-1"),
						Direction:        types.Egress,
						SourceIP:         ipAddr("1.1.1.1"),
						SourcePort:       1234,
						DestIP:           ipAddr("2.2.2.2"),
						DestPort:         443,
						SourceResourceID: []byte("source-resource-id"),
						DestResourceID:   []byte("dest-resource-id"),
						RxPackets:        10,
						TxPackets:        20,
						RxBytes:          10000,
						TxBytes:          20000,
						NumOfStarts:      1,
						NumOfEnds:        0,
						NumOfDrops:       0,
					}},
			},
		},
		{
			description: "drop only",
			events: []*types.Event{
				{
					ID:        pregeneratedUUIDs[2],
					Timestamp: time.Unix(100, 100).Add(time.Second),
					EventFields: types.EventFields{
						FlowID:           pregeneratedUUIDs[1],
						Type:             types.TypeDrop,
						RuleID:           []byte("rule-id-1"),
						Direction:        types.Egress,
						SourceIP:         ipAddr("1.1.1.1"),
						SourcePort:       1234,
						DestIP:           ipAddr("2.2.2.2"),
						DestPort:         443,
						SourceResourceID: []byte("source-resource-id"),
						DestResourceID:   []byte("dest-resource-id"),
						RxPackets:        30,
						TxPackets:        40,
						RxBytes:          30000,
						TxBytes:          40000,
					}},
			},
			expected: []*types.Event{
				{
					ID:        pregeneratedUUIDs[2],
					Timestamp: time.Unix(100, 100).Add(time.Second),
					EventFields: types.EventFields{
						FlowID:           pregeneratedUUIDs[1],
						Type:             types.TypeDrop,
						RuleID:           []byte("rule-id-1"),
						Direction:        types.Egress,
						SourceIP:         ipAddr("1.1.1.1"),
						SourcePort:       1234,
						DestIP:           ipAddr("2.2.2.2"),
						DestPort:         443,
						SourceResourceID: []byte("source-resource-id"),
						DestResourceID:   []byte("dest-resource-id"),
						RxPackets:        30,
						TxPackets:        40,
						RxBytes:          30000,
						TxBytes:          40000,
						NumOfStarts:      0,
						NumOfEnds:        0,
						NumOfDrops:       1,
					}},
			},
		}}

	for _, protocol := range protocols {
		for _, tt := range tests {
			t.Run(tt.description+" "+protocol.String(), func(t *testing.T) {
				store := NewAggregatingMemoryStore()
				for _, e := range tt.events {
					e.Protocol = protocol
					store.StoreEvent(e)
				}
				for _, e := range tt.expected {
					e.Protocol = protocol
				}
				events := store.GetAggregatedEvents()
				assert.Len(t, events, len(tt.expected))
				assert.ElementsMatch(t, events, tt.expected)
			})
		}
	}
}

func ipAddr(a string) netip.Addr {
	addr, _ := netip.ParseAddr(a)
	return addr
}
