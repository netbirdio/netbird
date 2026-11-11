package messages

import (
	"bytes"
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testPeerCount = 10
)

// Helper function to generate test PeerIDs
func generateTestPeerIDs(n int) []PeerID {
	ids := make([]PeerID, n)
	for i := 0; i < n; i++ {
		for j := 0; j < peerIDSize; j++ {
			ids[i][j] = byte(i + j)
		}
	}
	return ids
}

// Helper function to compare slices of PeerID
func peerIDEqual(a, b []PeerID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i][:], b[i][:]) {
			return false
		}
	}
	return true
}

func TestMarshalUnmarshalSubPeerState(t *testing.T) {
	ids := generateTestPeerIDs(testPeerCount)

	msgs, err := MarshalSubPeerStateMsg(ids, MaxMessageSize)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var allIDs []PeerID
	for _, msg := range msgs {
		decoded, err := UnmarshalSubPeerStateMsg(msg)
		if err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}
		allIDs = append(allIDs, decoded...)
	}

	if !peerIDEqual(ids, allIDs) {
		t.Errorf("expected %v, got %v", ids, allIDs)
	}
}

func TestMarshalSubPeerState_EmptyInput(t *testing.T) {
	_, err := MarshalSubPeerStateMsg([]PeerID{}, MaxMessageSize)
	if err == nil {
		t.Errorf("expected error for empty input")
	}
}

func TestUnmarshalSubPeerState_Invalid(t *testing.T) {
	// Too short
	_, err := UnmarshalSubPeerStateMsg([]byte{1})
	if err == nil {
		t.Errorf("expected error for short input")
	}

	// Misaligned length
	buf := make([]byte, sizeOfProtoHeader+1)
	_, err = UnmarshalSubPeerStateMsg(buf)
	if err == nil {
		t.Errorf("expected error for misaligned input")
	}
}

func TestMarshalUnmarshalPeersOnline(t *testing.T) {
	ids := generateTestPeerIDs(testPeerCount)

	msgs, err := MarshalPeersOnline(ids, MaxMessageSize)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var allIDs []PeerID
	for _, msg := range msgs {
		decoded, err := UnmarshalPeersOnlineMsg(msg)
		if err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}
		allIDs = append(allIDs, decoded...)
	}

	if !peerIDEqual(ids, allIDs) {
		t.Errorf("expected %v, got %v", ids, allIDs)
	}
}

func TestMarshalPeersOnline_EmptyInput(t *testing.T) {
	_, err := MarshalPeersOnline([]PeerID{}, MaxMessageSize)
	if err == nil {
		t.Errorf("expected error for empty input")
	}
}

func TestUnmarshalPeersOnline_Invalid(t *testing.T) {
	_, err := UnmarshalPeersOnlineMsg([]byte{1})
	if err == nil {
		t.Errorf("expected error for short input")
	}
}

func TestMarshalUnmarshalPeersWentOffline(t *testing.T) {
	ids := generateTestPeerIDs(testPeerCount)

	msgs, err := MarshalPeersWentOffline(ids, MaxMessageSize)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var allIDs []PeerID
	for _, msg := range msgs {
		// MarshalPeersWentOffline shares no unmarshal function, so reuse PeersOnline
		decoded, err := UnmarshalPeersOnlineMsg(msg)
		if err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}
		allIDs = append(allIDs, decoded...)
	}

	if !peerIDEqual(ids, allIDs) {
		t.Errorf("expected %v, got %v", ids, allIDs)
	}
}

func TestMarshalPeersWentOffline_EmptyInput(t *testing.T) {
	_, err := MarshalPeersWentOffline([]PeerID{}, MaxMessageSize)
	if err == nil {
		t.Errorf("expected error for empty input")
	}
}

func TestMarshalPeerIDs_SplitsByMaxMessageSize(t *testing.T) {
	marshalers := map[string]func([]PeerID, int) ([][]byte, error){
		"subscribe":    MarshalSubPeerStateMsg,
		"unsubscribe":  MarshalUnsubPeerStateMsg,
		"online":       MarshalPeersOnline,
		"went offline": MarshalPeersWentOffline,
		"encoder online": func(ids []PeerID, maxMsgSize int) ([][]byte, error) {
			return NewEncoder(CurrentProtocolVersion, maxMsgSize).PeersOnline(ids)
		},
		"encoder went offline": func(ids []PeerID, maxMsgSize int) ([][]byte, error) {
			return NewEncoder(CurrentProtocolVersion, maxMsgSize).PeersWentOffline(ids)
		},
	}
	limits := []struct {
		maxMsgSize      int
		peersPerMessage int
	}{
		{maxMsgSize: sizeOfProtoHeader + peerIDSize, peersPerMessage: 1},
		{maxMsgSize: 1195, peersPerMessage: 33},
		{maxMsgSize: MaxMessageSize, peersPerMessage: 244},
		// A transport limit above the protocol limit must not produce messages the receiver cannot read.
		{maxMsgSize: MaxMessageSize + 1000, peersPerMessage: 244},
	}

	for name, marshal := range marshalers {
		for _, limit := range limits {
			effectiveSize := min(limit.maxMsgSize, MaxMessageSize)
			for _, count := range []int{1, limit.peersPerMessage, limit.peersPerMessage + 1, 2*limit.peersPerMessage + 1} {
				t.Run(fmt.Sprintf("%s/limit %d/%d ids", name, limit.maxMsgSize, count), func(t *testing.T) {
					ids := generateTestPeerIDs(count)

					msgs, err := marshal(ids, limit.maxMsgSize)
					require.NoError(t, err)
					wantMsgs := (count + limit.peersPerMessage - 1) / limit.peersPerMessage
					assert.Len(t, msgs, wantMsgs, "peer IDs must be split into full messages")

					var decoded []PeerID
					for _, msg := range msgs {
						assert.LessOrEqual(t, len(msg), effectiveSize, "message must respect the max message size")
						chunk, err := unmarshalPeerIDs(msg)
						require.NoError(t, err)
						decoded = append(decoded, chunk...)
					}
					assert.Equal(t, ids, decoded, "all peer IDs must survive the split in order")
				})
			}
		}
	}
}

func TestMarshalPeerIDs_MaxMessageSizeTooSmall(t *testing.T) {
	ids := generateTestPeerIDs(testPeerCount)

	// math.MinInt and its neighbor wrap around to a huge positive size once the header is subtracted.
	for _, maxMsgSize := range []int{math.MinInt, math.MinInt + 1, -1, 0, sizeOfProtoHeader, sizeOfProtoHeader + peerIDSize - 1} {
		_, err := MarshalPeersOnline(ids, maxMsgSize)
		assert.Error(t, err, "max message size %d cannot hold a peer ID", maxMsgSize)
	}
}
