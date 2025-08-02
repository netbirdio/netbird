package messages

import (
	"bytes"
	"testing"
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

	msgs, err := MarshalSubPeerStateMsg(ids)
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
	_, err := MarshalSubPeerStateMsg([]PeerID{})
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

	msgs, err := MarshalPeersOnline(ids)
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
	_, err := MarshalPeersOnline([]PeerID{})
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

	msgs, err := MarshalPeersWentOffline(ids)
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
	_, err := MarshalPeersWentOffline([]PeerID{})
	if err == nil {
		t.Errorf("expected error for empty input")
	}
}
