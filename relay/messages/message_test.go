package messages

import (
	"testing"
)

func TestMarshalHelloMsg(t *testing.T) {
	peerID := []byte("abdFAaBcawquEiCMzAabYosuUaGLtSNhKxz+")
	bHello, err := MarshalHelloMsg(peerID, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	receivedPeerID, addition, err := UnmarshalHelloMsg(bHello)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if string(receivedPeerID) != string(peerID) {
		t.Errorf("expected %s, got %s", peerID, receivedPeerID)
	}

	if len(addition) != 0 {
		t.Errorf("expected empty addition, got %v", addition)
	}
}

func TestMarshalAuthMsg(t *testing.T) {
	peerID := []byte("abdFAaBcawquEiCMzAabYosuUaGLtSNhKxz+")
	bHello, err := MarshalAuthMsg(peerID, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	receivedPeerID, addition, err := UnmarshalAuthMsg(bHello)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if string(receivedPeerID) != string(peerID) {
		t.Errorf("expected %s, got %s", peerID, receivedPeerID)
	}

	if len(addition) != 0 {
		t.Errorf("expected empty addition, got %v", addition)
	}
}

func TestMarshalTransportMsg(t *testing.T) {
	peerID := []byte("abdFAaBcawquEiCMzAabYosuUaGLtSNhKxz+")
	payload := []byte("payload")
	msg, err := MarshalTransportMsg(peerID, payload)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	tid, err := UnmarshalTransportID(msg)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if string(tid) != string(peerID) {
		t.Errorf("expected %s, got %s", peerID, tid)
	}

	id, respPayload, err := UnmarshalTransportMsg(msg)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if string(id) != string(peerID) {
		t.Errorf("expected %s, got %s", peerID, id)
	}

	if string(respPayload) != string(payload) {
		t.Errorf("expected %s, got %s", payload, respPayload)
	}
}
