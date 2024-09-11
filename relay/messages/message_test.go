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

	receivedPeerID, _, err := UnmarshalHelloMsg(bHello[SizeOfProtoHeader:])
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if string(receivedPeerID) != string(peerID) {
		t.Errorf("expected %s, got %s", peerID, receivedPeerID)
	}
}

func TestMarshalAuthMsg(t *testing.T) {
	peerID := []byte("abdFAaBcawquEiCMzAabYosuUaGLtSNhKxz+")
	bHello, err := MarshalAuthMsg(peerID, []byte{})
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	receivedPeerID, _, err := UnmarshalAuthMsg(bHello[SizeOfProtoHeader:])
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if string(receivedPeerID) != string(peerID) {
		t.Errorf("expected %s, got %s", peerID, receivedPeerID)
	}
}

func TestMarshalTransportMsg(t *testing.T) {
	peerID := []byte("abdFAaBcawquEiCMzAabYosuUaGLtSNhKxz+")
	payload := []byte("payload")
	msg, err := MarshalTransportMsg(peerID, payload)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	id, respPayload, err := UnmarshalTransportMsg(msg[SizeOfProtoHeader:])
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
