package messages

import (
	"testing"
)

func TestMarshalHelloMsg(t *testing.T) {
	peerID := HashID("abdFAaBcawquEiCMzAabYosuUaGLtSNhKxz+")
	msg, err := MarshalHelloMsg(peerID, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	msgType, err := DetermineClientMessageType(msg)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if msgType != MsgTypeHello {
		t.Errorf("expected %d, got %d", MsgTypeHello, msgType)
	}

	receivedPeerID, _, err := UnmarshalHelloMsg(msg)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if receivedPeerID.String() != peerID.String() {
		t.Errorf("expected %s, got %s", peerID, receivedPeerID)
	}
}

func TestMarshalAuthMsg(t *testing.T) {
	peerID := HashID("abdFAaBcawquEiCMzAabYosuUaGLtSNhKxz+")
	msg, err := MarshalAuthMsg(peerID, []byte{})
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	msgType, err := DetermineClientMessageType(msg)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if msgType != MsgTypeAuth {
		t.Errorf("expected %d, got %d", MsgTypeAuth, msgType)
	}

	receivedPeerID, _, err := UnmarshalAuthMsg(msg)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if receivedPeerID.String() != peerID.String() {
		t.Errorf("expected %s, got %s", peerID, receivedPeerID)
	}
}

func TestMarshalAuthResponse(t *testing.T) {
	address := "myaddress"
	msg, err := MarshalAuthResponse(address)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	msgType, err := DetermineServerMessageType(msg)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if msgType != MsgTypeAuthResponse {
		t.Errorf("expected %d, got %d", MsgTypeAuthResponse, msgType)
	}

	respAddr, err := UnmarshalAuthResponse(msg)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if string(respAddr) != address {
		t.Errorf("expected %s, got %s", address, respAddr)
	}
}

func TestMarshalTransportMsg(t *testing.T) {
	peerID := HashID("abdFAaBcawquEiCMzAabYosuUaGLtSNhKxz+")
	payload := []byte("payload")
	msg, err := MarshalTransportMsg(peerID, payload)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	msgType, err := DetermineClientMessageType(msg)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if msgType != MsgTypeTransport {
		t.Errorf("expected %d, got %d", MsgTypeTransport, msgType)
	}

	uPeerID, err := UnmarshalTransportID(msg)
	if err != nil {
		t.Fatalf("failed to unmarshal transport id: %v", err)
	}

	if uPeerID.String() != peerID.String() {
		t.Errorf("expected %s, got %s", peerID, uPeerID)
	}

	id, respPayload, err := UnmarshalTransportMsg(msg)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if id.String() != peerID.String() {
		t.Errorf("expected: '%s', got: '%s'", peerID, id)
	}

	if string(respPayload) != string(payload) {
		t.Errorf("expected %s, got %s", payload, respPayload)
	}
}

func TestMarshalHealthcheck(t *testing.T) {
	msg := MarshalHealthcheck()

	_, err := ValidateVersion(msg)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	msgType, err := DetermineServerMessageType(msg)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if msgType != MsgTypeHealthCheck {
		t.Errorf("expected %d, got %d", MsgTypeHealthCheck, msgType)
	}
}
