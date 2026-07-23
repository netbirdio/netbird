package messages

import (
	"testing"
)

func TestDetermineClientMessageTypeRejectsHello(t *testing.T) {
	// The reserved legacy Hello message (type 1) must be rejected by the server.
	msg := []byte{byte(CurrentProtocolVersion), byte(MsgTypeHello)}
	if _, err := DetermineClientMessageType(msg); err == nil {
		t.Fatalf("expected hello message type to be rejected")
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
	if respAddr != address {
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

func TestMarshalTransportBatch(t *testing.T) {
	peerID := HashID("abdFAaBcawquEiCMzAabYosuUaGLtSNhKxz+")
	payloads := [][]byte{
		[]byte("first"),
		[]byte(""),
		[]byte("a slightly longer third payload"),
	}

	frame := TransportBatchHeader(peerID)
	for _, p := range payloads {
		var ok bool
		frame, ok = AppendBatchPayload(frame, p)
		if !ok {
			t.Fatalf("AppendBatchPayload rejected payload of len %d", len(p))
		}
	}

	// The batch frame must route like a transport frame on both sides.
	if mt, err := DetermineClientMessageType(frame); err != nil || mt != MsgTypeTransportBatch {
		t.Fatalf("client msg type = %v (err %v), want %d", mt, err, MsgTypeTransportBatch)
	}
	if mt, err := DetermineServerMessageType(frame); err != nil || mt != MsgTypeTransportBatch {
		t.Fatalf("server msg type = %v (err %v), want %d", mt, err, MsgTypeTransportBatch)
	}
	// The dest peerID lives at the transport offset, so the relay's opaque
	// UnmarshalTransportID/UpdateTransportMsg work unchanged.
	if id, err := UnmarshalTransportID(frame); err != nil || id.String() != peerID.String() {
		t.Fatalf("UnmarshalTransportID = %v (err %v), want %s", id, err, peerID)
	}

	id, got, err := UnmarshalTransportBatch(frame)
	if err != nil {
		t.Fatalf("UnmarshalTransportBatch: %v", err)
	}
	if id.String() != peerID.String() {
		t.Errorf("peerID = %s, want %s", id, peerID)
	}
	if len(got) != len(payloads) {
		t.Fatalf("got %d payloads, want %d", len(got), len(payloads))
	}
	for i := range payloads {
		if string(got[i]) != string(payloads[i]) {
			t.Errorf("payload %d = %q, want %q", i, got[i], payloads[i])
		}
	}

	// A truncated frame (length prefix promises more than is present) must error,
	// not panic or over-read.
	truncated := frame[:len(frame)-3]
	if _, _, err := UnmarshalTransportBatch(truncated); err == nil {
		t.Errorf("expected error on truncated batch frame")
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
