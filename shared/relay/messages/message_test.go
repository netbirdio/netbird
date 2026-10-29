package messages

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestReadVersion(t *testing.T) {
	_, err := ReadVersion([]byte{byte(ProtocolV1)})
	assert.ErrorIs(t, err, ErrInvalidMessageLength, "a header needs two bytes")

	_, err = ReadVersion([]byte{0, byte(MsgTypeAuth)})
	assert.ErrorIs(t, err, ErrUnsupportedVersion, "version zero is invalid")

	for _, version := range []ProtocolVersion{1, 2, 128, 255} {
		got, err := ReadVersion([]byte{byte(version), byte(MsgTypeAuth)})
		require.NoError(t, err)
		assert.Equal(t, version, got, "the advertised version must be returned unchanged")
	}
}

func TestSelectVersion(t *testing.T) {
	assert.Equal(t, ProtocolV1, SelectVersion(1, 1), "equal versions select themselves")
	assert.Equal(t, ProtocolV1, SelectVersion(2, 1), "a higher advertised version selects the server maximum")
	assert.Equal(t, ProtocolV1, SelectVersion(255, 1), "the highest advertised version selects the server maximum")
	assert.Equal(t, ProtocolVersion(2), SelectVersion(2, 3), "a lower advertised version selects itself")
	assert.Equal(t, ProtocolVersion(2), SelectVersion(3, 2), "a higher advertised version selects the server maximum")
}

func TestValidateVersionAcceptsOnlyCurrent(t *testing.T) {
	_, err := ValidateVersion([]byte{byte(CurrentProtocolVersion), byte(MsgTypeHealthCheck)})
	require.NoError(t, err)

	_, err = ValidateVersion([]byte{byte(CurrentProtocolVersion) + 1, byte(MsgTypeHealthCheck)})
	assert.ErrorIs(t, err, ErrUnsupportedVersion, "the client build accepts only its own version")

	_, err = ValidateVersion([]byte{0, byte(MsgTypeHealthCheck)})
	assert.ErrorIs(t, err, ErrUnsupportedVersion, "version zero is invalid")
}

func TestValidateConnectionVersion(t *testing.T) {
	require.NoError(t, ValidateConnectionVersion([]byte{1, byte(MsgTypeHealthCheck)}, ProtocolV1))
	assert.ErrorIs(t, ValidateConnectionVersion([]byte{2, byte(MsgTypeHealthCheck)}, ProtocolV1), ErrUnsupportedVersion, "a frame must carry the selected version")
	assert.ErrorIs(t, ValidateConnectionVersion([]byte{1, byte(MsgTypeHealthCheck)}, 2), ErrUnsupportedVersion, "a frame below the selected version is rejected too")
	assert.ErrorIs(t, ValidateConnectionVersion([]byte{0, byte(MsgTypeHealthCheck)}, ProtocolV1), ErrUnsupportedVersion, "version zero is invalid")
	assert.ErrorIs(t, ValidateConnectionVersion([]byte{1}, ProtocolV1), ErrInvalidMessageLength, "a header needs two bytes")
}

func TestDetermineClientMessageTypeClassification(t *testing.T) {
	rejected := []struct {
		name    string
		msgType MsgType
		wantErr error
	}{
		{"hello is reserved", MsgTypeHello, ErrReservedMsgType},
		{"hello response is reserved", MsgTypeHelloResponse, ErrReservedMsgType},
		{"auth response is server to client only", MsgTypeAuthResponse, ErrMsgTypeDirection},
		{"peers online is server to client only", MsgTypePeersOnline, ErrMsgTypeDirection},
		{"peers went offline is server to client only", MsgTypePeersWentOffline, ErrMsgTypeDirection},
		{"zero is unknown", MsgTypeUnknown, ErrUnknownMsgType},
		{"a future type is unknown", MsgType(200), ErrUnknownMsgType},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DetermineClientMessageType([]byte{byte(ProtocolV1), byte(tc.msgType)})
			assert.ErrorIs(t, err, tc.wantErr)
			assert.Equal(t, MsgTypeUnknown, got, "a rejected type must not be returned")
		})
	}

	accepted := []MsgType{MsgTypeAuth, MsgTypeTransport, MsgTypeClose, MsgTypeHealthCheck, MsgTypeSubscribePeerState, MsgTypeUnsubscribePeerState}
	for _, msgType := range accepted {
		got, err := DetermineClientMessageType([]byte{byte(ProtocolV1), byte(msgType)})
		require.NoError(t, err)
		assert.Equal(t, msgType, got, "a client message type must be returned")
	}
}

func TestAuthEnvelopeRoundTrip(t *testing.T) {
	peerID := HashID("future-client")
	token := []byte("0123456789abcdef")
	cases := []struct {
		name    string
		version ProtocolVersion
		ext     []byte
	}{
		{"v2 without extension", 2, nil},
		{"v2 with json extension", 2, []byte(`{"cred2":"value"}`)},
		{"v255 with opaque extension", 255, []byte("opaque-extension-bytes")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := MarshalAuthEnvelope(tc.version, peerID, token, tc.ext)
			require.NoError(t, err)

			version, err := ReadVersion(msg)
			require.NoError(t, err)
			assert.Equal(t, tc.version, version, "the header must carry the advertised version")

			msgType, err := DetermineClientMessageType(msg)
			require.NoError(t, err)
			assert.Equal(t, MsgType(MsgTypeAuth), msgType, "the envelope is an auth message")

			gotID, gotToken, err := UnmarshalAuthMsg(msg)
			require.NoError(t, err)
			assert.Equal(t, peerID, *gotID, "the peer ID must be preserved")
			assert.Equal(t, token, gotToken, "the token must be returned without the extension bytes")
		})
	}
}

func TestMarshalAuthEnvelopeRejectsInvalidInput(t *testing.T) {
	peerID := HashID("future-client")

	_, err := MarshalAuthEnvelope(ProtocolV1, peerID, []byte("token"), nil)
	assert.Error(t, err, "v1 does not use the envelope layout")

	_, err = MarshalAuthEnvelope(2, peerID, nil, nil)
	assert.ErrorIs(t, err, ErrInvalidTokenLength, "the token is mandatory")

	_, err = MarshalAuthEnvelope(2, peerID, []byte("token"), make([]byte, MaxHandshakeSize))
	assert.Error(t, err, "the envelope must fit the handshake size limit")
}

func TestUnmarshalAuthMsgV1LayoutUnchanged(t *testing.T) {
	peerID := HashID("legacy-client")
	// In the v1 layout the token runs to the end of the frame, so bytes that would be a
	// length prefix in the envelope belong to the token here.
	payload := []byte{0x00, 0x05, 'a', 'b', 'c', 'd', 'e', 'f', 'g'}
	msg, err := MarshalAuthMsg(peerID, payload)
	require.NoError(t, err)

	gotID, gotToken, err := UnmarshalAuthMsg(msg)
	require.NoError(t, err)
	assert.Equal(t, peerID, *gotID, "the peer ID must be preserved")
	assert.Equal(t, payload, gotToken, "the v1 token must be returned whole")
}

func TestUnmarshalAuthMsgRejectsMalformedFrames(t *testing.T) {
	peerID := HashID("future-client")
	valid, err := MarshalAuthEnvelope(2, peerID, []byte("token"), []byte("ext"))
	require.NoError(t, err)

	t.Run("zero token length", func(t *testing.T) {
		msg := append([]byte(nil), valid...)
		binary.BigEndian.PutUint16(msg[offsetAuthTokenLen:], 0)
		_, _, err := UnmarshalAuthMsg(msg)
		assert.ErrorIs(t, err, ErrInvalidTokenLength)
	})

	t.Run("token length past the end", func(t *testing.T) {
		msg := append([]byte(nil), valid...)
		binary.BigEndian.PutUint16(msg[offsetAuthTokenLen:], uint16(len(msg)))
		_, _, err := UnmarshalAuthMsg(msg)
		assert.ErrorIs(t, err, ErrInvalidTokenLength)
	})

	t.Run("truncated before the length field", func(t *testing.T) {
		_, _, err := UnmarshalAuthMsg(valid[:headerTotalSizeAuth+1])
		assert.ErrorIs(t, err, ErrInvalidMessageLength)
	})

	t.Run("version zero", func(t *testing.T) {
		msg := append([]byte(nil), valid...)
		msg[0] = 0
		_, _, err := UnmarshalAuthMsg(msg)
		assert.ErrorIs(t, err, ErrUnsupportedVersion)
	})

	t.Run("invalid magic", func(t *testing.T) {
		msg := append([]byte(nil), valid...)
		msg[offsetMagicByte] ^= 0xFF
		_, _, err := UnmarshalAuthMsg(msg)
		assert.Error(t, err)
	})

	t.Run("shorter than the fixed header", func(t *testing.T) {
		_, _, err := UnmarshalAuthMsg(valid[:headerTotalSizeAuth-1])
		assert.ErrorIs(t, err, ErrInvalidMessageLength)
	})
}

func TestEncoderStampsVersion(t *testing.T) {
	for _, version := range []ProtocolVersion{1, 2, 7} {
		enc := NewEncoder(version)
		assert.Equal(t, version, enc.Version())
		assert.Equal(t, []byte{byte(version), byte(MsgTypeHealthCheck)}, enc.Healthcheck(), "healthcheck must carry the version")
		assert.Equal(t, []byte{byte(version), byte(MsgTypeClose)}, enc.CloseMsg(), "close must carry the version")

		resp, err := enc.AuthResponse("rel://relay.example")
		require.NoError(t, err)
		assert.Equal(t, byte(version), resp[0], "auth response must carry the version")
		assert.Equal(t, byte(MsgTypeAuthResponse), resp[1])
		addr, err := UnmarshalAuthResponse(resp)
		require.NoError(t, err)
		assert.Equal(t, "rel://relay.example", addr, "the auth response payload must be the address")

		online, err := enc.PeersOnline([]PeerID{HashID("a")})
		require.NoError(t, err)
		require.Len(t, online, 1)
		assert.Equal(t, byte(version), online[0][0], "peers online must carry the version")
		assert.Equal(t, byte(MsgTypePeersOnline), online[0][1])

		offline, err := enc.PeersWentOffline([]PeerID{HashID("a")})
		require.NoError(t, err)
		require.Len(t, offline, 1)
		assert.Equal(t, byte(version), offline[0][0], "peers went offline must carry the version")
		assert.Equal(t, byte(MsgTypePeersWentOffline), offline[0][1])
	}
}

func TestPackageEncodersUseCurrentVersion(t *testing.T) {
	current := NewEncoder(CurrentProtocolVersion)
	assert.Equal(t, current.CloseMsg(), MarshalCloseMsg())
	assert.Equal(t, current.Healthcheck(), MarshalHealthcheck())

	want, err := current.AuthResponse("addr")
	require.NoError(t, err)
	got, err := MarshalAuthResponse("addr")
	require.NoError(t, err)
	assert.Equal(t, want, got)

	ids := []PeerID{HashID("a"), HashID("b")}
	wantOnline, err := current.PeersOnline(ids)
	require.NoError(t, err)
	gotOnline, err := MarshalPeersOnline(ids)
	require.NoError(t, err)
	assert.Equal(t, wantOnline, gotOnline)
}

func TestUpdateTransportMsgRewritesVersionAndSender(t *testing.T) {
	dst := HashID("dst")
	sender := HashID("sender")
	payload := []byte("payload")
	msg, err := MarshalTransportMsg(dst, payload)
	require.NoError(t, err)

	require.NoError(t, UpdateTransportMsg(msg, ProtocolVersion(2), sender))
	assert.Equal(t, byte(2), msg[0], "the header must carry the destination version")
	assert.Equal(t, byte(MsgTypeTransport), msg[1], "the message type must be preserved")

	gotID, gotPayload, err := UnmarshalTransportMsg(msg)
	require.NoError(t, err)
	assert.Equal(t, sender, *gotID, "the peer ID must be rewritten to the sender")
	assert.Equal(t, payload, gotPayload, "the payload must be preserved")

	assert.ErrorIs(t, UpdateTransportMsg(msg[:headerTotalSizeTransport-1], ProtocolV1, sender), ErrInvalidMessageLength)
}
