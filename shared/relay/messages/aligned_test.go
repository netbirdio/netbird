package messages

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthExtensionRoundTrip(t *testing.T) {
	ext := AuthExtension{
		PeriodSeconds: 60,
		SignedPhase:   &AuthSignedPhase{PhaseMs: 12345, Day: 20405, Signature: bytes.Repeat([]byte{7}, 32)},
	}
	b, err := MarshalAuthExtension(ext)
	require.NoError(t, err)
	got, err := UnmarshalAuthExtension(b)
	require.NoError(t, err)
	assert.Equal(t, ext, got)

	b, err = MarshalAuthExtension(AuthExtension{PeriodSeconds: 60})
	require.NoError(t, err)
	assert.Equal(t, []byte{ExtTypePeriod, 0, 2, 0, 60}, b, "period field layout")

	empty, err := MarshalAuthExtension(AuthExtension{})
	require.NoError(t, err)
	assert.Empty(t, empty)
	got, err = UnmarshalAuthExtension(empty)
	require.NoError(t, err)
	assert.Equal(t, AuthExtension{}, got)
}

func TestAuthExtensionSkipsUnknownTypes(t *testing.T) {
	b := []byte{200, 0, 3, 1, 2, 3, ExtTypePeriod, 0, 2, 0, 90, 201, 0, 0}
	got, err := UnmarshalAuthExtension(b)
	require.NoError(t, err)
	assert.Equal(t, AuthExtension{PeriodSeconds: 90}, got)
}

func TestAuthExtensionRejects(t *testing.T) {
	sp := func(sigLen int) []byte {
		v := append([]byte{ExtTypeSignedPhase, 0, byte(12 + sigLen)}, make([]byte, 12)...)
		return append(v, bytes.Repeat([]byte{1}, sigLen)...)
	}
	for name, b := range map[string][]byte{
		"short header":       {ExtTypePeriod, 0},
		"length past end":    {ExtTypePeriod, 0, 4, 0, 60},
		"period wrong size":  {ExtTypePeriod, 0, 1, 60},
		"zero period":        {ExtTypePeriod, 0, 2, 0, 0},
		"repeated period":    {ExtTypePeriod, 0, 2, 0, 60, ExtTypePeriod, 0, 2, 0, 60},
		"no signature":       sp(0),
		"signature too long": sp(MaxPhaseSignatureSize + 1),
		"repeated phase":     append(sp(1), sp(1)...),
		"negative day":       {ExtTypeSignedPhase, 0, 13, 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 1},
		"unknown truncated":  {200, 0, 5, 1},
	} {
		_, err := UnmarshalAuthExtension(b)
		assert.ErrorIs(t, err, ErrInvalidExtension, "case %q", name)
	}
}

func TestAuthExtensionDoesNotAliasInput(t *testing.T) {
	b, err := MarshalAuthExtension(AuthExtension{SignedPhase: &AuthSignedPhase{PhaseMs: 1, Signature: []byte{9, 9}}})
	require.NoError(t, err)
	got, err := UnmarshalAuthExtension(b)
	require.NoError(t, err)
	for i := range b {
		b[i] = 0
	}
	assert.Equal(t, []byte{9, 9}, got.SignedPhase.Signature, "signature must survive a reused buffer")
}

func TestMarshalAuthExtensionRejectsBadSignature(t *testing.T) {
	_, err := MarshalAuthExtension(AuthExtension{SignedPhase: &AuthSignedPhase{}})
	assert.ErrorIs(t, err, ErrInvalidExtension)
	_, err = MarshalAuthExtension(AuthExtension{SignedPhase: &AuthSignedPhase{Signature: make([]byte, MaxPhaseSignatureSize+1)}})
	assert.ErrorIs(t, err, ErrInvalidExtension)
}

func TestEncoderAuthLayouts(t *testing.T) {
	peerID := HashID("alice")
	token := []byte("token")
	ext, err := MarshalAuthExtension(AuthExtension{PeriodSeconds: 60})
	require.NoError(t, err)

	v2, err := NewEncoder(ProtocolV2, MaxMessageSize).Auth(peerID, token, ext)
	require.NoError(t, err)
	gotID, gotToken, err := UnmarshalAuthMsg(v2)
	require.NoError(t, err)
	assert.Equal(t, peerID, *gotID)
	assert.Equal(t, token, gotToken)
	gotExt, err := AuthMsgExtension(v2)
	require.NoError(t, err)
	assert.Equal(t, ext, gotExt, "the v2 auth must carry the extension")

	v1, err := NewEncoder(ProtocolV1, MaxMessageSize).Auth(peerID, token, nil)
	require.NoError(t, err)
	legacy, err := MarshalAuthMsg(peerID, token)
	require.NoError(t, err)
	assert.Equal(t, legacy, v1, "the v1 auth must keep the legacy layout")
	gotExt, err = AuthMsgExtension(v1)
	require.NoError(t, err)
	assert.Empty(t, gotExt, "a v1 auth has no extension")

	_, err = NewEncoder(ProtocolV1, MaxMessageSize).Auth(peerID, token, ext)
	assert.Error(t, err, "v1 cannot carry an extension")
}

func TestEncoderClientMessagesCarryVersion(t *testing.T) {
	enc := NewEncoder(ProtocolV2, MaxMessageSize)
	peerID := HashID("carol")
	tr := enc.Transport(peerID, []byte("payload"))
	require.NoError(t, ValidateConnectionVersion(tr, ProtocolV2))
	gotID, payload, err := UnmarshalTransportMsg(tr)
	require.NoError(t, err)
	assert.Equal(t, peerID, *gotID)
	assert.Equal(t, []byte("payload"), payload)

	sub, err := enc.SubscribePeerState([]PeerID{peerID})
	require.NoError(t, err)
	assert.Equal(t, []byte{byte(ProtocolV2), byte(MsgTypeSubscribePeerState)}, sub[0][:2])
	unsub, err := enc.UnsubscribePeerState([]PeerID{peerID})
	require.NoError(t, err)
	assert.Equal(t, []byte{byte(ProtocolV2), byte(MsgTypeUnsubscribePeerState)}, unsub[0][:2])
}

func TestHealthcheckPhase(t *testing.T) {
	msg := NewEncoder(ProtocolV2, MaxMessageSize).HealthcheckPhase(54321)
	assert.Equal(t, []byte{byte(ProtocolV2), byte(MsgTypeHealthCheck), 0, 0, 0xd4, 0x31}, msg)
	phase, ok, err := UnmarshalHealthcheckPhase(msg)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, uint32(54321), phase)

	_, ok, err = UnmarshalHealthcheckPhase(NewEncoder(ProtocolV2, MaxMessageSize).Healthcheck())
	require.NoError(t, err)
	assert.False(t, ok, "a bare health check has no phase")

	for _, n := range []int{0, 1, 3, 5, 7} {
		_, _, err := UnmarshalHealthcheckPhase(make([]byte, n))
		assert.ErrorIs(t, err, ErrInvalidMessageLength, "length %d", n)
	}
}

func FuzzUnmarshalAuthExtension(f *testing.F) {
	full, _ := MarshalAuthExtension(AuthExtension{
		PeriodSeconds: 60,
		SignedPhase:   &AuthSignedPhase{PhaseMs: 1, Day: 2, Signature: []byte{3}},
	})
	f.Add(full)
	f.Add([]byte{ExtTypePeriod, 0, 2, 0, 60})
	f.Add([]byte{200, 0, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		ext, err := UnmarshalAuthExtension(b)
		if err != nil {
			return
		}
		if sp := ext.SignedPhase; sp != nil {
			require.NotEmpty(t, sp.Signature)
			require.LessOrEqual(t, len(sp.Signature), MaxPhaseSignatureSize)
			require.GreaterOrEqual(t, sp.Day, int64(0))
		}
		again, err := MarshalAuthExtension(ext)
		require.NoError(t, err)
		back, err := UnmarshalAuthExtension(again)
		require.NoError(t, err)
		require.Equal(t, ext, back)
	})
}

func FuzzUnmarshalHealthcheckPhase(f *testing.F) {
	f.Add(NewEncoder(ProtocolV2, MaxMessageSize).HealthcheckPhase(1))
	f.Add(NewEncoder(ProtocolV2, MaxMessageSize).Healthcheck())
	f.Add([]byte{1})
	f.Fuzz(func(t *testing.T, b []byte) {
		phase, ok, err := UnmarshalHealthcheckPhase(b)
		if err != nil {
			require.False(t, ok)
			return
		}
		if ok {
			require.Equal(t, NewEncoder(ProtocolVersion(b[0]), MaxMessageSize).HealthcheckPhase(phase)[2:], b[2:])
		}
	})
}

func TestHealthcheckEcho(t *testing.T) {
	enc := NewEncoder(ProtocolV2, MaxMessageSize)
	plain, err := UnmarshalHealthcheckEcho(enc.Healthcheck())
	require.NoError(t, err)
	assert.False(t, plain.HasPhase, "a bare answer has no phase")

	msg := enc.HealthcheckEcho(54321, nil)
	assert.Equal(t, enc.HealthcheckPhase(54321), msg, "a phase alone has the server heartbeat layout")
	got, err := UnmarshalHealthcheckEcho(msg)
	require.NoError(t, err)
	assert.Equal(t, HealthcheckEchoMsg{PhaseMs: 54321, HasPhase: true}, got)

	ext, err := MarshalAuthExtension(AuthExtension{
		PeriodSeconds: 60,
		SignedPhase:   &AuthSignedPhase{PhaseMs: 7, Day: 2, Signature: []byte{3, 4}},
	})
	require.NoError(t, err)
	got, err = UnmarshalHealthcheckEcho(enc.HealthcheckEcho(7, append([]byte{200, 0, 1, 'x'}, ext...)))
	require.NoError(t, err)
	assert.Equal(t, HealthcheckEchoMsg{
		PhaseMs:  7,
		HasPhase: true,
		Ext:      AuthExtension{PeriodSeconds: 60, SignedPhase: &AuthSignedPhase{PhaseMs: 7, Day: 2, Signature: []byte{3, 4}}},
	}, got, "the signed phase follows the phase, unknown fields are skipped")

	for _, bad := range [][]byte{
		{1},
		{byte(ProtocolV2), byte(MsgTypeHealthCheck), 0, 0, 1},
		append(enc.HealthcheckEcho(1, nil), ExtTypePeriod, 0),
	} {
		_, err := UnmarshalHealthcheckEcho(bad)
		assert.Error(t, err, "malformed answer %v", bad)
	}
}
