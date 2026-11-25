package messages

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/peerauth"
)

func TestAlignedHeartbeatEntryRoundTrip(t *testing.T) {
	assert.Equal(t, []byte{ExtTypeAlignedHeartbeat, 0, 2, 0, 60}, AppendAlignedHeartbeatEntry(nil, 60),
		"type 2, value length 2, period as uint16 big endian seconds")

	for _, period := range []uint16{1, 30, 60, 300, 65535} {
		got, ok, err := AlignedHeartbeatEntry(AppendAlignedHeartbeatEntry(nil, period))
		require.NoError(t, err)
		assert.True(t, ok, "period %d", period)
		assert.Equal(t, period, got, "period %d", period)
	}
}

func TestAlignedHeartbeatEntryAbsentOrZeroStaysStock(t *testing.T) {
	for name, ext := range map[string][]byte{
		"nil area":            nil,
		"empty area":          {},
		"other entries only":  {1, 0, 1, 0xab, 7, 0, 0},
		"zero period":         AppendAlignedHeartbeatEntry(nil, 0),
		"zero then more data": {ExtTypeAlignedHeartbeat, 0, 4, 0, 0, 0, 60},
	} {
		period, ok, err := AlignedHeartbeatEntry(ext)
		require.NoError(t, err, "case %q", name)
		assert.False(t, ok, "case %q", name)
		assert.Zero(t, period, "case %q", name)
	}
}

func TestAlignedHeartbeatEntrySkipsOtherTypesAndLaterBytes(t *testing.T) {
	for name, ext := range map[string][]byte{
		"after another entry":   AppendAlignedHeartbeatEntry([]byte{7, 0, 3, 'a', 'b', 'c'}, 60),
		"before another entry":  append(AppendAlignedHeartbeatEntry(nil, 60), 7, 0, 1, 'x'),
		"longer value":          {ExtTypeAlignedHeartbeat, 0, 4, 0, 60, 0xff, 0xff},
		"first of two":          AppendAlignedHeartbeatEntry(AppendAlignedHeartbeatEntry(nil, 60), 120),
		"bad area after entry":  append(AppendAlignedHeartbeatEntry(nil, 60), 7, 0xff),
		"entry after empty one": AppendAlignedHeartbeatEntry([]byte{9, 0, 0}, 60),
	} {
		period, ok, err := AlignedHeartbeatEntry(ext)
		require.NoError(t, err, "case %q", name)
		assert.True(t, ok, "case %q", name)
		assert.Equal(t, uint16(60), period, "case %q", name)
	}
}

func TestAlignedHeartbeatEntryRejectsMalformed(t *testing.T) {
	for name, ext := range map[string][]byte{
		"short header":           {ExtTypeAlignedHeartbeat, 0},
		"one byte value":         {ExtTypeAlignedHeartbeat, 0, 1, 60},
		"empty value":            {ExtTypeAlignedHeartbeat, 0, 0},
		"length beyond the area": {ExtTypeAlignedHeartbeat, 0, 9, 0, 60},
		"bad entry before":       append([]byte{7, 0, 9, 1}, AppendAlignedHeartbeatEntry(nil, 60)...),
		"bad first entry of two": AppendAlignedHeartbeatEntry([]byte{ExtTypeAlignedHeartbeat, 0, 1, 60}, 60),
	} {
		_, ok, err := AlignedHeartbeatEntry(ext)
		assert.ErrorIs(t, err, ErrInvalidMessageLength, "case %q", name)
		assert.False(t, ok, "case %q", name)
	}
}

// The client puts the proof first and the aligned entry after it in one Auth envelope. The
// relay reads both from the same area, and a malformed aligned entry after the proof does not
// hide the proof.
func TestAlignedHeartbeatEntryWithProofInAuthEnvelope(t *testing.T) {
	proof := peerauth.Proof{
		Timestamp: time.Unix(1_700_000_000, 0),
		Signature: make([]byte, ed25519.SignatureSize),
		Hostname:  "relay.example.com",
	}
	proofEntry, err := peerauth.MarshalRelayExtension(proof)
	require.NoError(t, err)
	peerID := HashID("peer")

	msg, err := MarshalAuthEnvelope(ProtocolV2, peerID, []byte("token"), AppendAlignedHeartbeatEntry(proofEntry, 60))
	require.NoError(t, err)
	ext, err := UnmarshalAuthExtension(msg)
	require.NoError(t, err)

	gotProof, err := peerauth.UnmarshalRelayExtension(ext)
	require.NoError(t, err)
	assert.Equal(t, proof.Hostname, gotProof.Hostname, "the proof is read past the aligned entry")
	period, ok, err := AlignedHeartbeatEntry(ext)
	require.NoError(t, err)
	assert.True(t, ok, "the aligned entry is read past the proof")
	assert.Equal(t, uint16(60), period, "the asked period is read from the Auth envelope")

	malformed, err := MarshalAuthEnvelope(ProtocolV2, peerID, []byte("token"), append(proofEntry, ExtTypeAlignedHeartbeat, 0, 9, 0))
	require.NoError(t, err)
	ext, err = UnmarshalAuthExtension(malformed)
	require.NoError(t, err)
	_, err = peerauth.UnmarshalRelayExtension(ext)
	assert.NoError(t, err, "a malformed aligned entry after the proof must not hide the proof")
	_, ok, err = AlignedHeartbeatEntry(ext)
	assert.Error(t, err, "the malformed aligned entry is reported")
	assert.False(t, ok, "a malformed aligned entry stays stock")
}

// The relay answers with the accepted period in the extension area of the v2 AuthResponse; a
// client reads the URL as before and the period from the area.
func TestAlignedHeartbeatEntryInAuthResponse(t *testing.T) {
	const address = "rels://relay.example.com:443"
	msg, err := NewEncoder(ProtocolV2, MaxMessageSize).AuthResponseEnvelope(address, AppendAlignedHeartbeatEntry(nil, 60))
	require.NoError(t, err)
	assert.Equal(t, offsetAuthRespAddr+len(address)+5, len(msg), "the entry adds 5 bytes")

	addr, err := UnmarshalAuthResponse(msg)
	require.NoError(t, err)
	assert.Equal(t, address, addr, "the URL stays readable with the entry")
	ext, err := UnmarshalAuthResponseExtension(msg)
	require.NoError(t, err)
	period, ok, err := AlignedHeartbeatEntry(ext)
	require.NoError(t, err)
	assert.True(t, ok, "the accepted period is read from the response")
	assert.Equal(t, uint16(60), period, "the accepted period is the answered one")

	v1, err := NewEncoder(ProtocolV1, MaxMessageSize).AuthResponse(address)
	require.NoError(t, err)
	ext, err = UnmarshalAuthResponseExtension(v1)
	require.NoError(t, err)
	_, ok, err = AlignedHeartbeatEntry(ext)
	require.NoError(t, err)
	assert.False(t, ok, "a v1 response has no entry")
}
