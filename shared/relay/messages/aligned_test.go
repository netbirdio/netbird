package messages

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealthcheckWithPeriodRoundTrip(t *testing.T) {
	assert.Equal(t, []byte{byte(ProtocolV1), byte(MsgTypeHealthCheck), 0, 60}, MarshalHealthcheckWithPeriod(60),
		"protocol v1 health check with the period as uint16 big endian seconds")
	assert.Equal(t, MarshalHealthcheckWithPeriod(60), NewEncoder(ProtocolV1, MaxMessageSize).HealthcheckWithPeriod(60),
		"encoder of a v1 connection writes the same frame")

	for _, period := range []uint16{30, 60, 300, 65535} {
		msg := MarshalHealthcheckWithPeriod(period)
		for _, determine := range []func([]byte) (MsgType, error){DetermineClientMessageType, DetermineServerMessageType} {
			msgType, err := determine(msg)
			require.NoError(t, err)
			assert.Equal(t, MsgType(MsgTypeHealthCheck), msgType, "valid in both directions, period %d", period)
		}

		got, ok, err := UnmarshalHealthcheckPeriod(msg)
		require.NoError(t, err)
		assert.True(t, ok, "period %d", period)
		assert.Equal(t, period, got)
	}
}

func TestHealthcheckWithoutPeriodStaysStock(t *testing.T) {
	assert.Equal(t, MarshalHealthcheck(), MarshalHealthcheckWithPeriod(0), "zero period is the stock frame")
	assert.Equal(t, MarshalHealthcheck(), NewEncoder(ProtocolV1, MaxMessageSize).HealthcheckWithPeriod(0))

	period, ok, err := UnmarshalHealthcheckPeriod(MarshalHealthcheck())
	require.NoError(t, err)
	assert.False(t, ok, "no payload stays stock")
	assert.Zero(t, period)

	// A zero period payload is not a valid period either, also with later bytes.
	for _, msg := range [][]byte{append(MarshalHealthcheck(), 0, 0), append(MarshalHealthcheck(), 0, 0, 0, 60)} {
		period, ok, err = UnmarshalHealthcheckPeriod(msg)
		require.NoError(t, err)
		assert.False(t, ok, "payload %v", msg[sizeOfProtoHeader:])
		assert.Zero(t, period)
	}
}

func TestUnmarshalHealthcheckPeriodIgnoresLaterBytes(t *testing.T) {
	for name, msg := range map[string][]byte{
		"one more byte": append(MarshalHealthcheckWithPeriod(60), 0),
		"TLV after":     append(MarshalHealthcheckWithPeriod(60), 1, 2, 0xab, 0xcd),
	} {
		period, ok, err := UnmarshalHealthcheckPeriod(msg)
		require.NoError(t, err, "case %q", name)
		assert.True(t, ok, "case %q", name)
		assert.Equal(t, uint16(60), period, "case %q", name)
	}
}

func TestUnmarshalHealthcheckPeriodRejectsBadPayload(t *testing.T) {
	for name, msg := range map[string][]byte{
		"empty":          {},
		"header only v1": {byte(ProtocolV1)},
		"one byte":       append(MarshalHealthcheck(), 60),
	} {
		_, ok, err := UnmarshalHealthcheckPeriod(msg)
		assert.ErrorIs(t, err, ErrInvalidMessageLength, "case %q", name)
		assert.False(t, ok, "case %q", name)
	}
}
