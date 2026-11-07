package internal

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sProto "github.com/netbirdio/netbird/shared/signal/proto"
)

func signalOfferWithMlkemPort(port uint32) *sProto.Message {
	return &sProto.Message{Body: &sProto.Body{
		Type:      sProto.Body_OFFER,
		Payload:   "ufrag:pwd",
		MlkemPort: &port,
	}}
}

// TestConvertToOfferAnswer_MlkemPort checks that the proto's 32-bit ML-KEM port is narrowed
// to uint16 only when it fits: a larger value is a malformed message, not a port to
// truncate.
func TestConvertToOfferAnswer_MlkemPort(t *testing.T) {
	for _, port := range []uint32{0, 51833, math.MaxUint16} {
		oa, err := convertToOfferAnswer(signalOfferWithMlkemPort(port))
		require.NoError(t, err, "port %d", port)
		assert.Equal(t, uint16(port), oa.MlkemPort, "port %d must survive the conversion", port)
	}

	for _, port := range []uint32{math.MaxUint16 + 1, math.MaxUint32} {
		_, err := convertToOfferAnswer(signalOfferWithMlkemPort(port))
		assert.Error(t, err, "port %d does not fit in uint16 and must be rejected", port)
	}
}
