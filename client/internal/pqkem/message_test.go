package pqkem

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMessageRoundTrip(t *testing.T) {
	init, err := NewInitiator()
	require.NoError(t, err)
	answer, _, err := Respond(init.Offer(), Binding{LocalWgPub: wgB, RemoteWgPub: wgA})
	require.NoError(t, err)

	id := ExchangeID{1, 2, 3, 4}

	offBytes, err := (&OfferMsg{ExchangeID: id, KEMOffer: init.Offer()}).Encode()
	require.NoError(t, err)
	typ, decoded, err := Decode(offBytes)
	require.NoError(t, err)
	require.Equal(t, MsgOffer, typ)
	require.Equal(t, id, decoded.(*OfferMsg).ExchangeID)
	require.Equal(t, init.Offer(), decoded.(*OfferMsg).KEMOffer)

	ansBytes, err := (&AnswerMsg{ExchangeID: id, KEMAnswer: answer}).Encode()
	require.NoError(t, err)
	typ, decoded, err = Decode(ansBytes)
	require.NoError(t, err)
	require.Equal(t, MsgAnswer, typ)
	require.Equal(t, answer, decoded.(*AnswerMsg).KEMAnswer)

	confBytes := (&ConfirmMsg{ExchangeID: id}).Encode()
	typ, decoded, err = Decode(confBytes)
	require.NoError(t, err)
	require.Equal(t, MsgConfirm, typ)
	require.Equal(t, id, decoded.(*ConfirmMsg).ExchangeID)
}

func TestDecodeRejects(t *testing.T) {
	// too short
	_, _, err := Decode([]byte{1, 1})
	require.Error(t, err)

	// wrong version
	bad := make([]byte, headerSize+OfferSize)
	bad[0] = byte(MsgOffer)
	bad[1] = ProtocolVersion + 1
	_, _, err = Decode(bad)
	require.Error(t, err)

	// unknown type
	bad2 := make([]byte, headerSize)
	bad2[0] = 99
	bad2[1] = ProtocolVersion
	_, _, err = Decode(bad2)
	require.Error(t, err)

	// offer with wrong payload size
	_, err = (&OfferMsg{KEMOffer: []byte{1, 2, 3}}).Encode()
	require.Error(t, err)
}
