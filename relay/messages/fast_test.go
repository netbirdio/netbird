package messages

import (
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestMarshalEbpfTransportMsg(t *testing.T) {
	channelID := ChannelID{0x11, 0x22}
	payload := []byte("payload")
	msg, err := MarshalEbpfTransportMsg(channelID, payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	log.Info("marshalled msg len, cap: ", len(msg), cap(msg))
	responseChannelID, responsePayload, err := UnmarshalEbpfTransportMsg(msg)
	if err != nil {
		t.Fatalf("unexpected error during unmarshal: %v", err)
	}

	if responseChannelID != channelID {
		t.Errorf("expected channel ID %v, got %v", channelID, responseChannelID)
	}

	if string(responsePayload) != string(payload) {
		t.Errorf("expected payload %s, got %s", payload, responsePayload)
	}
}
