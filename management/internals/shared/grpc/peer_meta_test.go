package grpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestExtractPeerMeta_RemovesNulAndInvalidUTF8(t *testing.T) {
	meta := extractPeerMeta(context.Background(), &proto.PeerSystemMeta{
		Hostname:        "host\x00name",
		OS:              "\x00\x00\x00\x00\x00\x00s",
		OSVersion:       "11\xff",
		SysSerialNumber: "SN\x00\x00",
		Environment:     &proto.Environment{Cloud: "\x00aws"},
		NetworkAddresses: []*proto.NetworkAddress{
			{NetIP: "192.168.0.1/24", Mac: "e0:d5\x00"},
		},
		Files: []*proto.File{{Path: "C:\\x\x00.exe"}},
	})

	assert.Equal(t, "hostname", meta.Hostname)
	assert.Equal(t, "s", meta.OS)
	assert.Equal(t, "11", meta.OSVersion)
	assert.Equal(t, "SN", meta.SystemSerialNumber)
	assert.Equal(t, "aws", meta.Environment.Cloud)
	assert.Equal(t, "e0:d5", meta.NetworkAddresses[0].Mac)
	assert.Equal(t, "C:\\x.exe", meta.Files[0].Path)
}

func TestCleanClientString(t *testing.T) {
	tests := map[string]string{
		"":                    "",
		"\x00\x00":            "",
		"Wïndows":             "Wïndows",
		"ssh-ed25519 AAA\x00": "ssh-ed25519 AAA",
		"bad\xc3\x28utf8":     "bad(utf8",
	}
	for in, want := range tests {
		assert.Equal(t, want, cleanClientString(in), "input %q", in)
	}
}
