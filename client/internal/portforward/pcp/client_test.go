package pcp

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddrConversion(t *testing.T) {
	tests := []struct {
		name string
		addr netip.Addr
	}{
		{"IPv4", netip.MustParseAddr("192.168.1.100")},
		{"IPv4 loopback", netip.MustParseAddr("127.0.0.1")},
		{"IPv6", netip.MustParseAddr("2001:db8::1")},
		{"IPv6 loopback", netip.MustParseAddr("::1")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b16 := addrTo16(tt.addr)

			recovered := addrFrom16(b16)
			assert.Equal(t, tt.addr, recovered, "address should round-trip")
		})
	}
}

func TestBuildAnnounceRequest(t *testing.T) {
	clientIP := netip.MustParseAddr("192.168.1.100")
	req := buildAnnounceRequest(clientIP)

	require.Len(t, req, headerSize)
	assert.Equal(t, byte(Version), req[0], "version")
	assert.Equal(t, byte(OpAnnounce), req[1], "opcode")

	// Check client IP is properly encoded as IPv4-mapped IPv6
	assert.Equal(t, byte(0xff), req[18], "IPv4-mapped prefix byte 10")
	assert.Equal(t, byte(0xff), req[19], "IPv4-mapped prefix byte 11")
	assert.Equal(t, byte(192), req[20], "IP octet 1")
	assert.Equal(t, byte(168), req[21], "IP octet 2")
	assert.Equal(t, byte(1), req[22], "IP octet 3")
	assert.Equal(t, byte(100), req[23], "IP octet 4")
}

func TestBuildMapRequest(t *testing.T) {
	clientIP := netip.MustParseAddr("192.168.1.100")
	nonce := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	req := buildMapRequest(clientIP, nonce, ProtoUDP, 51820, 51820, netip.Addr{}, 3600)

	require.Len(t, req, mapRequestSize)
	assert.Equal(t, byte(Version), req[0], "version")
	assert.Equal(t, byte(OpMap), req[1], "opcode")

	// Lifetime at bytes 4-7
	assert.Equal(t, uint32(3600), (uint32(req[4])<<24)|(uint32(req[5])<<16)|(uint32(req[6])<<8)|uint32(req[7]), "lifetime")

	// Nonce at bytes 24-35
	assert.Equal(t, nonce[:], req[24:36], "nonce")

	// Protocol at byte 36
	assert.Equal(t, byte(ProtoUDP), req[36], "protocol")

	// Internal port at bytes 40-41
	assert.Equal(t, uint16(51820), (uint16(req[40])<<8)|uint16(req[41]), "internal port")

	// External port at bytes 42-43
	assert.Equal(t, uint16(51820), (uint16(req[42])<<8)|uint16(req[43]), "external port")
}

func TestParseResponse(t *testing.T) {
	// Construct a valid ANNOUNCE response
	resp := make([]byte, headerSize)
	resp[0] = Version
	resp[1] = OpAnnounce | OpReply
	// Result code = 0 (success)
	// Lifetime = 0
	// Epoch = 12345
	resp[8] = 0
	resp[9] = 0
	resp[10] = 0x30
	resp[11] = 0x39

	parsed, err := parseResponse(resp)
	require.NoError(t, err)
	assert.Equal(t, uint8(Version), parsed.Version)
	assert.Equal(t, uint8(OpAnnounce|OpReply), parsed.Opcode)
	assert.Equal(t, uint8(ResultSuccess), parsed.ResultCode)
	assert.Equal(t, uint32(12345), parsed.Epoch)
}

func TestParseResponseErrors(t *testing.T) {
	t.Run("too short", func(t *testing.T) {
		_, err := parseResponse([]byte{1, 2, 3})
		assert.Error(t, err)
	})

	t.Run("wrong version", func(t *testing.T) {
		resp := make([]byte, headerSize)
		resp[0] = 1 // Wrong version
		resp[1] = OpReply
		_, err := parseResponse(resp)
		assert.Error(t, err)
	})

	t.Run("missing reply bit", func(t *testing.T) {
		resp := make([]byte, headerSize)
		resp[0] = Version
		resp[1] = OpAnnounce // Missing OpReply bit
		_, err := parseResponse(resp)
		assert.Error(t, err)
	})
}

func TestResultCodeString(t *testing.T) {
	assert.Equal(t, "SUCCESS", ResultCodeString(ResultSuccess))
	assert.Equal(t, "NOT_AUTHORIZED", ResultCodeString(ResultNotAuthorized))
	assert.Equal(t, "ADDRESS_MISMATCH", ResultCodeString(ResultAddressMismatch))
	assert.Contains(t, ResultCodeString(255), "UNKNOWN")
}

func TestProtocolNumber(t *testing.T) {
	proto, err := protocolNumber("udp")
	require.NoError(t, err)
	assert.Equal(t, uint8(ProtoUDP), proto)

	proto, err = protocolNumber("tcp")
	require.NoError(t, err)
	assert.Equal(t, uint8(ProtoTCP), proto)

	proto, err = protocolNumber("UDP")
	require.NoError(t, err)
	assert.Equal(t, uint8(ProtoUDP), proto)

	_, err = protocolNumber("icmp")
	assert.Error(t, err)
}

func TestClientCreation(t *testing.T) {
	gateway := netip.MustParseAddr("192.168.1.1").AsSlice()

	client := NewClient(gateway)
	assert.Equal(t, net.IP(gateway), client.Gateway())
	assert.Equal(t, defaultTimeout, client.timeout)

	clientWithTimeout := NewClientWithTimeout(gateway, 5*time.Second)
	assert.Equal(t, 5*time.Second, clientWithTimeout.timeout)
}

func TestNATType(t *testing.T) {
	n := NewNAT(netip.MustParseAddr("192.168.1.1").AsSlice(), netip.MustParseAddr("192.168.1.100").AsSlice())
	assert.Equal(t, "PCP", n.Type())
}

// Integration test - skipped unless PCP_TEST_GATEWAY env is set
func TestClientIntegration(t *testing.T) {
	t.Skip("Integration test - run manually with PCP_TEST_GATEWAY=<gateway-ip>")

	gateway := netip.MustParseAddr("10.0.1.1").AsSlice()   // Change to your test gateway
	localIP := netip.MustParseAddr("10.0.1.100").AsSlice() // Change to your local IP

	client := NewClient(gateway)
	client.SetLocalIP(localIP)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Test ANNOUNCE
	epoch, err := client.Announce(ctx)
	require.NoError(t, err)
	t.Logf("Server epoch: %d", epoch)

	// Test MAP
	resp, err := client.AddPortMapping(ctx, "udp", 51820, 1*time.Hour)
	require.NoError(t, err)
	t.Logf("Mapping: internal=%d external=%d externalIP=%s",
		resp.InternalPort, resp.ExternalPort, resp.ExternalIP)

	// Cleanup
	err = client.DeletePortMapping(ctx, "udp", 51820)
	require.NoError(t, err)
}
