package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/inspect"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

func TestToProxyConfig_Basic(t *testing.T) {
	cfg := &mgmProto.TransparentProxyConfig{
		Enabled:       true,
		Mode:          mgmProto.TransparentProxyMode_TP_MODE_BUILTIN,
		DefaultAction: mgmProto.TransparentProxyAction_TP_ACTION_ALLOW,
		RedirectSources: []string{
			"10.0.0.0/24",
			"192.168.1.0/24",
		},
		RedirectPorts: []uint32{80, 443},
		Rules: []*mgmProto.TransparentProxyRule{
			{
				Id:       "block-evil",
				Domains:  []string{"*.evil.com", "malware.example.com"},
				Action:   mgmProto.TransparentProxyAction_TP_ACTION_BLOCK,
				Priority: 1,
			},
			{
				Id:       "inspect-internal",
				Domains:  []string{"*.internal.corp"},
				Networks: []string{"10.1.0.0/16"},
				Ports:    []uint32{443, 8443},
				Action:   mgmProto.TransparentProxyAction_TP_ACTION_INSPECT,
				Priority: 10,
			},
		},
		ListenPort: 8443,
	}

	config, err := toProxyConfig(cfg)
	require.NoError(t, err)

	assert.True(t, config.Enabled)
	assert.Equal(t, inspect.ModeBuiltin, config.Mode)
	assert.Equal(t, inspect.ActionAllow, config.DefaultAction)

	require.Len(t, config.RedirectSources, 2)
	assert.Equal(t, "10.0.0.0/24", config.RedirectSources[0].String())
	assert.Equal(t, "192.168.1.0/24", config.RedirectSources[1].String())

	require.Len(t, config.RedirectPorts, 2)
	assert.Equal(t, uint16(80), config.RedirectPorts[0])
	assert.Equal(t, uint16(443), config.RedirectPorts[1])

	require.Len(t, config.Rules, 2)

	// Rule 1: block evil domains
	assert.Equal(t, "block-evil", string(config.Rules[0].ID))
	assert.Equal(t, inspect.ActionBlock, config.Rules[0].Action)
	assert.Equal(t, 1, config.Rules[0].Priority)
	require.Len(t, config.Rules[0].Domains, 2)
	assert.Equal(t, "*.evil.com", config.Rules[0].Domains[0].PunycodeString())
	assert.Equal(t, "malware.example.com", config.Rules[0].Domains[1].PunycodeString())

	// Rule 2: inspect internal
	assert.Equal(t, "inspect-internal", string(config.Rules[1].ID))
	assert.Equal(t, inspect.ActionInspect, config.Rules[1].Action)
	assert.Equal(t, 10, config.Rules[1].Priority)
	require.Len(t, config.Rules[1].Networks, 1)
	assert.Equal(t, "10.1.0.0/16", config.Rules[1].Networks[0].String())
	require.Len(t, config.Rules[1].Ports, 2)

	// Listen address
	assert.True(t, config.ListenAddr.IsValid())
	assert.Equal(t, uint16(8443), config.ListenAddr.Port())
}

func TestToProxyConfig_ExternalMode(t *testing.T) {
	cfg := &mgmProto.TransparentProxyConfig{
		Enabled:         true,
		Mode:            mgmProto.TransparentProxyMode_TP_MODE_EXTERNAL,
		ExternalProxyUrl: "http://proxy.corp:8080",
		DefaultAction:   mgmProto.TransparentProxyAction_TP_ACTION_BLOCK,
	}

	config, err := toProxyConfig(cfg)
	require.NoError(t, err)

	assert.Equal(t, inspect.ModeExternal, config.Mode)
	assert.Equal(t, inspect.ActionBlock, config.DefaultAction)
	require.NotNil(t, config.ExternalURL)
	assert.Equal(t, "http", config.ExternalURL.Scheme)
	assert.Equal(t, "proxy.corp:8080", config.ExternalURL.Host)
}

func TestToProxyConfig_ICAP(t *testing.T) {
	cfg := &mgmProto.TransparentProxyConfig{
		Enabled: true,
		Icap: &mgmProto.TransparentProxyICAPConfig{
			ReqmodUrl:      "icap://icap-server:1344/reqmod",
			RespmodUrl:     "icap://icap-server:1344/respmod",
			MaxConnections: 16,
		},
	}

	config, err := toProxyConfig(cfg)
	require.NoError(t, err)

	require.NotNil(t, config.ICAP)
	assert.Equal(t, "icap", config.ICAP.ReqModURL.Scheme)
	assert.Equal(t, "icap-server:1344", config.ICAP.ReqModURL.Host)
	assert.Equal(t, "/reqmod", config.ICAP.ReqModURL.Path)
	assert.Equal(t, "/respmod", config.ICAP.RespModURL.Path)
	assert.Equal(t, 16, config.ICAP.MaxConnections)
}

func TestToProxyConfig_Empty(t *testing.T) {
	cfg := &mgmProto.TransparentProxyConfig{
		Enabled: true,
	}

	config, err := toProxyConfig(cfg)
	require.NoError(t, err)

	assert.True(t, config.Enabled)
	assert.Equal(t, inspect.ModeBuiltin, config.Mode)
	assert.Equal(t, inspect.ActionAllow, config.DefaultAction)
	assert.Empty(t, config.RedirectSources)
	assert.Empty(t, config.RedirectPorts)
	assert.Empty(t, config.Rules)
	assert.Nil(t, config.ICAP)
	assert.Nil(t, config.TLS)
	assert.False(t, config.ListenAddr.IsValid())
}

func TestToProxyConfig_InvalidSource(t *testing.T) {
	cfg := &mgmProto.TransparentProxyConfig{
		Enabled:         true,
		RedirectSources: []string{"not-a-cidr"},
	}

	_, err := toProxyConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse redirect source")
}

func TestToProxyConfig_InvalidNetwork(t *testing.T) {
	cfg := &mgmProto.TransparentProxyConfig{
		Enabled: true,
		Rules: []*mgmProto.TransparentProxyRule{
			{
				Id:       "bad",
				Networks: []string{"not-a-cidr"},
			},
		},
	}

	_, err := toProxyConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse network")
}

func TestToProxyAction(t *testing.T) {
	assert.Equal(t, inspect.ActionAllow, toProxyAction(mgmProto.TransparentProxyAction_TP_ACTION_ALLOW))
	assert.Equal(t, inspect.ActionBlock, toProxyAction(mgmProto.TransparentProxyAction_TP_ACTION_BLOCK))
	assert.Equal(t, inspect.ActionInspect, toProxyAction(mgmProto.TransparentProxyAction_TP_ACTION_INSPECT))
	// Unknown defaults to allow
	assert.Equal(t, inspect.ActionAllow, toProxyAction(99))
}

func TestParseUDPPacket_IPv4(t *testing.T) {
	// Build a minimal IPv4/UDP packet: 20-byte IPv4 header + 8-byte UDP header + payload
	packet := make([]byte, 20+8+4)

	// IPv4 header: version=4, IHL=5 (20 bytes)
	packet[0] = 0x45
	// Protocol = UDP (17)
	packet[9] = 17
	// Source IP: 10.0.0.1
	packet[12], packet[13], packet[14], packet[15] = 10, 0, 0, 1
	// Dest IP: 192.168.1.1
	packet[16], packet[17], packet[18], packet[19] = 192, 168, 1, 1
	// UDP source port: 54321 (0xD431)
	packet[20] = 0xD4
	packet[21] = 0x31
	// UDP dest port: 443 (0x01BB)
	packet[22] = 0x01
	packet[23] = 0xBB
	// Payload
	packet[28] = 0xDE
	packet[29] = 0xAD
	packet[30] = 0xBE
	packet[31] = 0xEF

	srcIP, dstIP, dstPort, payload, ok := parseUDPPacket(packet)
	require.True(t, ok)
	assert.Equal(t, "10.0.0.1", srcIP.String())
	assert.Equal(t, "192.168.1.1", dstIP.String())
	assert.Equal(t, uint16(443), dstPort)
	assert.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, payload)
}

func TestParseUDPPacket_IPv6(t *testing.T) {
	// Build a minimal IPv6/UDP packet: 40-byte IPv6 header + 8-byte UDP header + payload
	packet := make([]byte, 40+8+4)

	// Version = 6 (0x60 in high nibble)
	packet[0] = 0x60
	// Payload length: 8 (UDP header) + 4 (payload)
	packet[4] = 0
	packet[5] = 12
	// Next header: UDP (17)
	packet[6] = 17
	// Source: 2001:db8::1
	packet[8] = 0x20
	packet[9] = 0x01
	packet[10] = 0x0d
	packet[11] = 0xb8
	packet[23] = 0x01
	// Dest: 2001:db8::2
	packet[24] = 0x20
	packet[25] = 0x01
	packet[26] = 0x0d
	packet[27] = 0xb8
	packet[39] = 0x02
	// UDP source port: 54321 (0xD431)
	packet[40] = 0xD4
	packet[41] = 0x31
	// UDP dest port: 443 (0x01BB)
	packet[42] = 0x01
	packet[43] = 0xBB
	// Payload
	packet[48] = 0xCA
	packet[49] = 0xFE
	packet[50] = 0xBA
	packet[51] = 0xBE

	srcIP, dstIP, dstPort, payload, ok := parseUDPPacket(packet)
	require.True(t, ok)
	assert.Equal(t, "2001:db8::1", srcIP.String())
	assert.Equal(t, "2001:db8::2", dstIP.String())
	assert.Equal(t, uint16(443), dstPort)
	assert.Equal(t, []byte{0xCA, 0xFE, 0xBA, 0xBE}, payload)
}

func TestParseUDPPacket_TooShort(t *testing.T) {
	_, _, _, _, ok := parseUDPPacket(nil)
	assert.False(t, ok)

	_, _, _, _, ok = parseUDPPacket([]byte{0x45, 0x00})
	assert.False(t, ok)
}

func TestParseUDPPacket_IPv6ExtensionHeader(t *testing.T) {
	// IPv6 with next header != UDP should be rejected
	packet := make([]byte, 48)
	packet[0] = 0x60
	packet[6] = 6 // TCP, not UDP
	_, _, _, _, ok := parseUDPPacket(packet)
	assert.False(t, ok, "should reject IPv6 packets with non-UDP next header")
}

func TestParseUDPPacket_IPv4MappedIPv6(t *testing.T) {
	// IPv4 packet with normal addresses should Unmap correctly
	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[9] = 17
	packet[12], packet[13], packet[14], packet[15] = 127, 0, 0, 1
	packet[16], packet[17], packet[18], packet[19] = 10, 0, 0, 1
	packet[22] = 0x01
	packet[23] = 0xBB

	srcIP, dstIP, _, _, ok := parseUDPPacket(packet)
	require.True(t, ok)
	assert.True(t, srcIP.Is4(), "should be plain IPv4, not mapped")
	assert.True(t, dstIP.Is4(), "should be plain IPv4, not mapped")
}
